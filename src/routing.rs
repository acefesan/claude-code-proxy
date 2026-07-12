use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
    sync::{Arc, Mutex, MutexGuard},
    time::{SystemTime, UNIX_EPOCH},
};

pub const ROUTING_SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RouteProvider {
    Anthropic,
    Codex,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RouteTarget {
    pub provider: RouteProvider,
    pub model: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RouteStatus {
    Stable,
    PendingBusy,
    Blocked,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionRoute {
    pub desired: RouteTarget,
    pub effective: RouteTarget,
    pub revision: u64,
    pub pending_since_ms: Option<u64>,
    pub transitioned_at_ms: u64,
    pub last_error: Option<String>,
    #[serde(skip_serializing, default)]
    pub active_requests: usize,
    #[serde(skip_serializing, default)]
    pub host_idle: bool,
    #[serde(skip_serializing, default)]
    pub host_observed_at_ms: Option<u64>,
}

impl SessionRoute {
    pub fn status(&self) -> RouteStatus {
        if self.last_error.is_some() {
            RouteStatus::Blocked
        } else if self.desired == self.effective {
            RouteStatus::Stable
        } else {
            RouteStatus::PendingBusy
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct RoutingFile {
    schema_version: u32,
    sessions: BTreeMap<String, SessionRoute>,
}

#[derive(Debug, thiserror::Error)]
pub enum RoutingError {
    #[error("unknown routing state schema version {0}")]
    UnknownSchema(u32),
    #[error("unknown session: {0}")]
    UnknownSession(String),
    #[error("stale route revision: expected {expected}, current {current}")]
    StaleRevision { expected: u64, current: u64 },
    #[error("invalid route target: {0}")]
    InvalidTarget(String),
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
}

pub trait Clock: Send + Sync {
    fn now_ms(&self) -> u64;
}

#[derive(Debug)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now_ms(&self) -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64
    }
}

pub struct RoutingCoordinator {
    inner: Arc<Mutex<RoutingState>>,
    store_path: PathBuf,
    clock: Arc<dyn Clock>,
    max_scan_age_ms: u64,
}

#[derive(Debug, Default)]
struct RoutingState {
    sessions: BTreeMap<String, SessionRoute>,
}

pub struct RequestAdmission {
    session_id: String,
    target: RouteTarget,
    coordinator: RoutingCoordinator,
    released: bool,
}

impl RequestAdmission {
    pub fn target(&self) -> &RouteTarget {
        &self.target
    }

    pub fn release(mut self) {
        self.release_inner();
    }

    fn release_inner(&mut self) {
        if self.released {
            return;
        }
        self.released = true;
        let mut state = self.coordinator.lock();
        if let Some(route) = state.sessions.get_mut(&self.session_id) {
            route.active_requests = route.active_requests.saturating_sub(1);
            self.coordinator.reconcile_route(route);
        }
        let _ = self.coordinator.persist_locked(&state);
    }
}

impl Drop for RequestAdmission {
    fn drop(&mut self) {
        self.release_inner();
    }
}

impl Clone for RoutingCoordinator {
    fn clone(&self) -> Self {
        Self {
            inner: Arc::clone(&self.inner),
            store_path: self.store_path.clone(),
            clock: Arc::clone(&self.clock),
            max_scan_age_ms: self.max_scan_age_ms,
        }
    }
}

impl RoutingCoordinator {
    pub fn load(
        store_path: impl Into<PathBuf>,
        max_scan_age_ms: u64,
    ) -> Result<Self, RoutingError> {
        Self::load_with_clock(store_path, max_scan_age_ms, Arc::new(SystemClock))
    }

    fn load_with_clock(
        store_path: impl Into<PathBuf>,
        max_scan_age_ms: u64,
        clock: Arc<dyn Clock>,
    ) -> Result<Self, RoutingError> {
        let store_path = store_path.into();
        let sessions = load_file(&store_path)?;
        Ok(Self {
            inner: Arc::new(Mutex::new(RoutingState { sessions })),
            store_path,
            clock,
            max_scan_age_ms,
        })
    }

    pub fn ensure_session(
        &self,
        session_id: &str,
        target: RouteTarget,
    ) -> Result<SessionRoute, RoutingError> {
        validate_target(&target)?;
        let mut state = self.lock();
        let now = self.clock.now_ms();
        let route = state
            .sessions
            .entry(session_id.to_owned())
            .or_insert_with(|| SessionRoute {
                desired: target.clone(),
                effective: target,
                revision: 0,
                pending_since_ms: None,
                transitioned_at_ms: now,
                last_error: None,
                active_requests: 0,
                host_idle: false,
                host_observed_at_ms: None,
            });
        let result = route.clone();
        self.persist_locked(&state)?;
        Ok(result)
    }

    pub fn request_change(
        &self,
        session_id: &str,
        target: RouteTarget,
        expected_revision: u64,
    ) -> Result<SessionRoute, RoutingError> {
        validate_target(&target)?;
        let mut state = self.lock();
        let route = state
            .sessions
            .get_mut(session_id)
            .ok_or_else(|| RoutingError::UnknownSession(session_id.to_owned()))?;
        if route.revision != expected_revision {
            return Err(RoutingError::StaleRevision {
                expected: expected_revision,
                current: route.revision,
            });
        }
        route.revision += 1;
        route.desired = target;
        route.pending_since_ms = (route.desired != route.effective).then(|| self.clock.now_ms());
        route.last_error = None;
        self.reconcile_route(route);
        let result = route.clone();
        self.persist_locked(&state)?;
        Ok(result)
    }

    pub fn observe_host(
        &self,
        session_id: &str,
        idle: bool,
        observed_at_ms: u64,
    ) -> Result<SessionRoute, RoutingError> {
        let mut state = self.lock();
        let route = state
            .sessions
            .get_mut(session_id)
            .ok_or_else(|| RoutingError::UnknownSession(session_id.to_owned()))?;
        route.host_idle = idle;
        route.host_observed_at_ms = Some(observed_at_ms);
        self.reconcile_route(route);
        let result = route.clone();
        self.persist_locked(&state)?;
        Ok(result)
    }

    pub fn admit(&self, session_id: &str) -> Result<RequestAdmission, RoutingError> {
        let mut state = self.lock();
        let route = state
            .sessions
            .get_mut(session_id)
            .ok_or_else(|| RoutingError::UnknownSession(session_id.to_owned()))?;
        route.active_requests += 1;
        Ok(RequestAdmission {
            session_id: session_id.to_owned(),
            target: route.effective.clone(),
            coordinator: self.clone(),
            released: false,
        })
    }

    pub fn session(&self, session_id: &str) -> Option<SessionRoute> {
        self.lock().sessions.get(session_id).cloned()
    }

    fn reconcile_route(&self, route: &mut SessionRoute) {
        if route.desired == route.effective
            || route.last_error.is_some()
            || route.active_requests != 0
        {
            return;
        }
        let now = self.clock.now_ms();
        let fresh_idle = route.host_idle
            && route
                .host_observed_at_ms
                .is_some_and(|observed| now.saturating_sub(observed) <= self.max_scan_age_ms);
        if !fresh_idle {
            return;
        }
        route.effective = route.desired.clone();
        route.pending_since_ms = None;
        route.transitioned_at_ms = now;
    }

    fn persist_locked(&self, state: &RoutingState) -> Result<(), RoutingError> {
        write_file(&self.store_path, &state.sessions)
    }

    fn lock(&self) -> MutexGuard<'_, RoutingState> {
        self.inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

fn validate_target(target: &RouteTarget) -> Result<(), RoutingError> {
    if target.model.trim().is_empty() || target.model.len() > 128 {
        return Err(RoutingError::InvalidTarget(
            "model must contain 1-128 characters".to_owned(),
        ));
    }
    Ok(())
}

fn load_file(path: &Path) -> Result<BTreeMap<String, SessionRoute>, RoutingError> {
    let bytes = match std::fs::read(path) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(BTreeMap::new()),
        Err(error) => return Err(error.into()),
    };
    let file: RoutingFile = serde_json::from_slice(&bytes)?;
    if file.schema_version != ROUTING_SCHEMA_VERSION {
        return Err(RoutingError::UnknownSchema(file.schema_version));
    }
    Ok(file.sessions)
}

fn write_file(path: &Path, sessions: &BTreeMap<String, SessionRoute>) -> Result<(), RoutingError> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700))?;
        }
    }
    let payload = serde_json::to_vec_pretty(&RoutingFile {
        schema_version: ROUTING_SCHEMA_VERSION,
        sessions: sessions.clone(),
    })?;
    let temp = path.with_extension(format!("tmp-{}", std::process::id()));
    std::fs::write(&temp, payload)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&temp, std::fs::Permissions::from_mode(0o600))?;
    }
    std::fs::rename(temp, path)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};
    use tempfile::TempDir;

    struct TestClock(AtomicU64);
    impl Clock for TestClock {
        fn now_ms(&self) -> u64 {
            self.0.load(Ordering::SeqCst)
        }
    }

    fn target(provider: RouteProvider, model: &str) -> RouteTarget {
        RouteTarget {
            provider,
            model: model.to_owned(),
        }
    }

    fn coordinator(temp: &TempDir, clock: Arc<TestClock>) -> RoutingCoordinator {
        RoutingCoordinator::load_with_clock(temp.path().join("routing.json"), 1_000, clock).unwrap()
    }

    #[test]
    fn pending_change_waits_for_host_idle_and_active_requests() {
        let temp = TempDir::new().unwrap();
        let clock = Arc::new(TestClock(AtomicU64::new(100)));
        let routing = coordinator(&temp, clock.clone());
        routing
            .ensure_session("s", target(RouteProvider::Codex, "gpt-5.6-sol"))
            .unwrap();
        routing.observe_host("s", true, 100).unwrap();
        let admission = routing.admit("s").unwrap();
        let changed = routing
            .request_change("s", target(RouteProvider::Anthropic, "claude-fable-5"), 0)
            .unwrap();
        assert_eq!(changed.status(), RouteStatus::PendingBusy);
        assert_eq!(changed.effective.provider, RouteProvider::Codex);
        admission.release();
        let final_route = routing.session("s").unwrap();
        assert_eq!(final_route.status(), RouteStatus::Stable);
        assert_eq!(final_route.effective.provider, RouteProvider::Anthropic);
    }

    #[test]
    fn stale_host_observation_does_not_activate() {
        let temp = TempDir::new().unwrap();
        let clock = Arc::new(TestClock(AtomicU64::new(5_000)));
        let routing = coordinator(&temp, clock);
        routing
            .ensure_session("s", target(RouteProvider::Codex, "gpt-5.6-sol"))
            .unwrap();
        routing.observe_host("s", true, 1_000).unwrap();
        let changed = routing
            .request_change("s", target(RouteProvider::Anthropic, "claude-fable-5"), 0)
            .unwrap();
        assert_eq!(changed.status(), RouteStatus::PendingBusy);
        assert_eq!(changed.effective.provider, RouteProvider::Codex);
    }

    #[test]
    fn stale_revision_cannot_overwrite_newer_choice() {
        let temp = TempDir::new().unwrap();
        let clock = Arc::new(TestClock(AtomicU64::new(100)));
        let routing = coordinator(&temp, clock);
        routing
            .ensure_session("s", target(RouteProvider::Codex, "gpt-5.6-sol"))
            .unwrap();
        routing
            .request_change("s", target(RouteProvider::Anthropic, "claude-fable-5"), 0)
            .unwrap();
        let error = routing
            .request_change("s", target(RouteProvider::Codex, "gpt-5.6-luna"), 0)
            .unwrap_err();
        assert!(matches!(
            error,
            RoutingError::StaleRevision { current: 1, .. }
        ));
    }

    #[test]
    fn persisted_state_resets_transient_fields() {
        let temp = TempDir::new().unwrap();
        let clock = Arc::new(TestClock(AtomicU64::new(100)));
        let path = temp.path().join("routing.json");
        let routing = RoutingCoordinator::load_with_clock(&path, 1_000, clock.clone()).unwrap();
        routing
            .ensure_session("s", target(RouteProvider::Codex, "gpt-5.6-sol"))
            .unwrap();
        let _admission = routing.admit("s").unwrap();
        let reloaded = RoutingCoordinator::load_with_clock(&path, 1_000, clock).unwrap();
        let route = reloaded.session("s").unwrap();
        assert_eq!(route.active_requests, 0);
        assert!(!route.host_idle);
        assert_eq!(route.host_observed_at_ms, None);
    }
}

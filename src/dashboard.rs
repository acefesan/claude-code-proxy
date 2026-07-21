use crate::{
    registry::Registry,
    routing::{
        RouteProvider, RouteStatus, RouteTarget, RoutingCoordinator, RoutingError, SessionRoute,
    },
    scanner::{ScanConfig, ScanResult, scan_sessions},
};
use axum::{
    Json, Router,
    body::Body,
    extract::{Path, State},
    http::{HeaderMap, Request, StatusCode, header},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{get, post, put},
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::{future::Future, sync::Arc, time::Duration};
use tokio::net::TcpListener;

const INDEX: &str = include_str!("../assets/dashboard/index.html");
const APP_JS: &str = include_str!("../assets/dashboard/app.js");
const STYLES: &str = include_str!("../assets/dashboard/styles.css");
const SESSION_COOKIE: &str = "ccp_admin";

#[derive(Clone)]
pub struct DashboardConfig {
    pub scan: ScanConfig,
    pub routing: RoutingCoordinator,
    pub initial_target: RouteTarget,
    pub admin_secret: Option<String>,
    pub allowed_origins: Vec<String>,
    /// When true, skip the admin-cookie check on mutating endpoints and trust the
    /// network boundary instead (loopback bind + Tailscale tailnet-only serve).
    /// The same-origin check still applies as CSRF protection. Intended for a
    /// single-user tailnet where the admin secret is redundant friction.
    pub trust_local_network: bool,
    /// Path to the `--settings` file that puts a session in gateway/proxy mode
    /// (sets `ANTHROPIC_BASE_URL` to the local proxy). Used when switching a
    /// session into proxy mode. None disables switching *into* proxy mode.
    pub proxy_settings_path: Option<String>,
}

#[derive(Clone)]
struct DashboardState {
    config: DashboardConfig,
    registry: Arc<Registry>,
    session_hash: Option<String>,
}

#[derive(Debug, Deserialize)]
struct LoginRequest {
    secret: String,
}

#[derive(Debug, Deserialize)]
struct ChangeRouteRequest {
    provider: RouteProvider,
    model: String,
    expected_revision: u64,
}

#[derive(Debug, Deserialize)]
struct ModeRequest {
    /// "native-rc" (first-party + Remote Control) or "proxy" (gateway-routed).
    mode: String,
    /// When true, return the exact relaunch plan without executing anything —
    /// the no-traffic smoke test.
    #[serde(default)]
    dry_run: bool,
    /// Optional Remote Control name override (native-rc mode).
    #[serde(default)]
    name: Option<String>,
}

/// The exact, side-effect-free relaunch plan for a mode switch. Serialized back
/// on a dry run so the whole switch can be inspected without spawning `claude`.
#[derive(Debug, Serialize, PartialEq, Eq)]
struct ModePlan {
    mode: String,
    resume_id: String,
    cwd: Option<String>,
    binary: String,
    argv: Vec<String>,
    /// Environment variables the child must NOT inherit (gateway leftovers that
    /// would otherwise trip the RC gate or mislabel the mode).
    env_unset: Vec<String>,
    /// The live process to stop first (its short id), if any.
    stop_short_id: Option<String>,
}

#[derive(Debug, Deserialize, Default)]
struct RemoteControlRequest {
    /// Optional override for the Remote Control session name. Defaults to the
    /// session's existing rc name, then its display name.
    #[serde(default)]
    name: Option<String>,
}

#[derive(Debug, Serialize)]
struct SessionView {
    #[serde(flatten)]
    observed: crate::scanner::ScannedSession,
    routing: Option<RouteView>,
}

#[derive(Debug, Serialize)]
struct RouteView {
    desired: RouteTarget,
    effective: RouteTarget,
    revision: u64,
    pending_since_ms: Option<u64>,
    transitioned_at_ms: u64,
    last_error: Option<String>,
    active_requests: usize,
    host_idle: bool,
    host_observed_at_ms: Option<u64>,
    status: RouteStatus,
}

impl From<SessionRoute> for RouteView {
    fn from(route: SessionRoute) -> Self {
        Self {
            status: route.status(),
            desired: route.desired,
            effective: route.effective,
            revision: route.revision,
            pending_since_ms: route.pending_since_ms,
            transitioned_at_ms: route.transitioned_at_ms,
            last_error: route.last_error,
            active_requests: route.active_requests,
            host_idle: route.host_idle,
            host_observed_at_ms: route.host_observed_at_ms,
        }
    }
}

#[derive(Debug, Serialize)]
struct SessionsView {
    scanned_at_ms: u64,
    counts: crate::scanner::SessionCounts,
    sessions: Vec<SessionView>,
    warnings: Vec<String>,
}

pub async fn bind_dashboard_listener(port: u16) -> anyhow::Result<TcpListener> {
    let address = format!("127.0.0.1:{port}");
    TcpListener::bind(&address)
        .await
        .map_err(|error| anyhow::anyhow!("failed to bind dashboard listener on {address}: {error}"))
}

pub async fn serve_listener(
    listener: TcpListener,
    registry: Arc<Registry>,
    config: DashboardConfig,
    shutdown: impl Future<Output = ()> + Send + 'static,
) -> anyhow::Result<()> {
    axum::serve(listener, app(registry, config))
        .with_graceful_shutdown(shutdown)
        .await?;
    Ok(())
}

pub fn app(registry: Arc<Registry>, config: DashboardConfig) -> Router {
    assert!(
        !config.allowed_origins.is_empty()
            && config
                .allowed_origins
                .iter()
                .all(|origin| valid_origin(origin)),
        "dashboard origins must be HTTPS or HTTP loopback origins"
    );
    let session_hash = config.admin_secret.as_deref().map(hash_secret);
    let state = DashboardState {
        config,
        registry,
        session_hash,
    };
    Router::new()
        .route("/", get(index))
        .route("/app.js", get(app_js))
        .route("/styles.css", get(styles))
        .route("/health", get(health))
        .route("/api/v1/login", post(login))
        .route("/api/v1/sessions", get(sessions))
        .route("/api/v1/providers", get(providers))
        .route("/api/v1/sessions/{session_id}/route", put(change_route))
        .route(
            "/api/v1/sessions/{session_id}/remote-control",
            post(enable_remote_control),
        )
        .route("/api/v1/sessions/{session_id}/mode", post(switch_mode))
        .fallback(not_found)
        .layer(middleware::from_fn(security_headers))
        .with_state(state)
}

async fn security_headers(request: Request<Body>, next: Next) -> Response {
    let mut response = next.run(request).await;
    let headers = response.headers_mut();
    headers.insert(header::X_CONTENT_TYPE_OPTIONS, "nosniff".parse().unwrap());
    headers.insert(header::REFERRER_POLICY, "no-referrer".parse().unwrap());
    headers.insert(header::CACHE_CONTROL, "no-store".parse().unwrap());
    headers.insert("x-frame-options", "DENY".parse().unwrap());
    headers.insert("content-security-policy", "default-src 'self'; script-src 'self'; style-src 'self'; object-src 'none'; frame-ancestors 'none'; base-uri 'none'".parse().unwrap());
    response
}

async fn health() -> Json<serde_json::Value> {
    Json(json!({"ok": true, "proof": health_proof()}))
}

fn health_proof() -> Option<String> {
    std::env::var("CCP_HEALTH_NONCE")
        .ok()
        .map(|nonce| hash_secret(&nonce))
}

async fn login(
    State(state): State<DashboardState>,
    headers: HeaderMap,
    Json(body): Json<LoginRequest>,
) -> Response {
    if !same_origin(&state, &headers) {
        return error(StatusCode::FORBIDDEN, "origin_not_allowed");
    }
    let Some(expected) = state.session_hash.as_deref() else {
        return error(StatusCode::SERVICE_UNAVAILABLE, "admin_auth_not_configured");
    };
    if !constant_time_eq(expected.as_bytes(), hash_secret(&body.secret).as_bytes()) {
        return error(StatusCode::UNAUTHORIZED, "invalid_admin_secret");
    }
    let secure = if request_origin(&headers).is_some_and(|origin| origin.starts_with("https://")) {
        "; Secure"
    } else {
        ""
    };
    let cookie = format!(
        "{SESSION_COOKIE}={expected}; HttpOnly; SameSite=Strict; Path=/; Max-Age=3600{secure}"
    );
    (StatusCode::NO_CONTENT, [(header::SET_COOKIE, cookie)]).into_response()
}

async fn sessions(State(state): State<DashboardState>) -> Response {
    let result = scan_sessions(&state.config.scan);
    match enrich_sessions(&state, result) {
        Ok(view) => Json(view).into_response(),
        Err(routing_error) => error(
            StatusCode::INTERNAL_SERVER_ERROR,
            &routing_error.to_string(),
        ),
    }
}

fn enrich_sessions(
    state: &DashboardState,
    result: ScanResult,
) -> Result<SessionsView, RoutingError> {
    let mut views = Vec::with_capacity(result.sessions.len());
    let mut counts = result.counts.clone();
    for observed in result.sessions {
        let routing = if let (true, true, Some(session_id)) = (
            observed.live,
            observed.managed,
            observed.session_id.as_deref(),
        ) {
            state
                .config
                .routing
                .ensure_session(session_id, state.config.initial_target.clone())?;
            let route: RouteView = state
                .config
                .routing
                .observe_host(
                    session_id,
                    host_quiescent(&observed.status),
                    result.scanned_at_ms,
                )?
                .into();
            counts.unknown = counts.unknown.saturating_sub(1);
            match route.effective.provider {
                RouteProvider::Anthropic => counts.anthropic += 1,
                RouteProvider::Codex => counts.codex += 1,
            }
            Some(route)
        } else {
            None
        };
        views.push(SessionView { observed, routing });
    }
    Ok(SessionsView {
        scanned_at_ms: result.scanned_at_ms,
        counts,
        sessions: views,
        warnings: result.warnings,
    })
}

fn host_quiescent(status: &str) -> bool {
    matches!(status, "idle" | "blocked")
}

async fn providers(State(state): State<DashboardState>) -> impl IntoResponse {
    Json(json!({"providers":[
        {
            "id":"anthropic",
            "available":true,
            "models":["claude-fable-5"],
            "picker_behavior":"passthrough"
        },
        {
            "id":"codex",
            "available":true,
            "models":state.registry.concrete_models_for("codex"),
            "picker_behavior":"override"
        }
    ]}))
}

async fn change_route(
    State(state): State<DashboardState>,
    Path(session_id): Path<String>,
    headers: HeaderMap,
    Json(body): Json<ChangeRouteRequest>,
) -> Response {
    if !same_origin(&state, &headers) {
        return error(StatusCode::FORBIDDEN, "origin_not_allowed");
    }
    if !authenticated(&state, &headers) {
        return error(StatusCode::UNAUTHORIZED, "admin_auth_required");
    }
    let managed = scan_sessions(&state.config.scan)
        .sessions
        .into_iter()
        .any(|session| {
            session.live
                && session.managed
                && session.session_id.as_deref() == Some(session_id.as_str())
        });
    if !managed {
        return error(StatusCode::BAD_REQUEST, "session_not_proxy_managed");
    }
    if !model_allowed(&state, &body.provider, &body.model) {
        return error(StatusCode::BAD_REQUEST, "unsupported_provider_model");
    }
    match state.config.routing.request_change(
        &session_id,
        RouteTarget {
            provider: body.provider,
            model: body.model,
        },
        body.expected_revision,
    ) {
        Ok(route) => Json(RouteView::from(route)).into_response(),
        Err(RoutingError::StaleRevision { .. }) => error(StatusCode::CONFLICT, "stale_revision"),
        Err(RoutingError::UnknownSession(_)) => error(StatusCode::NOT_FOUND, "unknown_session"),
        Err(other) => error(StatusCode::BAD_REQUEST, &other.to_string()),
    }
}

/// Re-arm Remote Control on a session by resuming it with `--remote-control`.
/// This works for any session (managed or native) because rc is orthogonal to
/// which provider serves it. Because the `claude` CLI only enables rc at launch,
/// re-arming necessarily resumes the session from its last transcript checkpoint
/// — the live process (if any) is stopped first to avoid a duplicate.
async fn enable_remote_control(
    State(state): State<DashboardState>,
    Path(session_id): Path<String>,
    headers: HeaderMap,
    Json(body): Json<RemoteControlRequest>,
) -> Response {
    if !same_origin(&state, &headers) {
        return error(StatusCode::FORBIDDEN, "origin_not_allowed");
    }
    if !authenticated(&state, &headers) {
        return error(StatusCode::UNAUTHORIZED, "admin_auth_required");
    }
    let Some(spec) = crate::scanner::launch_spec(&state.config.scan, &session_id) else {
        return error(StatusCode::NOT_FOUND, "unknown_session");
    };
    let rc_name = body
        .name
        .or_else(|| spec.rc_name.clone())
        .or_else(|| spec.name.clone())
        .map(|name| sanitize_rc_name(&name))
        .filter(|name| !name.is_empty())
        .unwrap_or_else(|| "session".to_owned());
    match resume_with_remote_control(&spec, &rc_name).await {
        Ok(new_session_id) => Json(json!({
            "ok": true,
            "rc_name": rc_name,
            "resumed_from": spec.resume_id,
            "was_live": spec.live,
            "new_session_id": new_session_id,
        }))
        .into_response(),
        Err(err) => error(StatusCode::INTERNAL_SERVER_ERROR, &format!("relaunch_failed: {err}")),
    }
}

/// Switch a bg session between routing modes by pausing and resuming its
/// transcript in the target mode. `native-rc` = first-party + Remote Control
/// (phone-steerable); `proxy` = gateway-routed (Codex). The transcript carries
/// across; only in-flight work since the last checkpoint is lost. `dry_run`
/// returns the exact plan without touching anything.
async fn switch_mode(
    State(state): State<DashboardState>,
    Path(session_id): Path<String>,
    headers: HeaderMap,
    Json(body): Json<ModeRequest>,
) -> Response {
    if !same_origin(&state, &headers) {
        return error(StatusCode::FORBIDDEN, "origin_not_allowed");
    }
    if !authenticated(&state, &headers) {
        return error(StatusCode::UNAUTHORIZED, "admin_auth_required");
    }
    let Some(spec) = crate::scanner::launch_spec(&state.config.scan, &session_id) else {
        return error(StatusCode::NOT_FOUND, "unknown_session");
    };
    let rc_name = body
        .name
        .or_else(|| spec.rc_name.clone())
        .or_else(|| spec.name.clone())
        .map(|name| sanitize_rc_name(&name))
        .filter(|name| !name.is_empty())
        .unwrap_or_else(|| "session".to_owned());
    let binary = claude_binary().to_string_lossy().into_owned();
    let plan = match mode_plan(
        &spec,
        &body.mode,
        &rc_name,
        state.config.proxy_settings_path.as_deref(),
        &binary,
    ) {
        Ok(plan) => plan,
        Err(err) => return error(StatusCode::BAD_REQUEST, &err),
    };
    if body.dry_run {
        return Json(json!({ "dry_run": true, "plan": plan })).into_response();
    }
    match execute_mode_plan(&plan).await {
        Ok(new_session_id) => Json(json!({
            "ok": true,
            "mode": plan.mode,
            "resumed_from": plan.resume_id,
            "new_session_id": new_session_id,
        }))
        .into_response(),
        Err(err) => error(StatusCode::INTERNAL_SERVER_ERROR, &format!("switch_failed: {err}")),
    }
}

/// Build the relaunch plan for a mode switch. Pure — no I/O, no spawning — so it
/// is fully unit-testable and safe to expose as a dry run.
fn mode_plan(
    spec: &crate::scanner::LaunchSpec,
    mode: &str,
    rc_name: &str,
    proxy_settings: Option<&str>,
    binary: &str,
) -> Result<ModePlan, String> {
    // Keep the session's own flags, minus the ones each mode owns and re-adds.
    let preserved = strip_flags(&spec.respawn_flags, &["--remote-control", "--settings"]);
    let mut argv = vec![
        "--resume".to_owned(),
        spec.resume_id.clone(),
        "--bg".to_owned(),
    ];
    let env_unset = match mode {
        "native-rc" => {
            argv.push("--remote-control".to_owned());
            argv.push(rc_name.to_owned());
            // Native must be first-party direct to Anthropic: strip any gateway
            // env the launcher would otherwise inherit and that trips the RC gate.
            vec![
                "ANTHROPIC_BASE_URL".to_owned(),
                "CCP_ALIAS_PROVIDER".to_owned(),
                "ANTHROPIC_UNIX_SOCKET".to_owned(),
            ]
        }
        "proxy" => {
            let settings =
                proxy_settings.ok_or_else(|| "proxy_settings_not_configured".to_owned())?;
            argv.push("--settings".to_owned());
            argv.push(settings.to_owned());
            Vec::new()
        }
        other => return Err(format!("unknown_mode: {other}")),
    };
    argv.extend(preserved);
    Ok(ModePlan {
        mode: mode.to_owned(),
        resume_id: spec.resume_id.clone(),
        cwd: spec.cwd.clone(),
        binary: binary.to_owned(),
        argv,
        env_unset,
        stop_short_id: spec.live.then(|| {
            spec.resume_id
                .split('-')
                .next()
                .unwrap_or(&spec.resume_id)
                .to_owned()
        }),
    })
}

/// Drop `strip` flags (and any following value token) from a flag list.
fn strip_flags(flags: &[String], strip: &[&str]) -> Vec<String> {
    let mut out = Vec::new();
    let mut iter = flags.iter().peekable();
    while let Some(flag) = iter.next() {
        if strip.contains(&flag.as_str()) {
            if iter.peek().is_some_and(|next| !next.starts_with("--")) {
                iter.next();
            }
            continue;
        }
        out.push(flag.clone());
    }
    out
}

async fn execute_mode_plan(plan: &ModePlan) -> anyhow::Result<Option<String>> {
    let cwd = plan.cwd.clone().unwrap_or_else(|| ".".to_owned());
    if let Some(short) = &plan.stop_short_id {
        let _ = tokio::process::Command::new(&plan.binary)
            .arg("stop")
            .arg(short)
            .current_dir(&cwd)
            .output()
            .await;
    }
    let mut command = tokio::process::Command::new(&plan.binary);
    command.args(&plan.argv).current_dir(&cwd);
    for key in &plan.env_unset {
        command.env_remove(key);
    }
    let output = tokio::time::timeout(Duration::from_secs(25), command.output())
        .await
        .map_err(|_| anyhow::anyhow!("claude did not return within 25s"))??;
    let mut combined = String::from_utf8_lossy(&output.stdout).into_owned();
    combined.push_str(&String::from_utf8_lossy(&output.stderr));
    let new_session_id = combined.split("backgrounded").nth(1).and_then(|rest| {
        rest.split(|c: char| !c.is_ascii_hexdigit())
            .find(|token| token.len() >= 6)
            .map(str::to_owned)
    });
    if !output.status.success() && new_session_id.is_none() {
        anyhow::bail!("claude exited with {}: {}", output.status, combined.trim());
    }
    Ok(new_session_id)
}

async fn resume_with_remote_control(
    spec: &crate::scanner::LaunchSpec,
    rc_name: &str,
) -> anyhow::Result<Option<String>> {
    let claude = claude_binary();
    let cwd = spec.cwd.clone().unwrap_or_else(|| ".".to_owned());

    // Stop the still-running process first so resuming doesn't fork a duplicate.
    // `claude stop` takes the short id (the uuid's first segment), not the full id.
    if spec.live {
        let short = spec.resume_id.split('-').next().unwrap_or(&spec.resume_id);
        let _ = tokio::process::Command::new(&claude)
            .arg("stop")
            .arg(short)
            .current_dir(&cwd)
            .output()
            .await;
    }

    let mut args = vec![
        "--resume".to_owned(),
        spec.resume_id.clone(),
        "--remote-control".to_owned(),
        rc_name.to_owned(),
        "--bg".to_owned(),
    ];
    // Carry the original dispatch flags, dropping any prior `--remote-control [name]`.
    let mut flags = spec.respawn_flags.iter().peekable();
    while let Some(flag) = flags.next() {
        if flag == "--remote-control" {
            if flags.peek().is_some_and(|next| !next.starts_with("--")) {
                flags.next();
            }
            continue;
        }
        args.push(flag.clone());
    }

    let output = tokio::time::timeout(
        Duration::from_secs(25),
        tokio::process::Command::new(&claude)
            .args(&args)
            .current_dir(&cwd)
            .output(),
    )
    .await
    .map_err(|_| anyhow::anyhow!("claude did not return within 25s"))??;

    let mut combined = String::from_utf8_lossy(&output.stdout).into_owned();
    combined.push_str(&String::from_utf8_lossy(&output.stderr));
    // `claude --bg` prints "backgrounded · <shortid>" on success.
    let new_session_id = combined
        .split("backgrounded")
        .nth(1)
        .and_then(|rest| {
            rest.split(|c: char| !c.is_ascii_hexdigit())
                .find(|token| token.len() >= 6)
                .map(str::to_owned)
        });
    if !output.status.success() && new_session_id.is_none() {
        anyhow::bail!("claude exited with {}: {}", output.status, combined.trim());
    }
    Ok(new_session_id)
}

/// Locate the `claude` binary: an explicit `CLAUDE_BIN`, else the standard
/// user-local install, else rely on PATH.
fn claude_binary() -> std::path::PathBuf {
    if let Some(bin) = std::env::var_os("CLAUDE_BIN") {
        return bin.into();
    }
    if let Some(home) = std::env::var_os("HOME") {
        let candidate = std::path::Path::new(&home).join(".local/bin/claude");
        if candidate.exists() {
            return candidate;
        }
    }
    "claude".into()
}

/// Reduce a display name to a safe Remote Control name (alphanumerics, dash,
/// underscore; capped length). Passed as an argv element, so this is defensive,
/// not a shell-injection guard.
fn sanitize_rc_name(name: &str) -> String {
    name.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                c
            } else {
                '-'
            }
        })
        .collect::<String>()
        .trim_matches('-')
        .chars()
        .take(60)
        .collect()
}

fn model_allowed(state: &DashboardState, provider: &RouteProvider, model: &str) -> bool {
    match provider {
        RouteProvider::Anthropic => [
            "claude-fable-5",
            "claude-opus-4-8",
            "claude-sonnet-5",
            "claude-haiku-4-5",
        ]
        .contains(&model),
        RouteProvider::Codex => state
            .registry
            .concrete_models_for("codex")
            .iter()
            .any(|candidate| candidate == model),
    }
}

fn valid_origin(origin: &str) -> bool {
    let Ok(url) = url::Url::parse(origin) else {
        return false;
    };
    if url.scheme() == "https" {
        return true;
    }
    url.scheme() == "http"
        && url.host_str().is_some_and(|host| {
            host == "localhost"
                || host
                    .parse::<std::net::IpAddr>()
                    .is_ok_and(|ip| ip.is_loopback())
        })
}

fn request_origin(headers: &HeaderMap) -> Option<&str> {
    headers.get(header::ORIGIN)?.to_str().ok()
}

fn same_origin(state: &DashboardState, headers: &HeaderMap) -> bool {
    request_origin(headers).is_some_and(|origin| {
        state
            .config
            .allowed_origins
            .iter()
            .any(|allowed| allowed == origin)
    })
}

fn authenticated(state: &DashboardState, headers: &HeaderMap) -> bool {
    // Trusted-network mode: the caller already cleared same-origin, and the
    // dashboard is reachable only over loopback + the tailnet, so skip the
    // admin-cookie factor entirely.
    if state.config.trust_local_network {
        return true;
    }
    let Some(expected) = state.session_hash.as_deref() else {
        return false;
    };
    headers
        .get(header::COOKIE)
        .and_then(|value| value.to_str().ok())
        .and_then(|cookies| {
            cookies
                .split(';')
                .map(str::trim)
                .find_map(|cookie| cookie.strip_prefix(&format!("{SESSION_COOKIE}=")))
        })
        .is_some_and(|value| constant_time_eq(value.as_bytes(), expected.as_bytes()))
}

fn hash_secret(secret: &str) -> String {
    format!("{:x}", Sha256::digest(secret.as_bytes()))
}
fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    left.iter()
        .zip(right)
        .fold(0u8, |diff, (a, b)| diff | (a ^ b))
        == 0
}
fn error(status: StatusCode, code: &str) -> Response {
    (status, Json(json!({"error":code}))).into_response()
}
async fn index() -> Response {
    asset("text/html; charset=utf-8", INDEX, "no-cache")
}
async fn app_js() -> Response {
    asset(
        "text/javascript; charset=utf-8",
        APP_JS,
        "public, max-age=300",
    )
}
async fn styles() -> Response {
    asset("text/css; charset=utf-8", STYLES, "public, max-age=300")
}
fn asset(content_type: &'static str, body: &'static str, cache: &'static str) -> Response {
    (
        StatusCode::OK,
        [
            (header::CONTENT_TYPE, content_type),
            (header::CACHE_CONTROL, cache),
        ],
        body,
    )
        .into_response()
}
async fn not_found() -> impl IntoResponse {
    (StatusCode::NOT_FOUND, Json(json!({"error":"not found"})))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        body::Body,
        http::{Method, Request},
    };
    use tempfile::TempDir;
    use tower::ServiceExt;

    fn fixture() -> (TempDir, DashboardConfig) {
        let temp = TempDir::new().unwrap();
        let scan = ScanConfig {
            claude_dir: temp.path().join(".claude"),
            proc_dir: temp.path().join("proc"),
        };
        std::fs::create_dir_all(scan.claude_dir.join("sessions")).unwrap();
        std::fs::create_dir_all(&scan.proc_dir).unwrap();
        let routing = RoutingCoordinator::load(temp.path().join("routing.json"), 10_000).unwrap();
        (
            temp,
            DashboardConfig {
                scan,
                routing,
                initial_target: RouteTarget {
                    provider: RouteProvider::Anthropic,
                    model: "claude-fable-5".to_owned(),
                },
                admin_secret: Some("test-secret".to_owned()),
                allowed_origins: vec!["http://127.0.0.1:3036".to_owned()],
                trust_local_network: false,
                proxy_settings_path: Some("/cfg/proxy-settings.json".to_owned()),
            },
        )
    }

    #[tokio::test]
    async fn dashboard_serves_assets_and_excludes_proxy_routes() {
        let (_temp, config) = fixture();
        let app = app(Arc::new(Registry::with_default_alias()), config);
        for path in ["/", "/app.js", "/styles.css", "/api/v1/sessions"] {
            assert_eq!(
                app.clone()
                    .oneshot(Request::builder().uri(path).body(Body::empty()).unwrap())
                    .await
                    .unwrap()
                    .status(),
                StatusCode::OK
            );
        }
        assert_eq!(
            app.oneshot(
                Request::builder()
                    .uri("/v1/messages")
                    .body(Body::empty())
                    .unwrap()
            )
            .await
            .unwrap()
            .status(),
            StatusCode::NOT_FOUND
        );
    }

    #[tokio::test]
    async fn route_mutation_requires_origin_and_admin_session() {
        let (_temp, config) = fixture();
        config
            .routing
            .ensure_session(
                "session",
                RouteTarget {
                    provider: RouteProvider::Codex,
                    model: "gpt-5.6-sol".to_owned(),
                },
            )
            .unwrap();
        let app = app(Arc::new(Registry::with_default_alias()), config);
        let request = || {
            Request::builder()
                .method(Method::PUT)
                .uri("/api/v1/sessions/session/route")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    r#"{"provider":"anthropic","model":"claude-fable-5","expected_revision":0}"#,
                ))
                .unwrap()
        };
        assert_eq!(
            app.clone().oneshot(request()).await.unwrap().status(),
            StatusCode::FORBIDDEN
        );
        let mut with_origin = request();
        with_origin
            .headers_mut()
            .insert(header::ORIGIN, "http://127.0.0.1:3036".parse().unwrap());
        assert_eq!(
            app.oneshot(with_origin).await.unwrap().status(),
            StatusCode::UNAUTHORIZED
        );
    }

    #[tokio::test]
    async fn trust_local_network_bypasses_admin_but_keeps_same_origin() {
        let (_temp, mut config) = fixture();
        config.trust_local_network = true;
        let app = app(Arc::new(Registry::with_default_alias()), config);
        let request = || {
            Request::builder()
                .method(Method::PUT)
                .uri("/api/v1/sessions/session/route")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    r#"{"provider":"anthropic","model":"claude-fable-5","expected_revision":0}"#,
                ))
                .unwrap()
        };
        // Same-origin is still enforced even in trusted mode.
        assert_eq!(
            app.clone().oneshot(request()).await.unwrap().status(),
            StatusCode::FORBIDDEN
        );
        // With a valid origin and NO admin cookie, auth is bypassed: the request
        // gets past the 401 gate and fails later on the managed-session check.
        let mut with_origin = request();
        with_origin
            .headers_mut()
            .insert(header::ORIGIN, "http://127.0.0.1:3036".parse().unwrap());
        assert_eq!(
            app.oneshot(with_origin).await.unwrap().status(),
            StatusCode::BAD_REQUEST
        );
    }

    fn spec(live: bool, flags: &[&str]) -> crate::scanner::LaunchSpec {
        crate::scanner::LaunchSpec {
            resume_id: "abcd1234-5678-90ab-cdef-1234567890ab".to_owned(),
            cwd: Some("/home/x/proj".to_owned()),
            respawn_flags: flags.iter().map(|s| s.to_string()).collect(),
            name: Some("my-agent".to_owned()),
            rc_name: None,
            live,
        }
    }

    #[test]
    fn mode_plan_native_rc_strips_gateway_and_arms_rc() {
        let s = spec(
            true,
            &[
                "--settings",
                "/cfg/proxy-settings.json",
                "--agent",
                "claude",
                "--allow-dangerously-skip-permissions",
                "--model",
                "claude-sonnet-4-6",
            ],
        );
        let plan = mode_plan(&s, "native-rc", "my-agent", Some("/cfg/proxy.json"), "claude").unwrap();
        // resume + rc, proxy --settings stripped, other flags preserved.
        assert_eq!(
            plan.argv,
            vec![
                "--resume",
                "abcd1234-5678-90ab-cdef-1234567890ab",
                "--bg",
                "--remote-control",
                "my-agent",
                "--agent",
                "claude",
                "--allow-dangerously-skip-permissions",
                "--model",
                "claude-sonnet-4-6",
            ]
        );
        assert!(plan.env_unset.contains(&"ANTHROPIC_BASE_URL".to_owned()));
        assert!(plan.env_unset.contains(&"CCP_ALIAS_PROVIDER".to_owned()));
        assert!(!plan.argv.iter().any(|a| a == "--settings"));
        assert_eq!(plan.stop_short_id.as_deref(), Some("abcd1234"));
    }

    #[test]
    fn mode_plan_proxy_adds_settings_no_rc() {
        let s = spec(false, &["--remote-control", "old-name", "--agent", "claude"]);
        let plan = mode_plan(&s, "proxy", "x", Some("/cfg/proxy.json"), "claude").unwrap();
        assert_eq!(
            plan.argv,
            vec![
                "--resume",
                "abcd1234-5678-90ab-cdef-1234567890ab",
                "--bg",
                "--settings",
                "/cfg/proxy.json",
                "--agent",
                "claude",
            ]
        );
        assert!(plan.env_unset.is_empty());
        assert!(!plan.argv.iter().any(|a| a == "--remote-control"));
        assert_eq!(plan.stop_short_id, None, "terminated session isn't stopped");
    }

    #[test]
    fn mode_plan_proxy_without_settings_configured_errors() {
        let s = spec(true, &[]);
        assert!(mode_plan(&s, "proxy", "x", None, "claude").is_err());
        assert!(mode_plan(&s, "teleport", "x", Some("/p"), "claude").is_err());
    }

    #[test]
    fn blocked_and_idle_sessions_are_quiescent() {
        assert!(host_quiescent("idle"));
        assert!(host_quiescent("blocked"));
        assert!(!host_quiescent("busy"));
        assert!(!host_quiescent("unknown"));
    }

    #[test]
    fn provider_targets_exclude_request_aliases() {
        let registry = Registry::with_default_alias();
        let codex = registry.concrete_models_for("codex");
        assert!(codex.contains(&"gpt-5.6-sol".to_owned()));
        assert!(!codex.contains(&"claude-opus-4-8".to_owned()));
        assert!(!codex.contains(&"opus".to_owned()));
    }

    #[test]
    fn only_https_or_loopback_http_origins_are_valid() {
        assert!(valid_origin("https://example.tailnet.ts.net"));
        assert!(valid_origin("http://127.0.0.1:3036"));
        assert!(valid_origin("http://localhost:3036"));
        assert!(!valid_origin("http://remote.example:3036"));
        assert!(!valid_origin("not-an-origin"));
    }

    #[test]
    fn dashboard_has_accessible_provider_identity_without_route_borders() {
        assert!(APP_JS.contains("aria-label=\"Anthropic\""));
        assert!(APP_JS.contains("aria-label=\"OpenAI\""));
        assert!(APP_JS.contains("aria-label=\"Native or unknown provider\""));
        assert!(APP_JS.contains("Proxy managed"));
        assert!(APP_JS.contains("Native / unmanaged"));
        assert!(APP_JS.contains("passed through unchanged"));
        assert!(APP_JS.contains("ignored for target selection"));
        assert!(!STYLES.contains("border-left"));
    }
}

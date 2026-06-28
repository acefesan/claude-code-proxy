use std::{
    collections::{HashMap, VecDeque},
    path::PathBuf,
    sync::{Arc, Mutex},
    time::{Duration, Instant, SystemTime},
};

const DEFAULT_RECENT_LIMIT: usize = 200;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EndpointKind {
    Messages,
    CountTokens,
}

impl EndpointKind {
    pub fn label(self) -> &'static str {
        match self {
            Self::Messages => "messages",
            Self::CountTokens => "count_tokens",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RequestStatus {
    Started,
    ProviderSelected,
    Upstream,
    Streaming,
    Completed,
    Failed,
}

impl RequestStatus {
    pub fn label(&self) -> &'static str {
        match self {
            Self::Started => "started",
            Self::ProviderSelected => "selected",
            Self::Upstream => "upstream",
            Self::Streaming => "streaming",
            Self::Completed => "completed",
            Self::Failed => "failed",
        }
    }
}

#[derive(Debug, Clone)]
pub enum MonitorEvent {
    RequestStarted {
        request_id: String,
        session_id: Option<String>,
        session_seq: Option<u64>,
        endpoint: EndpointKind,
    },
    ProviderSelected {
        request_id: String,
        provider: String,
        model: String,
    },
    UpstreamStarted {
        request_id: String,
    },
    TrafficCapturePath {
        request_id: String,
        path: PathBuf,
    },
    StreamProgress {
        request_id: String,
        bytes: u64,
        chunks: u64,
        input_tokens: Option<u64>,
        output_tokens: Option<u64>,
    },
    UsageUpdated {
        request_id: String,
        input_tokens: Option<u64>,
        output_tokens: Option<u64>,
    },
    RequestCompleted {
        request_id: String,
        http_status: u16,
        input_tokens: Option<u64>,
        output_tokens: Option<u64>,
    },
    RequestFailed {
        request_id: String,
        http_status: Option<u16>,
        error: String,
    },
}

#[derive(Debug, Clone)]
pub struct ActiveRequest {
    pub request_id: String,
    pub session_id: Option<String>,
    pub session_seq: Option<u64>,
    pub provider: Option<String>,
    pub model: Option<String>,
    pub endpoint: EndpointKind,
    pub started_at: SystemTime,
    started_instant: Instant,
    pub status: RequestStatus,
    pub streamed_bytes: u64,
    pub stream_chunks: u64,
    pub input_tokens: Option<u64>,
    pub output_tokens: Option<u64>,
    pub error: Option<String>,
    pub traffic_capture_path: Option<PathBuf>,
}

impl ActiveRequest {
    pub fn elapsed(&self) -> Duration {
        self.started_instant.elapsed()
    }

    pub fn rate(&self) -> Throughput {
        throughput(
            self.output_tokens,
            self.streamed_bytes,
            self.stream_chunks,
            self.elapsed(),
        )
    }
}

#[derive(Debug, Clone)]
pub struct CompletedRequest {
    pub request_id: String,
    pub session_id: Option<String>,
    pub session_seq: Option<u64>,
    pub provider: Option<String>,
    pub model: Option<String>,
    pub endpoint: EndpointKind,
    pub started_at: SystemTime,
    pub finished_at: SystemTime,
    pub status: RequestStatus,
    pub http_status: Option<u16>,
    pub latency: Duration,
    pub streamed_bytes: u64,
    pub stream_chunks: u64,
    pub input_tokens: Option<u64>,
    pub output_tokens: Option<u64>,
    pub error: Option<String>,
    pub traffic_capture_path: Option<PathBuf>,
}

impl CompletedRequest {
    pub fn rate(&self) -> Throughput {
        throughput(
            self.output_tokens,
            self.streamed_bytes,
            self.stream_chunks,
            self.latency,
        )
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum Throughput {
    TokensPerSecond(f64),
    BytesPerSecond(f64),
    EventsPerSecond(f64),
    None,
}

impl Throughput {
    pub fn label(&self) -> String {
        match self {
            Self::TokensPerSecond(value) => format!("{value:.1} tok/s"),
            Self::BytesPerSecond(value) if *value >= 1024.0 => {
                format!("{:.1} KB/s", value / 1024.0)
            }
            Self::BytesPerSecond(value) => format!("{value:.0} B/s"),
            Self::EventsPerSecond(value) => format!("{value:.1} ev/s"),
            Self::None => "-".to_string(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct MonitorState {
    pub started_at: SystemTime,
    pub active: Vec<ActiveRequest>,
    pub recent: Vec<CompletedRequest>,
}

#[derive(Debug)]
struct MonitorStore {
    started_at: SystemTime,
    active: HashMap<String, ActiveRequest>,
    recent: VecDeque<CompletedRequest>,
    recent_limit: usize,
}

#[derive(Debug, Clone)]
pub struct MonitorHandle {
    store: Arc<Mutex<MonitorStore>>,
}

impl Default for MonitorHandle {
    fn default() -> Self {
        Self::new(DEFAULT_RECENT_LIMIT)
    }
}

impl MonitorHandle {
    pub fn new(recent_limit: usize) -> Self {
        Self {
            store: Arc::new(Mutex::new(MonitorStore {
                started_at: SystemTime::now(),
                active: HashMap::new(),
                recent: VecDeque::new(),
                recent_limit,
            })),
        }
    }

    pub fn publish(&self, event: MonitorEvent) {
        if let Ok(mut store) = self.store.lock() {
            store.apply(event);
        }
    }

    pub fn snapshot(&self) -> MonitorState {
        match self.store.lock() {
            Ok(store) => store.snapshot(),
            Err(_) => MonitorState {
                started_at: SystemTime::now(),
                active: Vec::new(),
                recent: Vec::new(),
            },
        }
    }

    pub fn request_started(
        &self,
        request_id: impl Into<String>,
        session_id: Option<String>,
        session_seq: Option<u64>,
        endpoint: EndpointKind,
    ) {
        self.publish(MonitorEvent::RequestStarted {
            request_id: request_id.into(),
            session_id,
            session_seq,
            endpoint,
        });
    }

    pub fn provider_selected(
        &self,
        request_id: impl Into<String>,
        provider: impl Into<String>,
        model: impl Into<String>,
    ) {
        self.publish(MonitorEvent::ProviderSelected {
            request_id: request_id.into(),
            provider: provider.into(),
            model: model.into(),
        });
    }

    pub fn upstream_started(&self, request_id: impl Into<String>) {
        self.publish(MonitorEvent::UpstreamStarted {
            request_id: request_id.into(),
        });
    }

    pub fn traffic_capture_path(&self, request_id: impl Into<String>, path: PathBuf) {
        self.publish(MonitorEvent::TrafficCapturePath {
            request_id: request_id.into(),
            path,
        });
    }

    pub fn stream_progress(
        &self,
        request_id: impl Into<String>,
        bytes: u64,
        chunks: u64,
        input_tokens: Option<u64>,
        output_tokens: Option<u64>,
    ) {
        self.publish(MonitorEvent::StreamProgress {
            request_id: request_id.into(),
            bytes,
            chunks,
            input_tokens,
            output_tokens,
        });
    }

    pub fn usage_updated(
        &self,
        request_id: impl Into<String>,
        input_tokens: Option<u64>,
        output_tokens: Option<u64>,
    ) {
        self.publish(MonitorEvent::UsageUpdated {
            request_id: request_id.into(),
            input_tokens,
            output_tokens,
        });
    }

    pub fn request_completed(
        &self,
        request_id: impl Into<String>,
        http_status: u16,
        input_tokens: Option<u64>,
        output_tokens: Option<u64>,
    ) {
        self.publish(MonitorEvent::RequestCompleted {
            request_id: request_id.into(),
            http_status,
            input_tokens,
            output_tokens,
        });
    }

    pub fn request_failed(
        &self,
        request_id: impl Into<String>,
        http_status: Option<u16>,
        error: impl Into<String>,
    ) {
        self.publish(MonitorEvent::RequestFailed {
            request_id: request_id.into(),
            http_status,
            error: error.into(),
        });
    }
}

impl MonitorStore {
    fn apply(&mut self, event: MonitorEvent) {
        match event {
            MonitorEvent::RequestStarted {
                request_id,
                session_id,
                session_seq,
                endpoint,
            } => {
                self.active.insert(
                    request_id.clone(),
                    ActiveRequest {
                        request_id,
                        session_id,
                        session_seq,
                        provider: None,
                        model: None,
                        endpoint,
                        started_at: SystemTime::now(),
                        started_instant: Instant::now(),
                        status: RequestStatus::Started,
                        streamed_bytes: 0,
                        stream_chunks: 0,
                        input_tokens: None,
                        output_tokens: None,
                        error: None,
                        traffic_capture_path: None,
                    },
                );
            }
            MonitorEvent::ProviderSelected {
                request_id,
                provider,
                model,
            } => {
                if let Some(active) = self.active.get_mut(&request_id) {
                    active.provider = Some(provider);
                    active.model = Some(model);
                    active.status = RequestStatus::ProviderSelected;
                }
            }
            MonitorEvent::UpstreamStarted { request_id } => {
                if let Some(active) = self.active.get_mut(&request_id) {
                    active.status = RequestStatus::Upstream;
                }
            }
            MonitorEvent::TrafficCapturePath { request_id, path } => {
                if let Some(active) = self.active.get_mut(&request_id) {
                    active.traffic_capture_path = Some(path);
                }
            }
            MonitorEvent::StreamProgress {
                request_id,
                bytes,
                chunks,
                input_tokens,
                output_tokens,
            } => {
                if let Some(active) = self.active.get_mut(&request_id) {
                    active.status = RequestStatus::Streaming;
                    active.streamed_bytes = active.streamed_bytes.saturating_add(bytes);
                    active.stream_chunks = active.stream_chunks.saturating_add(chunks);
                    active.input_tokens = input_tokens.or(active.input_tokens);
                    active.output_tokens = output_tokens.or(active.output_tokens);
                }
            }
            MonitorEvent::UsageUpdated {
                request_id,
                input_tokens,
                output_tokens,
            } => {
                if let Some(active) = self.active.get_mut(&request_id) {
                    active.input_tokens = input_tokens.or(active.input_tokens);
                    active.output_tokens = output_tokens.or(active.output_tokens);
                }
            }
            MonitorEvent::RequestCompleted {
                request_id,
                http_status,
                input_tokens,
                output_tokens,
            } => {
                self.finish(
                    &request_id,
                    RequestStatus::Completed,
                    Some(http_status),
                    input_tokens,
                    output_tokens,
                    None,
                );
            }
            MonitorEvent::RequestFailed {
                request_id,
                http_status,
                error,
            } => {
                self.finish(
                    &request_id,
                    RequestStatus::Failed,
                    http_status,
                    None,
                    None,
                    Some(error),
                );
            }
        }
    }

    fn finish(
        &mut self,
        request_id: &str,
        status: RequestStatus,
        http_status: Option<u16>,
        input_tokens: Option<u64>,
        output_tokens: Option<u64>,
        error: Option<String>,
    ) {
        let active = self
            .active
            .remove(request_id)
            .unwrap_or_else(|| ActiveRequest {
                request_id: request_id.to_string(),
                session_id: None,
                session_seq: None,
                provider: None,
                model: None,
                endpoint: EndpointKind::Messages,
                started_at: SystemTime::now(),
                started_instant: Instant::now(),
                status: RequestStatus::Started,
                streamed_bytes: 0,
                stream_chunks: 0,
                input_tokens: None,
                output_tokens: None,
                error: None,
                traffic_capture_path: None,
            });
        let completed = CompletedRequest {
            request_id: active.request_id,
            session_id: active.session_id,
            session_seq: active.session_seq,
            provider: active.provider,
            model: active.model,
            endpoint: active.endpoint,
            started_at: active.started_at,
            finished_at: SystemTime::now(),
            status,
            http_status,
            latency: active.started_instant.elapsed(),
            streamed_bytes: active.streamed_bytes,
            stream_chunks: active.stream_chunks,
            input_tokens: input_tokens.or(active.input_tokens),
            output_tokens: output_tokens.or(active.output_tokens),
            error: error.or(active.error),
            traffic_capture_path: active.traffic_capture_path,
        };
        self.recent.push_front(completed);
        while self.recent.len() > self.recent_limit {
            self.recent.pop_back();
        }
    }

    fn snapshot(&self) -> MonitorState {
        let mut active: Vec<_> = self.active.values().cloned().collect();
        active.sort_by_key(|request| request.started_at);
        MonitorState {
            started_at: self.started_at,
            active,
            recent: self.recent.iter().cloned().collect(),
        }
    }
}

pub fn throughput(
    output_tokens: Option<u64>,
    streamed_bytes: u64,
    stream_chunks: u64,
    elapsed: Duration,
) -> Throughput {
    let secs = elapsed.as_secs_f64();
    if secs <= 0.0 {
        return Throughput::None;
    }
    if let Some(tokens) = output_tokens.filter(|tokens| *tokens > 0) {
        return Throughput::TokensPerSecond(tokens as f64 / secs);
    }
    if streamed_bytes > 0 {
        return Throughput::BytesPerSecond(streamed_bytes as f64 / secs);
    }
    if stream_chunks > 0 {
        return Throughput::EventsPerSecond(stream_chunks as f64 / secs);
    }
    Throughput::None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn started_requests_appear_active() {
        let monitor = MonitorHandle::new(10);
        monitor.request_started(
            "r1",
            Some("s1".to_string()),
            Some(3),
            EndpointKind::Messages,
        );
        let state = monitor.snapshot();
        assert_eq!(state.active.len(), 1);
        assert_eq!(state.active[0].request_id, "r1");
        assert_eq!(state.active[0].session_id.as_deref(), Some("s1"));
        assert_eq!(state.active[0].session_seq, Some(3));
    }

    #[test]
    fn completed_requests_leave_active_and_enter_recent() {
        let monitor = MonitorHandle::new(10);
        monitor.request_started("r1", None, None, EndpointKind::Messages);
        monitor.provider_selected("r1", "codex", "gpt-5.5");
        monitor.request_completed("r1", 200, Some(10), Some(20));
        let state = monitor.snapshot();
        assert!(state.active.is_empty());
        assert_eq!(state.recent.len(), 1);
        assert_eq!(state.recent[0].provider.as_deref(), Some("codex"));
        assert_eq!(state.recent[0].output_tokens, Some(20));
    }

    #[test]
    fn failed_requests_preserve_error_summary() {
        let monitor = MonitorHandle::new(10);
        monitor.request_started("r1", None, None, EndpointKind::Messages);
        monitor.request_failed("r1", Some(400), "Unknown model");
        let state = monitor.snapshot();
        assert_eq!(state.recent[0].status, RequestStatus::Failed);
        assert_eq!(state.recent[0].http_status, Some(400));
        assert_eq!(state.recent[0].error.as_deref(), Some("Unknown model"));
    }

    #[test]
    fn bounded_recent_history_drops_oldest() {
        let monitor = MonitorHandle::new(2);
        for id in ["r1", "r2", "r3"] {
            monitor.request_started(id, None, None, EndpointKind::Messages);
            monitor.request_completed(id, 200, None, None);
        }
        let state = monitor.snapshot();
        let ids: Vec<_> = state
            .recent
            .iter()
            .map(|request| request.request_id.as_str())
            .collect();
        assert_eq!(ids, vec!["r3", "r2"]);
    }

    #[test]
    fn throughput_selects_best_available_signal() {
        let elapsed = Duration::from_secs(2);
        assert_eq!(
            throughput(Some(84), 1024, 10, elapsed),
            Throughput::TokensPerSecond(42.0)
        );
        assert_eq!(
            throughput(None, 2048, 10, elapsed),
            Throughput::BytesPerSecond(1024.0)
        );
        assert_eq!(
            throughput(None, 0, 36, elapsed),
            Throughput::EventsPerSecond(18.0)
        );
    }
}

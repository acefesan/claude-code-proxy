use crate::{
    registry::Registry,
    routing::{RouteProvider, RouteTarget, RoutingCoordinator, RoutingError, SessionRoute},
    scanner::{ObservedRoute, ScanConfig, ScanResult, scan_sessions},
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
use std::{future::Future, sync::Arc};
use tokio::net::TcpListener;

const INDEX: &str = include_str!("../assets/dashboard/index.html");
const APP_JS: &str = include_str!("../assets/dashboard/app.js");
const STYLES: &str = include_str!("../assets/dashboard/styles.css");
const SESSION_COOKIE: &str = "ccp_admin";

#[derive(Clone)]
pub struct DashboardConfig {
    pub scan: ScanConfig,
    pub routing: RoutingCoordinator,
    pub admin_secret: Option<String>,
    pub allowed_origin: String,
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

#[derive(Debug, Serialize)]
struct SessionView {
    #[serde(flatten)]
    observed: crate::scanner::ScannedSession,
    routing: Option<SessionRoute>,
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
    Json(json!({"ok": true}))
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
    let cookie =
        format!("{SESSION_COOKIE}={expected}; HttpOnly; SameSite=Strict; Path=/; Max-Age=3600");
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
    for observed in result.sessions {
        let routing = if let Some(session_id) = observed.session_id.as_deref() {
            let initial = initial_target(&observed.route);
            state.config.routing.ensure_session(session_id, initial)?;
            Some(state.config.routing.observe_host(
                session_id,
                observed.status == "idle",
                result.scanned_at_ms,
            )?)
        } else {
            None
        };
        views.push(SessionView { observed, routing });
    }
    Ok(SessionsView {
        scanned_at_ms: result.scanned_at_ms,
        counts: result.counts,
        sessions: views,
        warnings: result.warnings,
    })
}

fn initial_target(route: &ObservedRoute) -> RouteTarget {
    match route {
        ObservedRoute::Anthropic => RouteTarget {
            provider: RouteProvider::Anthropic,
            model: "claude-fable-5".to_owned(),
        },
        ObservedRoute::Codex | ObservedRoute::Unknown => RouteTarget {
            provider: RouteProvider::Codex,
            model: "gpt-5.6-sol".to_owned(),
        },
    }
}

async fn providers(State(state): State<DashboardState>) -> impl IntoResponse {
    let grouped = state.registry.grouped_models();
    Json(json!({"providers":[
        {"id":"anthropic","available":true,"models":["claude-fable-5","claude-opus-4-8","claude-sonnet-5","claude-haiku-4-5"]},
        {"id":"codex","available":true,"models":grouped.get("codex").cloned().unwrap_or_default()}
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
        Ok(route) => Json(route).into_response(),
        Err(RoutingError::StaleRevision { .. }) => error(StatusCode::CONFLICT, "stale_revision"),
        Err(RoutingError::UnknownSession(_)) => error(StatusCode::NOT_FOUND, "unknown_session"),
        Err(other) => error(StatusCode::BAD_REQUEST, &other.to_string()),
    }
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
            .supported_models_for("codex")
            .iter()
            .any(|candidate| candidate == model),
    }
}

fn same_origin(state: &DashboardState, headers: &HeaderMap) -> bool {
    headers
        .get(header::ORIGIN)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|origin| origin == state.config.allowed_origin)
}

fn authenticated(state: &DashboardState, headers: &HeaderMap) -> bool {
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
                admin_secret: Some("test-secret".to_owned()),
                allowed_origin: "http://127.0.0.1:3036".to_owned(),
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

    #[test]
    fn dashboard_has_accessible_provider_identity_without_route_borders() {
        assert!(APP_JS.contains("aria-label=\"Anthropic\""));
        assert!(APP_JS.contains("aria-label=\"OpenAI\""));
        assert!(APP_JS.contains("aria-label=\"Unknown provider\""));
        assert!(!STYLES.contains("border-left"));
    }
}

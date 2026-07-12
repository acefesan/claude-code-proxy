use crate::{
    registry::Registry,
    scanner::{ScanConfig, scan_sessions},
};
use axum::{
    Json, Router,
    http::{StatusCode, header},
    response::{IntoResponse, Response},
    routing::get,
};
use serde_json::json;
use std::{future::Future, sync::Arc};
use tokio::net::TcpListener;

const INDEX: &str = include_str!("../assets/dashboard/index.html");
const APP_JS: &str = include_str!("../assets/dashboard/app.js");
const STYLES: &str = include_str!("../assets/dashboard/styles.css");

#[derive(Clone)]
struct DashboardState {
    scan: ScanConfig,
    registry: Arc<Registry>,
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
    scan: ScanConfig,
    shutdown: impl Future<Output = ()> + Send + 'static,
) -> anyhow::Result<()> {
    axum::serve(listener, app(registry, scan))
        .with_graceful_shutdown(shutdown)
        .await?;
    Ok(())
}

pub fn app(registry: Arc<Registry>, scan: ScanConfig) -> Router {
    Router::new()
        .route("/", get(index))
        .route("/app.js", get(app_js))
        .route("/styles.css", get(styles))
        .route("/health", get(health))
        .route("/api/v1/sessions", get(sessions))
        .route("/api/v1/providers", get(providers))
        .fallback(not_found)
        .with_state(DashboardState { scan, registry })
}

async fn health() -> Json<serde_json::Value> {
    Json(json!({"ok": true}))
}

async fn sessions(
    axum::extract::State(state): axum::extract::State<DashboardState>,
) -> impl IntoResponse {
    Json(scan_sessions(&state.scan))
}

async fn providers(
    axum::extract::State(state): axum::extract::State<DashboardState>,
) -> impl IntoResponse {
    let grouped = state.registry.grouped_models();
    Json(json!({
        "providers": [
            {"id": "anthropic", "available": false, "reason": "subscription_auth_probe_required", "models": []},
            {"id": "codex", "available": true, "models": grouped.get("codex").cloned().unwrap_or_default()}
        ]
    }))
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
            (header::X_CONTENT_TYPE_OPTIONS, "nosniff"),
            (header::REFERRER_POLICY, "no-referrer"),
        ],
        body,
    )
        .into_response()
}

async fn not_found() -> impl IntoResponse {
    (StatusCode::NOT_FOUND, Json(json!({"error": "not found"})))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{body::Body, http::Request};
    use tempfile::TempDir;
    use tower::ServiceExt;

    fn fixture() -> (TempDir, ScanConfig) {
        let temp = TempDir::new().unwrap();
        let scan = ScanConfig {
            claude_dir: temp.path().join(".claude"),
            proc_dir: temp.path().join("proc"),
        };
        std::fs::create_dir_all(scan.claude_dir.join("sessions")).unwrap();
        std::fs::create_dir_all(&scan.proc_dir).unwrap();
        (temp, scan)
    }

    #[tokio::test]
    async fn dashboard_serves_embedded_assets_and_api_without_proxy_routes() {
        let (_temp, scan) = fixture();
        let app = app(Arc::new(Registry::with_default_alias()), scan);
        for (path, content_type) in [
            ("/", "text/html; charset=utf-8"),
            ("/app.js", "text/javascript; charset=utf-8"),
            ("/styles.css", "text/css; charset=utf-8"),
            ("/api/v1/sessions", "application/json"),
        ] {
            let response = app
                .clone()
                .oneshot(Request::builder().uri(path).body(Body::empty()).unwrap())
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::OK);
            assert!(
                response
                    .headers()
                    .get(header::CONTENT_TYPE)
                    .unwrap()
                    .to_str()
                    .unwrap()
                    .starts_with(content_type)
            );
        }
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/v1/messages")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[test]
    fn dashboard_has_accessible_provider_identity_without_route_borders() {
        assert!(APP_JS.contains("aria-label=\"Anthropic\""));
        assert!(APP_JS.contains("aria-label=\"OpenAI\""));
        assert!(APP_JS.contains("aria-label=\"Unknown provider\""));
        assert!(!STYLES.contains("border-left"));
    }
}

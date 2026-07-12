use anyhow::{Context, Result, bail};
use axum::{
    Router,
    body::Body,
    extract::State,
    http::{HeaderMap, Request, StatusCode, Uri, header},
    response::Response,
    routing::any,
};
use futures_util::StreamExt;
use reqwest::Client;
use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::Arc,
    time::Duration,
};
use tokio::{
    net::TcpListener,
    sync::{Mutex, oneshot},
};

const ANTHROPIC_ORIGIN: &str = "https://api.anthropic.com";
const DEFAULT_TIMEOUT_SECONDS: u64 = 120;

#[derive(Debug, Clone)]
pub struct ProbeConfig {
    pub port: u16,
    pub timeout: Duration,
    upstream_origin: String,
    reject_shadowing_credentials: bool,
}

impl ProbeConfig {
    pub fn production(port: u16) -> Self {
        Self {
            port,
            timeout: Duration::from_secs(DEFAULT_TIMEOUT_SECONDS),
            upstream_origin: ANTHROPIC_ORIGIN.to_owned(),
            reject_shadowing_credentials: true,
        }
    }

    #[cfg(test)]
    fn with_upstream(port: u16, upstream_origin: String) -> Self {
        Self {
            port,
            timeout: Duration::from_secs(5),
            upstream_origin,
            reject_shadowing_credentials: false,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct CredentialSummary {
    authorization_scheme: Option<String>,
    has_api_key: bool,
}

impl CredentialSummary {
    fn from_headers(headers: &HeaderMap) -> Self {
        let authorization_scheme = headers
            .get(header::AUTHORIZATION)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.split_whitespace().next())
            .filter(|scheme| !scheme.is_empty())
            .map(str::to_owned);
        Self {
            authorization_scheme,
            has_api_key: headers.contains_key("x-api-key"),
        }
    }

    fn has_credentials(&self) -> bool {
        self.authorization_scheme.is_some() || self.has_api_key
    }
}

#[derive(Debug)]
struct ProbeResult {
    method: String,
    path: String,
    credentials: CredentialSummary,
    upstream_status: StatusCode,
    stream_started: bool,
}

#[derive(Clone)]
struct ProbeState {
    client: Client,
    upstream_origin: String,
    result_tx: Arc<Mutex<Option<oneshot::Sender<Result<ProbeResult, String>>>>>,
}

pub async fn run(config: ProbeConfig) -> Result<()> {
    if config.reject_shadowing_credentials {
        reject_shadowing_credentials()?;
    }

    let listener = TcpListener::bind(SocketAddr::new(
        IpAddr::V4(Ipv4Addr::LOCALHOST),
        config.port,
    ))
    .await
    .with_context(|| {
        format!(
            "failed to bind Anthropic auth probe on 127.0.0.1:{}",
            config.port
        )
    })?;
    let address = listener.local_addr()?;
    let (result_tx, result_rx) = oneshot::channel();
    let state = ProbeState {
        client: Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .build()?,
        upstream_origin: config.upstream_origin,
        result_tx: Arc::new(Mutex::new(Some(result_tx))),
    };
    let app = Router::new().fallback(any(handle_probe)).with_state(state);
    let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();
    let server = tokio::spawn(async move {
        axum::serve(listener, app)
            .with_graceful_shutdown(async move {
                let _ = shutdown_rx.await;
            })
            .await
    });

    println!("Anthropic subscription-auth probe listening on http://{address}");
    println!("Run one disposable Claude Code request with:");
    println!(
        "  env -u ANTHROPIC_API_KEY -u ANTHROPIC_AUTH_TOKEN ANTHROPIC_BASE_URL=http://{address} claude -p 'Reply with OK only'"
    );
    println!("No credential values or message bodies will be printed or stored.");

    let result = tokio::time::timeout(config.timeout, result_rx)
        .await
        .context("probe timed out before receiving a Claude Code request")?
        .context("probe request handler stopped before reporting a result")?
        .map_err(anyhow::Error::msg);
    let _ = shutdown_tx.send(());
    server.await.context("probe server task failed")??;
    let result = result?;

    println!("method: {}", result.method);
    println!("path: {}", result.path);
    println!(
        "authorization: {}",
        result
            .credentials
            .authorization_scheme
            .as_deref()
            .unwrap_or("absent")
    );
    println!(
        "x-api-key: {}",
        if result.credentials.has_api_key {
            "present"
        } else {
            "absent"
        }
    );
    println!("upstream-status: {}", result.upstream_status.as_u16());
    println!("stream-started: {}", result.stream_started);

    if !result.credentials.has_credentials() {
        bail!("subscription_auth_unsupported: Claude Code sent no credential header");
    }
    if !result.upstream_status.is_success() || !result.stream_started {
        bail!(
            "subscription_auth_unsupported: Anthropic did not accept and begin the response stream"
        );
    }
    println!("subscription-auth: supported");
    Ok(())
}

fn reject_shadowing_credentials() -> Result<()> {
    let shadowing = ["ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN"]
        .into_iter()
        .filter(|name| std::env::var_os(name).is_some())
        .collect::<Vec<_>>();
    if !shadowing.is_empty() {
        bail!(
            "unset {} before running the probe; even empty values can shadow subscription authentication",
            shadowing.join(" and ")
        );
    }
    Ok(())
}

async fn handle_probe(State(state): State<ProbeState>, request: Request<Body>) -> Response {
    let method = request.method().clone();
    let uri = request.uri().clone();
    let is_messages_request = method == http::Method::POST && uri.path() == "/v1/messages";
    let credentials = CredentialSummary::from_headers(request.headers());
    let result = forward_request(&state, request).await;
    if is_messages_request {
        let report = match &result {
            Ok((response, stream_started)) => Ok(ProbeResult {
                method: method.to_string(),
                path: path_and_query(&uri),
                credentials,
                upstream_status: response.status(),
                stream_started: *stream_started,
            }),
            Err(error) => Err(error.to_string()),
        };
        if let Some(tx) = state.result_tx.lock().await.take() {
            let _ = tx.send(report);
        }
    }
    match result {
        Ok((response, _)) => response,
        Err(_) => Response::builder()
            .status(StatusCode::BAD_GATEWAY)
            .body(Body::empty())
            .expect("valid probe error response"),
    }
}

async fn forward_request(state: &ProbeState, request: Request<Body>) -> Result<(Response, bool)> {
    let (parts, body) = request.into_parts();
    let target = format!("{}{}", state.upstream_origin, path_and_query(&parts.uri));
    let mut upstream = state.client.request(parts.method, target);
    for (name, value) in &parts.headers {
        if !is_hop_by_hop(name.as_str()) && name != header::HOST && name != header::CONTENT_LENGTH {
            upstream = upstream.header(name, value);
        }
    }
    let response = upstream
        .body(reqwest::Body::wrap_stream(body.into_data_stream()))
        .send()
        .await?;
    let status = response.status();
    let headers = response.headers().clone();
    let mut stream = response.bytes_stream();
    let first = stream.next().await.transpose()?;
    let stream_started = first.is_some();
    let output = futures_util::stream::iter(first.map(Ok::<_, reqwest::Error>)).chain(stream);
    let mut builder = Response::builder().status(status);
    for (name, value) in &headers {
        if !is_hop_by_hop(name.as_str()) && name != header::CONTENT_LENGTH {
            builder = builder.header(name, value);
        }
    }
    Ok((builder.body(Body::from_stream(output))?, stream_started))
}

fn path_and_query(uri: &Uri) -> String {
    uri.path_and_query()
        .map(|value| value.as_str())
        .unwrap_or("/")
        .to_owned()
}

fn is_hop_by_hop(name: &str) -> bool {
    matches!(
        name.to_ascii_lowercase().as_str(),
        "connection"
            | "keep-alive"
            | "proxy-authenticate"
            | "proxy-authorization"
            | "te"
            | "trailer"
            | "transfer-encoding"
            | "upgrade"
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{body::Bytes, response::IntoResponse};

    #[test]
    fn credential_summary_never_contains_values() {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::AUTHORIZATION,
            "Bearer super-secret".parse().unwrap(),
        );
        headers.insert("x-api-key", "another-secret".parse().unwrap());
        let summary = CredentialSummary::from_headers(&headers);
        assert_eq!(summary.authorization_scheme.as_deref(), Some("Bearer"));
        assert!(summary.has_api_key);
        assert!(!format!("{summary:?}").contains("super-secret"));
        assert!(!format!("{summary:?}").contains("another-secret"));
    }

    #[tokio::test]
    async fn probe_forwards_credentials_and_body_without_printing_values() {
        async fn upstream(headers: HeaderMap, body: Bytes) -> impl IntoResponse {
            assert_eq!(headers.get(header::AUTHORIZATION).unwrap(), "Bearer hidden");
            assert_eq!(body, Bytes::from_static(b"{\"model\":\"claude-test\"}"));
            (
                StatusCode::OK,
                [(header::CONTENT_TYPE, "text/event-stream")],
                "event: message_start\n\ndata: {}\n\n",
            )
        }
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream_address = listener.local_addr().unwrap();
        let upstream_task = tokio::spawn(async move {
            axum::serve(listener, Router::new().fallback(any(upstream)))
                .await
                .unwrap();
        });
        let probe_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let probe_port = probe_listener.local_addr().unwrap().port();
        drop(probe_listener);
        let config = ProbeConfig::with_upstream(probe_port, format!("http://{upstream_address}"));
        let probe_task = tokio::spawn(run(config));
        tokio::time::sleep(Duration::from_millis(50)).await;
        let response = Client::new()
            .post(format!(
                "http://127.0.0.1:{probe_port}/v1/messages?beta=true"
            ))
            .header(header::AUTHORIZATION, "Bearer hidden")
            .body("{\"model\":\"claude-test\"}")
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert!(probe_task.await.unwrap().is_ok());
        upstream_task.abort();
    }
}

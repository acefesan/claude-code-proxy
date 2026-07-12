use anyhow::{Context, Result};
use axum::{
    body::Body,
    http::{Request, Response, header},
};
use reqwest::Client;

const DEFAULT_ORIGIN: &str = "https://api.anthropic.com";

#[derive(Clone)]
pub struct AnthropicPassthrough {
    client: Client,
    origin: String,
}

impl AnthropicPassthrough {
    pub fn production() -> Result<Self> {
        Self::new(DEFAULT_ORIGIN.to_owned())
    }

    #[doc(hidden)]
    pub fn with_origin(origin: String) -> Result<Self> {
        Self::new(origin)
    }

    fn new(origin: String) -> Result<Self> {
        Ok(Self {
            client: Client::builder()
                .redirect(reqwest::redirect::Policy::none())
                .build()?,
            origin,
        })
    }

    pub async fn forward(&self, request: Request<Body>) -> Result<Response<Body>> {
        let (parts, body) = request.into_parts();
        let path = parts
            .uri
            .path_and_query()
            .map(|value| value.as_str())
            .unwrap_or("/");
        let target = format!("{}{path}", self.origin);
        let mut upstream = self.client.request(parts.method, target);
        for (name, value) in &parts.headers {
            if !hop_by_hop(name.as_str()) && name != header::HOST && name != header::CONTENT_LENGTH
            {
                upstream = upstream.header(name, value);
            }
        }
        let response = upstream
            .body(reqwest::Body::wrap_stream(body.into_data_stream()))
            .send()
            .await
            .context("native Anthropic request failed")?;
        let status = response.status();
        let headers = response.headers().clone();
        let stream = response.bytes_stream();
        let mut builder = Response::builder().status(status);
        for (name, value) in &headers {
            if !hop_by_hop(name.as_str()) && name != header::CONTENT_LENGTH {
                builder = builder.header(name, value);
            }
        }
        Ok(builder.body(Body::from_stream(stream))?)
    }
}

fn hop_by_hop(name: &str) -> bool {
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
    use axum::{Router, body::Bytes, http::StatusCode, response::IntoResponse, routing::post};
    use tokio::net::TcpListener;

    #[tokio::test]
    async fn preserves_body_auth_path_status_and_stream() {
        async fn upstream(headers: axum::http::HeaderMap, body: Bytes) -> impl IntoResponse {
            assert_eq!(
                headers.get(header::AUTHORIZATION).unwrap(),
                "Bearer private"
            );
            assert_eq!(headers.get("anthropic-beta").unwrap(), "oauth-2025-04-20");
            assert!(headers.get("x-ccp-route").is_none());
            assert_eq!(
                body,
                Bytes::from_static(b"{ \"model\": \"claude-fable-5\" }")
            );
            (
                StatusCode::ACCEPTED,
                [(header::CONTENT_TYPE, "text/event-stream")],
                "event: message_start\n\ndata: {}\n\n",
            )
        }
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            axum::serve(
                listener,
                Router::new().route("/v1/messages", post(upstream)),
            )
            .await
            .unwrap();
        });
        let passthrough = AnthropicPassthrough::new(format!("http://{address}")).unwrap();
        let request = Request::builder()
            .method("POST")
            .uri("/v1/messages?beta=true")
            .header(header::AUTHORIZATION, "Bearer private")
            .header("anthropic-beta", "oauth-2025-04-20")
            .body(Body::from("{ \"model\": \"claude-fable-5\" }"))
            .unwrap();
        let response = passthrough.forward(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::ACCEPTED);
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        assert_eq!(
            bytes,
            Bytes::from_static(b"event: message_start\n\ndata: {}\n\n")
        );
        server.abort();
    }

    #[tokio::test]
    async fn does_not_follow_redirects() {
        async fn redirect() -> impl IntoResponse {
            (
                StatusCode::TEMPORARY_REDIRECT,
                [(header::LOCATION, "https://example.com/")],
            )
        }
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            axum::serve(
                listener,
                Router::new().route("/v1/messages", post(redirect)),
            )
            .await
            .unwrap();
        });
        let passthrough = AnthropicPassthrough::new(format!("http://{address}")).unwrap();
        let response = passthrough
            .forward(
                Request::builder()
                    .method("POST")
                    .uri("/v1/messages")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::TEMPORARY_REDIRECT);
        server.abort();
    }
}

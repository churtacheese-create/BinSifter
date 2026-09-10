//! Embedded frontend assets.
//!
//! In a release build the contents of `ingot/frontend/` are baked into the
//! binary; in a debug build `rust-embed` reads them from disk each request,
//! so editing the UI needs no rebuild.

use axum::body::Body;
use axum::extract::Path;
use axum::http::{header, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use rust_embed::Embed;

#[derive(Embed)]
#[folder = "$CARGO_MANIFEST_DIR/../../frontend"]
struct Frontend;

fn serve(path: &str) -> Response {
    let path = if path.is_empty() { "index.html" } else { path };
    match Frontend::get(path) {
        Some(content) => {
            let mime = mime_guess::from_path(path).first_or_octet_stream();
            (
                [(
                    header::CONTENT_TYPE,
                    HeaderValue::from_str(mime.as_ref()).unwrap(),
                )],
                Body::from(content.data.into_owned()),
            )
                .into_response()
        }
        None => (StatusCode::NOT_FOUND, "not found").into_response(),
    }
}

pub async fn index() -> Response {
    serve("index.html")
}

pub async fn asset(Path(path): Path<String>) -> Response {
    serve(path.trim_start_matches('/'))
}

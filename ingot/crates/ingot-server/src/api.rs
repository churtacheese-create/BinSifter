//! HTTP API: config, scan control, progress + log SSE streams, reports.
//!
//! Bound to loopback only, single user, no auth - it's a local analyst tool
//! (see `docs/ingot.md`). Exactly one scan runs at a time; starting a second
//! while one is in flight is a `409`.

use std::convert::Infallible;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, RwLock};

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::sse::{Event, KeepAlive, Sse};
use axum::response::{IntoResponse, Response};
use axum::Json;
use futures_util::stream::Stream;
use serde::{Deserialize, Serialize};
use serde_json::json;
use tokio::sync::broadcast;
use tokio_stream::wrappers::BroadcastStream;
use tokio_stream::StreamExt;

use ingot_core::config::{self, IngotConfig, SettingsFields};
use ingot_core::engine::{self, Progress};
use ingot_core::report::ReportPaths;
use ingot_core::{disposition, FileRecord, PRODUCT_NAME, VERSION};

#[derive(Clone)]
pub struct AppState {
    inner: Arc<Inner>,
}

struct Inner {
    config: RwLock<IngotConfig>,
    scan: RwLock<Option<Arc<ScanSession>>>,
    log_tx: broadcast::Sender<String>,
}

struct ScanSession {
    id: String,
    started: String,
    total: AtomicUsize,
    done: AtomicUsize,
    finished: AtomicBool,
    error: Mutex<Option<String>>,
    records: Mutex<Vec<FileRecord>>,
    report_paths: Mutex<Option<ReportPaths>>,
    events: broadcast::Sender<String>,
}

impl ScanSession {
    fn running(&self) -> bool {
        !self.finished.load(Ordering::SeqCst)
    }

    fn snapshot(&self) -> serde_json::Value {
        json!({
            "id": self.id,
            "started": self.started,
            "total": self.total.load(Ordering::SeqCst),
            "done": self.done.load(Ordering::SeqCst),
            "finished": self.finished.load(Ordering::SeqCst),
            "error": *self.error.lock().unwrap(),
            "reportPaths": *self.report_paths.lock().unwrap(),
            "records": *self.records.lock().unwrap(),
        })
    }
}

impl AppState {
    pub fn new(config: IngotConfig, log_tx: broadcast::Sender<String>) -> Self {
        AppState {
            inner: Arc::new(Inner {
                config: RwLock::new(config),
                scan: RwLock::new(None),
                log_tx,
            }),
        }
    }
}

// ------------------------------------------------------------------ health

pub async fn health() -> Json<serde_json::Value> {
    Json(json!({ "name": PRODUCT_NAME, "version": VERSION }))
}

// ------------------------------------------------------------------ config

pub async fn get_config(State(state): State<AppState>) -> Json<IngotConfig> {
    Json(state.inner.config.read().unwrap().clone())
}

pub async fn put_config(
    State(state): State<AppState>,
    Json(fields): Json<SettingsFields>,
) -> Response {
    let mut config = state.inner.config.write().unwrap();
    config.apply_settings(fields);
    if let Err(e) = config::save_settings_cache(&config) {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("could not persist settings: {e}"),
        )
            .into_response();
    }
    Json(config.clone()).into_response()
}

// ------------------------------------------------------------------- tools

/// capa / FLOSS binary status. `available` means Ingot found (or downloaded)
/// the standalone binary; `path` is where.
pub async fn get_tools(State(state): State<AppState>) -> Json<serde_json::Value> {
    let config = state.inner.config.read().unwrap();
    Json(json!({
        "capa":  { "available": !config.capa_exe.is_empty(),  "path": config.capa_exe },
        "floss": { "available": !config.floss_exe.is_empty(), "path": config.floss_exe },
    }))
}

/// Download the standalone capa or FLOSS binary into the per-user tools
/// directory. Runs in the background; watch the Logs tab for progress.
pub async fn install_tool(State(state): State<AppState>, Path(tool): Path<String>) -> Response {
    let installer: fn() -> anyhow::Result<std::path::PathBuf> = match tool.as_str() {
        "capa" => ingot_core::tool_bootstrap::install_capa,
        "floss" => ingot_core::tool_bootstrap::install_floss,
        _ => {
            return (
                StatusCode::BAD_REQUEST,
                "unknown tool (want 'capa' or 'floss')",
            )
                .into_response()
        }
    };

    let label = tool.clone();
    tokio::task::spawn_blocking(move || match installer() {
        Ok(path) => {
            tracing::info!("{label} installed: {}", path.display());
            state.inner.config.write().unwrap().refresh_tool_paths();
        }
        Err(e) => tracing::error!("{label} install failed: {e:#}"),
    });

    (StatusCode::ACCEPTED, Json(json!({ "started": tool }))).into_response()
}

// -------------------------------------------------------------------- scan

pub async fn start_scan(State(state): State<AppState>) -> Response {
    {
        let current = state.inner.scan.read().unwrap();
        if let Some(session) = current.as_ref() {
            if session.running() {
                return (StatusCode::CONFLICT, "a scan is already running").into_response();
            }
        }
    }

    let config = state.inner.config.read().unwrap().clone();
    if config.src_dir.trim().is_empty() {
        return (StatusCode::BAD_REQUEST, "source directory is not set").into_response();
    }
    if !PathBuf::from(&config.src_dir).is_dir() {
        return (
            StatusCode::BAD_REQUEST,
            format!("source directory does not exist: {}", config.src_dir),
        )
            .into_response();
    }

    let (events_tx, _) = broadcast::channel::<String>(1024);
    let session = Arc::new(ScanSession {
        id: uuid::Uuid::new_v4().to_string(),
        started: chrono::Local::now().to_rfc3339(),
        total: AtomicUsize::new(0),
        done: AtomicUsize::new(0),
        finished: AtomicBool::new(false),
        error: Mutex::new(None),
        records: Mutex::new(Vec::new()),
        report_paths: Mutex::new(None),
        events: events_tx,
    });

    *state.inner.scan.write().unwrap() = Some(session.clone());
    let id = session.id.clone();

    tokio::task::spawn_blocking(move || {
        let session_for_cb = session.clone();
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            engine::scan_directory(&config, |p: Progress| {
                session_for_cb.total.store(p.total, Ordering::SeqCst);
                session_for_cb.done.store(p.done, Ordering::SeqCst);
                let payload = json!({
                    "kind": "progress",
                    "done": p.done,
                    "total": p.total,
                    "record": p.record,
                });
                let _ = session_for_cb.events.send(payload.to_string());
            })
        }));

        match result {
            Ok(scan_result) => {
                *session.records.lock().unwrap() = scan_result.records;
                *session.report_paths.lock().unwrap() = scan_result.report_paths;
            }
            Err(_) => {
                *session.error.lock().unwrap() = Some("scan worker panicked".to_string());
            }
        }
        session.finished.store(true, Ordering::SeqCst);
        let done = session.done.load(Ordering::SeqCst);
        let total = session.total.load(Ordering::SeqCst);
        let _ = session.events.send(
            json!({
                "kind": "complete",
                "done": done,
                "total": total,
                "error": *session.error.lock().unwrap(),
                "reportPaths": *session.report_paths.lock().unwrap(),
            })
            .to_string(),
        );
    });

    (StatusCode::ACCEPTED, Json(json!({ "id": id }))).into_response()
}

pub async fn scan_status(State(state): State<AppState>) -> Response {
    match state.inner.scan.read().unwrap().as_ref() {
        Some(session) => Json(session.snapshot()).into_response(),
        None => (StatusCode::NOT_FOUND, "no scan has been run yet").into_response(),
    }
}

pub async fn scan_events(
    State(state): State<AppState>,
) -> Sse<impl Stream<Item = Result<Event, Infallible>>> {
    let rx = match state.inner.scan.read().unwrap().as_ref() {
        Some(session) => session.events.subscribe(),
        None => {
            // no scan yet: hand back a channel that will never emit
            let (tx, rx) = broadcast::channel::<String>(1);
            drop(tx);
            rx
        }
    };

    let stream = BroadcastStream::new(rx).filter_map(|msg| match msg {
        Ok(text) => Some(Ok(Event::default().data(text))),
        Err(_) => None,
    });
    Sse::new(stream).keep_alive(KeepAlive::default())
}

pub async fn scan_report(State(state): State<AppState>, Path(kind): Path<String>) -> Response {
    let path = {
        let guard = state.inner.scan.read().unwrap();
        let Some(session) = guard.as_ref() else {
            return (StatusCode::NOT_FOUND, "no scan has been run yet").into_response();
        };
        let paths = session.report_paths.lock().unwrap();
        let Some(paths) = paths.as_ref() else {
            return (StatusCode::NOT_FOUND, "no reports for this scan").into_response();
        };
        match kind.as_str() {
            "full" => paths.full.clone(),
            "suspicious" => paths.suspicious.clone(),
            "yara" => paths.yara_matches.clone(),
            "capa" => paths.capa_compatible.clone(),
            _ => return (StatusCode::BAD_REQUEST, "unknown report kind").into_response(),
        }
    };

    match tokio::fs::read(&path).await {
        Ok(bytes) => {
            let filename = std::path::Path::new(&path)
                .file_name()
                .and_then(|s| s.to_str())
                .unwrap_or("report.csv")
                .to_string();
            (
                [
                    (
                        axum::http::header::CONTENT_TYPE,
                        "text/csv; charset=utf-8".to_string(),
                    ),
                    (
                        axum::http::header::CONTENT_DISPOSITION,
                        format!("attachment; filename=\"{filename}\""),
                    ),
                ],
                bytes,
            )
                .into_response()
        }
        Err(e) => (StatusCode::NOT_FOUND, format!("could not read report: {e}")).into_response(),
    }
}

// ------------------------------------------------------------- disposition

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DispositionUpdate {
    sha1: String,
    disposition: String,
}

/// Set one file's triage disposition. Persists it to the report directory's
/// disposition history (keyed by SHA-1, so it survives rescans) and updates
/// any matching rows in the current scan's in-memory results.
pub async fn set_disposition(
    State(state): State<AppState>,
    Json(update): Json<DispositionUpdate>,
) -> Response {
    if !disposition::is_valid_disposition(&update.disposition) {
        return (
            StatusCode::BAD_REQUEST,
            format!("unknown disposition: {}", update.disposition),
        )
            .into_response();
    }
    if update.sha1.trim().is_empty() {
        return (StatusCode::BAD_REQUEST, "sha1 is required").into_response();
    }

    let report_dir = state.inner.config.read().unwrap().report_directory.clone();
    if let Err(e) =
        disposition::save_disposition_entry(&report_dir, &update.sha1, &update.disposition)
    {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("could not persist disposition: {e}"),
        )
            .into_response();
    }

    let mut updated = 0usize;
    if let Some(session) = state.inner.scan.read().unwrap().as_ref() {
        let needle = update.sha1.to_ascii_lowercase();
        for record in session.records.lock().unwrap().iter_mut() {
            if record.sha1.as_deref().map(str::to_ascii_lowercase) == Some(needle.clone()) {
                record.disposition = update.disposition.clone();
                updated += 1;
            }
        }
    }

    Json(json!({ "ok": true, "rowsUpdated": updated })).into_response()
}

// ----------------------------------------------------------------- reports

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ReportFile {
    name: String,
    size: u64,
    modified: String,
}

pub async fn list_reports(State(state): State<AppState>) -> Json<Vec<ReportFile>> {
    let dir = state.inner.config.read().unwrap().report_directory.clone();
    let mut out = Vec::new();
    if let Ok(entries) = std::fs::read_dir(&dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().and_then(|s| s.to_str()) != Some("csv") {
                continue;
            }
            let Ok(md) = entry.metadata() else { continue };
            let modified = md
                .modified()
                .ok()
                .map(|t| chrono::DateTime::<chrono::Local>::from(t).to_rfc3339())
                .unwrap_or_default();
            out.push(ReportFile {
                name: entry.file_name().to_string_lossy().into_owned(),
                size: md.len(),
                modified,
            });
        }
    }
    out.sort_by(|a, b| b.name.cmp(&a.name));
    Json(out)
}

// -------------------------------------------------------------------- logs

pub async fn log_events(
    State(state): State<AppState>,
) -> Sse<impl Stream<Item = Result<Event, Infallible>>> {
    let rx = state.inner.log_tx.subscribe();
    let stream = BroadcastStream::new(rx).filter_map(|msg| match msg {
        Ok(text) => Some(Ok(Event::default().data(text))),
        Err(_) => None,
    });
    Sse::new(stream).keep_alive(KeepAlive::default())
}

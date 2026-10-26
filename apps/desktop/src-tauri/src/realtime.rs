//! Sync signals. While unlocked, the app keeps a WebSocket to Supabase
//! Realtime joined to the account's private topic, "user:<id>". The server
//! sends "sync" there when an item, a vault or its members change on another
//! device (supabase/migrations/20261026000000_sync_signals.sql), and the app
//! syncs right away. A signal carries nothing: what changed comes from the
//! sync, checked as always. Only the account's own session can join the
//! topic. The periodic sync (`sync::start_background_sync`) stays, slower
//! while signals arrive.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use futures_util::{SinkExt, StreamExt};
use rustls_platform_verifier::ConfigVerifierExt;
use serde_json::{Value, json};
use tauri::{AppHandle, Manager};
use tokio_tungstenite::{Connector, tungstenite::Message};

use crate::{config, state::AppState, sync};

/// Realtime drops a connection without a heartbeat for 30 s.
const HEARTBEAT: Duration = Duration::from_secs(25);
/// A heartbeat unanswered for this long: the connection is gone (sleep, network).
const NO_ANSWER: Duration = Duration::from_secs(15);
/// Waits between failed connections, then the last one over and over.
const BACKOFF: [u64; 6] = [1, 2, 5, 10, 30, 60];
/// Signals close together make one sync.
const GATHER: Duration = Duration::from_millis(300);

/// Joined to the topic: signals are arriving.
static LISTENING: AtomicBool = AtomicBool::new(false);
static SYNC_PENDING: AtomicBool = AtomicBool::new(false);

pub fn listening() -> bool {
    LISTENING.load(Ordering::Relaxed)
}

pub fn start(app: AppHandle) {
    if !config::SUPABASE_URL.starts_with("https://") {
        return;
    }
    tauri::async_runtime::spawn(async move {
        let mut failures = 0usize;
        loop {
            if !unlocked(&app).await {
                failures = 0;
                tokio::time::sleep(Duration::from_secs(1)).await;
                continue;
            }
            let result = listen(&app).await;
            LISTENING.store(false, Ordering::Relaxed);
            match result {
                // Locked.
                Ok(()) => failures = 0,
                Err(err) => {
                    log::info!("sync signals: {err}");
                    let wait = BACKOFF[failures.min(BACKOFF.len() - 1)];
                    failures += 1;
                    tokio::time::sleep(Duration::from_secs(wait)).await;
                }
            }
        }
    });
}

async fn unlocked(app: &AppHandle) -> bool {
    app.state::<AppState>().session.lock().await.is_some()
}

/// Syncs soon, once for signals close together.
fn request_sync(app: &AppHandle) {
    if SYNC_PENDING.swap(true, Ordering::AcqRel) {
        return;
    }
    let app = app.clone();
    tauri::async_runtime::spawn(async move {
        tokio::time::sleep(GATHER).await;
        SYNC_PENDING.store(false, Ordering::Release);
        if let Err(err) = sync::sync_now(&app).await {
            log::info!("sync after a signal: {err}");
        }
    });
}

fn socket_url() -> String {
    format!(
        "{}/realtime/v1/websocket?apikey={}&vsn=1.0.0",
        config::SUPABASE_URL.trim_end_matches('/').replacen("https://", "wss://", 1),
        config::SUPABASE_PUBLISHABLE_KEY
    )
}

fn frame(topic: &str, event: &str, payload: Value, reference: u64) -> Message {
    Message::text(json!({ "topic": topic, "event": event, "payload": payload, "ref": reference.to_string(), "join_ref": "1" }).to_string())
}

/// Listens until locked (Ok) or the connection fails (Err).
async fn listen(app: &AppHandle) -> Result<(), String> {
    let state = app.state::<AppState>();
    let (user_id, mut token) = sync::ensure_token(&state).await.map_err(|e| e.to_string())?;
    let _ = rustls::crypto::ring::default_provider().install_default();
    let tls = rustls::ClientConfig::with_platform_verifier().map_err(|e| e.to_string())?;
    let connect = tokio_tungstenite::connect_async_tls_with_config(socket_url(), None, false, Some(Connector::Rustls(Arc::new(tls))));
    let (socket, _) = tokio::time::timeout(Duration::from_secs(15), connect)
        .await
        .map_err(|_| "connection timed out".to_string())?
        .map_err(|e| e.to_string())?;
    let (mut tx, mut rx) = socket.split();

    let topic = format!("realtime:user:{user_id}");
    let config = json!({ "broadcast": { "ack": false, "self": false }, "presence": { "enabled": false }, "private": true });
    tx.send(frame(&topic, "phx_join", json!({ "config": config, "access_token": token.as_str() }), 1))
        .await
        .map_err(|e| e.to_string())?;

    let mut reference = 1u64;
    let mut waiting: Option<(String, Instant)> = None;
    let mut next_heartbeat = Instant::now() + HEARTBEAT;
    let mut tick = tokio::time::interval(Duration::from_secs(1));
    loop {
        tokio::select! {
            message = rx.next() => {
                let text = match message {
                    Some(Ok(Message::Text(text))) => text,
                    Some(Ok(Message::Close(_))) | None => return Err("closed".into()),
                    Some(Ok(_)) => continue,
                    Some(Err(err)) => return Err(err.to_string()),
                };
                let Ok(message) = serde_json::from_str::<Value>(text.as_str()) else { continue };
                let event = message["event"].as_str().unwrap_or_default();
                let at_topic = message["topic"].as_str() == Some(topic.as_str());
                match event {
                    "phx_reply" if message["ref"].as_str() == Some("1") => {
                        if message["payload"]["status"].as_str() != Some("ok") {
                            return Err(format!("join refused: {}", message["payload"]["response"]["reason"]));
                        }
                        LISTENING.store(true, Ordering::Relaxed);
                        log::info!("sync signals: listening");
                        // Changes made while not listening.
                        request_sync(app);
                    }
                    "phx_reply" => {
                        if waiting.as_ref().is_some_and(|(r, _)| message["ref"].as_str() == Some(r.as_str())) {
                            waiting = None;
                        }
                    }
                    "broadcast" if at_topic && message["payload"]["event"].as_str() == Some("sync") => request_sync(app),
                    "phx_close" | "phx_error" if at_topic => return Err(format!("channel {event}")),
                    "system" if at_topic && message["payload"]["status"].as_str() == Some("error") => {
                        return Err(format!("channel error: {}", message["payload"]["message"]));
                    }
                    _ => {}
                }
            }
            _ = tick.tick() => {
                if !unlocked(app).await {
                    let _ = tx.send(Message::Close(None)).await;
                    return Ok(());
                }
                if waiting.as_ref().is_some_and(|(_, sent)| sent.elapsed() > NO_ANSWER) {
                    return Err("no answer".into());
                }
                if Instant::now() < next_heartbeat {
                    continue;
                }
                next_heartbeat = Instant::now() + HEARTBEAT;
                reference += 1;
                tx.send(frame("phoenix", "heartbeat", json!({}), reference)).await.map_err(|e| e.to_string())?;
                waiting = Some((reference.to_string(), Instant::now()));
                // A refreshed session: Realtime closes the channel when the
                // token it has expires.
                let (current_user, current) = sync::ensure_token(&state).await.map_err(|e| e.to_string())?;
                if current_user != user_id {
                    return Err("another account".into());
                }
                if current != token {
                    token = current;
                    reference += 1;
                    tx.send(frame(&topic, "access_token", json!({ "access_token": token.as_str() }), reference))
                        .await
                        .map_err(|e| e.to_string())?;
                }
            }
        }
    }
}

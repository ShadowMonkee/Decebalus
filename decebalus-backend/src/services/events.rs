//! Structured real-time events.
//!
//! Broadcasts a typed JSON envelope — `{ "type": ..., "payload": ... }` — over the
//! same WebSocket channel as the legacy colon-delimited progress strings. The
//! frontend parses JSON when it can and falls back to the raw string otherwise,
//! so this is purely additive: existing string consumers keep working while the
//! war table subscribes to typed events (`finding`, `cred`, `job`, `engine`).

use std::sync::Arc;

use serde_json::{json, Value};

use crate::state::AppState;

/// Broadcast a structured event. `event_type` is a short tag the frontend switches
/// on; `payload` is the event body.
pub fn emit(state: &Arc<AppState>, event_type: &str, payload: Value) {
    let envelope = json!({ "type": event_type, "payload": payload });
    let _ = state.broadcaster.send(envelope.to_string());
}

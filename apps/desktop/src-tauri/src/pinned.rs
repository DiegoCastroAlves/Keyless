//! Logins pinned to a website: first for it in the browser (the menu below a
//! field, the sign-in card, the fill shortcut), whatever else is used more,
//! like the account one signs in with most among several. A setting that
//! follows the account (see `account_settings`), keyed by the website's
//! registrable domain, so a pin on instagram.com counts on www. and m. too.

use std::collections::HashMap;

use serde_json::json;
use tauri::{AppHandle, Manager};

use crate::{error::AppResult, state::AppState};

const PINS: &str = "pins";

/// Website -> the item pinned to it.
fn all(state: &AppState) -> HashMap<String, String> {
    crate::account_settings::get(state, PINS).and_then(|pins| serde_json::from_value(pins).ok()).unwrap_or_default()
}

/// The item pinned to `site`, if any.
pub fn for_site(state: &AppState, site: &str) -> Option<String> {
    all(state).remove(site)
}

/// The websites `item_id` is pinned to.
pub fn sites_of(state: &AppState, item_id: &str) -> Vec<String> {
    let mut sites: Vec<String> = all(state).into_iter().filter(|(_, id)| id == item_id).map(|(site, _)| site).collect();
    sites.sort();
    sites
}

/// Pins `item_id` to `site`, in place of the one pinned there, or unpins it.
pub async fn set(app: &AppHandle, site: &str, item_id: &str, pinned: bool) -> AppResult<()> {
    let state = app.state::<AppState>();
    let mut pins = all(&state);
    if pinned {
        pins.insert(site.to_string(), item_id.to_string());
    } else if pins.get(site).is_some_and(|id| id == item_id) {
        pins.remove(site);
    }
    // Pins of items that are gone.
    if let Some(session) = state.session.lock().await.as_ref() {
        pins.retain(|_, id| session.items.contains_key(id));
    }
    crate::account_settings::set(app, PINS, Some(json!(pins))).await
}

/// Items moved to another vault (under new ids) keep their pins.
pub async fn moved(app: &AppHandle, renamed: &[(String, String)]) -> AppResult<()> {
    let state = app.state::<AppState>();
    let mut pins = all(&state);
    let mut changed = false;
    for id in pins.values_mut() {
        if let Some((_, to)) = renamed.iter().find(|(from, _)| from == id) {
            *id = to.clone();
            changed = true;
        }
    }
    if !changed {
        return Ok(());
    }
    crate::account_settings::set(app, PINS, Some(json!(pins))).await
}

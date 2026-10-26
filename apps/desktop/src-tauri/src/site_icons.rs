//! Website icons for logins.
//!
//! Each icon is downloaded from the site itself, never through a third-party
//! service that would learn which sites the user has saved. Only public
//! `https` addresses are contacted (nothing on the local network), with size
//! and time limits, and the image is converted here to a small PNG: nothing
//! from a site reaches the UI as it was sent.
//!
//! Icons are kept in the local database, encrypted with a key derived from
//! the account key (see `keyless_core::site_icons`, shared with the phone).
//! Rows are named by a keyed hash of the host, so the file does not reveal
//! the sites either. Icons never leave this device and are fetched again by
//! each one.

use std::{
    collections::HashMap,
    io::Cursor,
    net::SocketAddr,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use base64::{Engine, engine::general_purpose::STANDARD};
use keyless_core::{
    item::Category,
    site_icons::{ICON_SIZE as SIZE, IconKeys, allowed_host, icon_address, icon_links, is_public},
};
use serde::Serialize;
use tauri::{AppHandle, Emitter, Manager};
use url::Url;

use crate::{
    api::now_secs,
    bridge::handlers::url_host,
    error::{AppError, AppResult},
    state::{AppState, Session},
};

pub const EVENT_CHANGED: &str = "keyless://site-icons-changed";

/// A page is read up to the end of its head, where icons are declared.
const MAX_PAGE: usize = 2 * 1024 * 1024;
/// `.ico` files often hold several sizes.
const MAX_ICON: usize = 1024 * 1024;
const REFRESH_AFTER: i64 = 30 * 24 * 3600;
/// Sites without an icon are asked again after a week.
const RETRY_AFTER: i64 = 7 * 24 * 3600;
const PARALLEL: usize = 4;
/// Sites expect a browser; this is not one, but it asks like one.
const USER_AGENT: &str = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0 Safari/537.36";

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SiteIcon {
    /// PNG as a data URL.
    pub src: String,
    /// The icon has a transparent background: show it on a light tile.
    pub padded: bool,
}

/// The icon as the UI shows it.
fn to_view((png, opaque): (Vec<u8>, bool)) -> SiteIcon {
    SiteIcon { src: format!("data:image/png;base64,{}", STANDARD.encode(png)), padded: !opaque }
}

/// Normalized host for an address or host typed by the user.
fn host_of(url_or_host: &str) -> Option<String> {
    url_host(url_or_host)
}

/// Cached icons for these addresses or hosts, keyed as given.
pub fn lookup(state: &AppState, session: &Session, sites: &[String]) -> HashMap<String, SiteIcon> {
    let mut found = HashMap::new();
    if !state.settings().site_icons {
        return found;
    }
    let Ok(keys) = IconKeys::new(session.account.user_key()) else { return found };
    let store = state.store();
    for site in sites {
        let Some(host) = host_of(site) else { continue };
        let id = keys.id(&host);
        if let Ok(Some((data, true, _))) = store.site_icon(&id)
            && let Some(icon) = keys.open(&id, &data)
        {
            found.insert(site.clone(), to_view(icon));
        }
    }
    found
}

// ----- fetching ------------------------------------------------------------------

static RUNNING: AtomicBool = AtomicBool::new(false);
/// Asked for while running (e.g. an item was saved): run once more.
static AGAIN: AtomicBool = AtomicBool::new(false);

/// Fetches the icons that are missing or old, in the background.
pub fn refresh(app: &AppHandle) {
    if !app.state::<AppState>().settings().site_icons {
        return;
    }
    if RUNNING.swap(true, Ordering::SeqCst) {
        AGAIN.store(true, Ordering::SeqCst);
        return;
    }
    let app = app.clone();
    tauri::async_runtime::spawn(async move {
        loop {
            AGAIN.store(false, Ordering::SeqCst);
            if let Err(err) = run(&app).await {
                log::info!("site icons: {err}");
            }
            if !AGAIN.load(Ordering::SeqCst) {
                break;
            }
        }
        RUNNING.store(false, Ordering::SeqCst);
    });
}

/// Forgets every icon (the setting was turned off).
pub fn clear(app: &AppHandle) -> AppResult<()> {
    app.state::<AppState>().store().clear_site_icons()?;
    let _ = app.emit(EVENT_CHANGED, ());
    Ok(())
}

async fn run(app: &AppHandle) -> AppResult<()> {
    let state = app.state::<AppState>();
    let (keys, hosts) = {
        let guard = state.session.lock().await;
        let Some(session) = guard.as_ref() else { return Ok(()) };
        let mut hosts: Vec<String> = session
            .items
            .values()
            .filter(|item| item.overview.trashed_at.is_none() && matches!(item.overview.category, Category::Login | Category::Password))
            .flat_map(|item| {
                let urls = &item.overview.urls;
                // A linked app's site too, for a login with no website.
                urls.iter().filter_map(|u| host_of(&u.href)).chain(icon_address(urls).and_then(|a| host_of(&a)))
            })
            .filter(|host| allowed_host(host))
            .collect();
        hosts.sort();
        hosts.dedup();
        (IconKeys::new(session.account.user_key())?, hosts)
    };

    let now = now_secs();
    let due: Vec<(String, String)> = {
        let store = state.store();
        hosts
            .into_iter()
            .map(|host| (keys.id(&host), host))
            .filter(|(id, _)| match store.site_icon(id) {
                Ok(Some((_, found, fetched_at))) => now - fetched_at > if found { REFRESH_AFTER } else { RETRY_AFTER },
                _ => true,
            })
            .collect()
    };
    if due.is_empty() {
        return Ok(());
    }
    log::info!("site icons: fetching {}", due.len());

    let client = client()?;
    let limit = Arc::new(tokio::sync::Semaphore::new(PARALLEL));
    let mut tasks = tokio::task::JoinSet::new();
    for (id, host) in due {
        let (client, limit) = (client.clone(), limit.clone());
        tasks.spawn(async move {
            let _permit = limit.acquire_owned().await;
            let icon = fetch(&client, &host).await;
            (id, icon)
        });
    }

    let mut stored = 0;
    while let Some(Ok((id, icon))) = tasks.join_next().await {
        // Locked meanwhile: stop, and drop the keys with the tasks.
        if state.session.lock().await.is_none() || !state.settings().site_icons {
            tasks.abort_all();
            break;
        }
        let data = keys.seal(&id, icon.as_ref().map(|(png, opaque)| (png.as_slice(), *opaque)))?;
        state.store().save_site_icon(&id, &data, icon.is_some(), now_secs())?;
        if icon.is_some() {
            stored += 1;
            if stored % 10 == 0 {
                let _ = app.emit(EVENT_CHANGED, ());
            }
        }
    }
    if stored > 0 {
        let _ = app.emit(EVENT_CHANGED, ());
    }
    Ok(())
}

fn client() -> AppResult<reqwest::Client> {
    reqwest::Client::builder()
        .https_only(true)
        .timeout(Duration::from_secs(15))
        .connect_timeout(Duration::from_secs(8))
        .redirect(reqwest::redirect::Policy::custom(|attempt| {
            let allowed = attempt.url().scheme() == "https" && attempt.url().host_str().is_some_and(allowed_host);
            if attempt.previous().len() >= 5 || !allowed { attempt.stop() } else { attempt.follow() }
        }))
        .dns_resolver(Arc::new(PublicOnly))
        .user_agent(USER_AGENT)
        .build()
        .map_err(|e| AppError::Server(e.to_string()))
}

/// The site's icon as a PNG, and whether it is opaque.
async fn fetch(client: &reqwest::Client, host: &str) -> Option<(Vec<u8>, bool)> {
    let home = Url::parse(&format!("https://{host}/")).ok()?;
    let mut candidates = Vec::new();
    if let Some((page, html)) = get(client, home.clone(), Body::Page, "text/html").await {
        candidates.extend(icon_links(&String::from_utf8_lossy(&html), &page));
        candidates.extend(page.join("/favicon.ico").ok());
    }
    candidates.extend(home.join("/favicon.ico").ok());
    candidates.dedup();
    for candidate in candidates.into_iter().take(5) {
        if let Some((_, bytes)) = get(client, candidate, Body::Icon, "image/*").await
            && let Some(icon) = to_png(&bytes)
        {
            return Some(icon);
        }
    }
    None
}

enum Body {
    /// Read the page up to the end of its head, at most `MAX_PAGE`.
    Page,
    /// The whole image, refused above `MAX_ICON`.
    Icon,
}

/// GET with a size limit. Returns the final address (after redirects).
async fn get(client: &reqwest::Client, url: Url, body: Body, accept: &str) -> Option<(Url, Vec<u8>)> {
    if url.scheme() != "https" || !url.host_str().is_some_and(allowed_host) {
        return None;
    }
    let mut response = client.get(url).header(reqwest::header::ACCEPT, accept).send().await.ok()?;
    let limit = match body {
        Body::Page => MAX_PAGE,
        Body::Icon => MAX_ICON,
    };
    if !response.status().is_success() || (matches!(body, Body::Icon) && response.content_length().is_some_and(|n| n > limit as u64)) {
        return None;
    }
    let url = response.url().clone();
    let mut data = Vec::new();
    while let Some(chunk) = response.chunk().await.ok()? {
        let searched = data.len().saturating_sub(6);
        data.extend_from_slice(&chunk);
        if matches!(body, Body::Page) && data[searched..].windows(7).any(|w| w.eq_ignore_ascii_case(b"</head>")) {
            break;
        }
        if data.len() > limit {
            match body {
                Body::Page => {
                    data.truncate(limit);
                    break;
                }
                Body::Icon => return None,
            }
        }
    }
    Some((url, data))
}

/// Decodes an icon (PNG, ICO, JPEG, GIF, WebP, BMP) with size limits and
/// re-encodes it as a PNG of at most `SIZE` pixels.
fn to_png(bytes: &[u8]) -> Option<(Vec<u8>, bool)> {
    let mut reader = image::ImageReader::new(Cursor::new(bytes)).with_guessed_format().ok()?;
    let mut limits = image::Limits::default();
    limits.max_image_width = Some(1024);
    limits.max_image_height = Some(1024);
    limits.max_alloc = Some(32 * 1024 * 1024);
    reader.limits(limits);
    let image = reader.decode().ok()?;
    if image.width() < 16 || image.height() < 16 {
        return None;
    }
    let image = if image.width() > SIZE || image.height() > SIZE {
        image.resize(SIZE, SIZE, image::imageops::FilterType::Lanczos3)
    } else {
        image
    };
    let rgba = image.to_rgba8();
    let pixels = rgba.pixels().len();
    let opaque = rgba.pixels().filter(|p| p[3] > 200).count() * 10 >= pixels * 9;
    let mut png = Vec::new();
    image::DynamicImage::ImageRgba8(rgba).write_to(&mut Cursor::new(&mut png), image::ImageFormat::Png).ok()?;
    Some((png, opaque))
}

// ----- what may be contacted ---------------------------------------------------------

/// DNS that only returns public addresses, so a site cannot point its name
/// (or a redirect) at the local network. The connection uses exactly these
/// addresses.
struct PublicOnly;

impl reqwest::dns::Resolve for PublicOnly {
    fn resolve(&self, name: reqwest::dns::Name) -> reqwest::dns::Resolving {
        let host = name.as_str().to_string();
        Box::pin(async move {
            let addrs: Vec<SocketAddr> = tokio::net::lookup_host((host.as_str(), 443)).await?.filter(|a| is_public(a.ip())).collect();
            if addrs.is_empty() {
                return Err("no public address".into());
            }
            Ok(Box::new(addrs.into_iter()) as reqwest::dns::Addrs)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn icons_are_reencoded_and_bounded() {
        let mut source = image::RgbaImage::new(128, 128);
        source.pixels_mut().for_each(|p| *p = image::Rgba([200, 30, 90, 255]));
        let mut bytes = Vec::new();
        image::DynamicImage::ImageRgba8(source).write_to(&mut Cursor::new(&mut bytes), image::ImageFormat::Png).unwrap();
        let (png, opaque) = to_png(&bytes).unwrap();
        let decoded = image::load_from_memory(&png).unwrap();
        assert_eq!((decoded.width(), decoded.height()), (64, 64));
        assert!(opaque);
        assert!(to_png(b"<svg onload=alert(1)></svg>").is_none());
        assert!(to_png(b"not an image").is_none());
    }

    /// Talks to real sites: `cargo test fetches_real_icons -- --ignored`.
    /// Set KEYLESS_ICON_DUMP to a folder to look at the results.
    #[test]
    #[ignore]
    fn fetches_real_icons() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
        let client = client().unwrap();
        let mut found = 0;
        for host in ["instagram.com", "accounts.google.com", "github.com", "paypal.com", "nubank.com.br", "netflix.com"] {
            let icon = runtime.block_on(fetch(&client, host));
            println!("{host}: {:?}", icon.as_ref().map(|(png, opaque)| (png.len(), *opaque)));
            if let (Some((png, _)), Ok(dir)) = (&icon, std::env::var("KEYLESS_ICON_DUMP")) {
                std::fs::write(format!("{dir}/{host}.png"), png).unwrap();
            }
            found += usize::from(icon.is_some());
        }
        assert!(found >= 4);
    }
}

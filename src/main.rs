mod alloc;
mod api;
mod db;
mod net;
mod wg;

use anyhow::{Context, Result};
use db::Db;
use rtnetlink::new_connection;
use std::sync::Arc;
use utoipa::OpenApi;
use utoipa_scalar::{Scalar, Servable};

#[derive(OpenApi)]
#[openapi(
    info(
        title = "wgdb",
        version = "0.1.0",
        description = "WireGuard management daemon — manages interfaces, peers, principals, and registration tokens.",
    ),
    paths(
        api::list_interfaces,
        api::create_interface,
        api::get_interface,
        api::update_interface,
        api::delete_interface,
        api::list_peers,
        api::update_peer,
        api::revoke_peer,
        api::list_principals,
        api::get_principal_handler,
        api::create_principal,
        api::update_principal,
        api::delete_principal,
        api::list_principal_peers,
        api::create_session,
        api::list_tokens,
        api::create_token,
        api::revoke_token,
        api::register,
        api::connect,
    ),
    components(schemas(
        db::Interface,
        db::Principal,
        db::Peer,
        db::Token,
        api::CreateInterfaceBody,
        api::UpdateInterfaceBody,
        api::CreatePrincipalBody,
        api::UpdatePrincipalBody,
        api::CreateSessionBody,
        api::SessionResponse,
        api::CreateTokenBody,
        api::UpdatePeerBody,
        api::RegisterRequest,
        api::RegisterResponse,
        api::ConnectRequest,
        api::ConnectResponse,
    )),
    tags(
        (name = "Interfaces", description = "WireGuard interface management"),
        (name = "Peers",      description = "Peer management and revocation"),
        (name = "Principals", description = "User account management"),
        (name = "Tokens",     description = "Registration token management"),
        (name = "Client",     description = "Public endpoints used by WireGuard clients"),
    ),
    security(("bearer_token" = [])),
    modifiers(&BearerSecurityAddon),
)]
struct ApiDoc;

struct BearerSecurityAddon;

impl utoipa::Modify for BearerSecurityAddon {
    fn modify(&self, openapi: &mut utoipa::openapi::OpenApi) {
        if let Some(components) = openapi.components.as_mut() {
            components.add_security_scheme(
                "bearer_token",
                utoipa::openapi::security::SecurityScheme::Http(
                    utoipa::openapi::security::HttpBuilder::new()
                        .scheme(utoipa::openapi::security::HttpAuthScheme::Bearer)
                        .build(),
                ),
            );
        }
    }
}

// ── App state ─────────────────────────────────────────────────────────────────

pub struct AppState {
    pub db:          Db,
    pub netlink:     rtnetlink::Handle,
    pub admin_token: String,
}

// ── Entry point ───────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();

    let args: Vec<String> = std::env::args().collect();
    let db_path     = args.get(1).map(|s| s.as_str()).unwrap_or("wgdb.db");
    let bind        = args.get(2).map(|s| s.as_str()).unwrap_or("127.0.0.1:51800");
    let admin_token = std::env::var("WGDB_ADMIN_TOKEN")
        .unwrap_or_else(|_| "changeme".to_string());

    tracing::info!("wgdb: db={db_path} bind={bind}");

    if let Some(parent) = std::path::Path::new(db_path).parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("create directory {}", parent.display()))?;
        }
    }

    let db = db::open(db_path).context("open db")?;

    let (rtnetlink_conn, handle, _) = new_connection().context("rtnetlink")?;
    tokio::spawn(rtnetlink_conn);

    // Bring up all enabled interfaces
    let ifaces = db::list_interfaces(&db)?;
    let mut iface_names: Vec<String> = Vec::new();
    for iface in &ifaces {
        iface_names.push(iface.name.clone());
        if iface.enabled
            && let Err(e) = api::bring_up_interface(&handle, &db, iface).await {
                tracing::warn!("wgdb: failed to bring up {}: {e:#}", iface.name);
            }
    }

    // Background handshake poller
    let poll_db = db.clone();
    tokio::spawn(poll_handshakes(poll_db, iface_names));

    // HTTP server — public routes + admin routes with bearer auth
    let state = Arc::new(AppState { db, netlink: handle, admin_token });

    let public_routes = axum::Router::new()
        .route("/v1/register", axum::routing::post(api::register_handler))
        .route("/v1/connect",  axum::routing::post(api::connect_handler))
        .with_state(state.clone());

    let admin_routes = api::router()
        .route_layer(axum::middleware::from_fn_with_state(state.clone(), api::bearer_auth))
        .with_state(state);

    let app = public_routes
        .merge(admin_routes)
        .merge(Scalar::with_url("/docs", ApiDoc::openapi()));

    let listener = tokio::net::TcpListener::bind(bind)
        .await
        .context("bind")?;
    tracing::info!("wgdb: listening on {bind}");

    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await
        .context("serve")?;

    tracing::info!("wgdb: shutdown complete");
    Ok(())
}

// ── Background poller ─────────────────────────────────────────────────────────

async fn poll_handshakes(db: Db, iface_names: Vec<String>) {
    let mut tick = tokio::time::interval(std::time::Duration::from_secs(30));
    loop {
        tick.tick().await;
        for name in &iface_names {
            let n = name.clone();
            match tokio::task::spawn_blocking(move || wg::peer_handshakes(&n)).await {
                Ok(Ok(map)) => {
                    for (pubkey, ts) in map {
                        let _ = db::update_peer_last_seen(&db, &pubkey, ts);
                    }
                }
                Ok(Err(e)) => tracing::warn!("poll {name}: {e:#}"),
                Err(e)     => tracing::warn!("poll join {name}: {e}"),
            }
        }
    }
}

// ── Graceful shutdown ─────────────────────────────────────────────────────────

async fn shutdown_signal() {
    use tokio::signal;
    let ctrl_c  = async { signal::ctrl_c().await.expect("ctrl+c") };
    #[cfg(unix)]
    let sigterm = async {
        signal::unix::signal(signal::unix::SignalKind::terminate())
            .expect("sigterm")
            .recv()
            .await;
    };
    #[cfg(not(unix))]
    let sigterm = std::future::pending::<()>();
    tokio::select! { _ = ctrl_c => {}, _ = sigterm => {} }
}

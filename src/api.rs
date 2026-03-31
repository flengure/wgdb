use axum::{
    extract::{Path, State},
    http::{header, StatusCode},
    middleware,
    response::{IntoResponse, Response},
    routing::{delete, get, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use utoipa::ToSchema;

use crate::{db, net, wg, AppState};

// ── Auth middleware ───────────────────────────────────────────────────────────

pub async fn bearer_auth(
    State(state): State<Arc<AppState>>,
    req: axum::extract::Request,
    next: middleware::Next,
) -> Response {
    let authorized = req
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .map(|t| t == state.admin_token)
        .unwrap_or(false);

    if authorized {
        next.run(req).await
    } else {
        StatusCode::UNAUTHORIZED.into_response()
    }
}

// ── Router ────────────────────────────────────────────────────────────────────

/// Admin-only routes (caller adds bearer auth layer).
pub fn router() -> Router<Arc<AppState>> {
    Router::new()
        // Interfaces
        .route("/v1/interfaces", get(list_interfaces).post(create_interface))
        .route(
            "/v1/interfaces/{name}",
            get(get_interface).patch(update_interface).delete(delete_interface),
        )
        // Peers
        .route("/v1/peers", get(list_peers))
        .route("/v1/peers/{pubkey}", delete(revoke_peer).patch(update_peer))
        // Principals
        .route("/v1/principals", get(list_principals).post(create_principal))
        .route(
            "/v1/principals/{id}",
            get(get_principal_handler)
                .patch(update_principal)
                .delete(delete_principal),
        )
        .route("/v1/principals/{id}/peers", get(list_principal_peers))
        .route("/v1/principals/{id}/session", post(create_session))
        // Tokens
        .route("/v1/tokens", get(list_tokens).post(create_token))
        .route("/v1/tokens/{token}", delete(revoke_token))
}

/// Public registration handler (no auth — token is in the request body).
pub async fn register_handler(
    State(state): State<Arc<AppState>>,
    Json(req): Json<RegisterRequest>,
) -> impl IntoResponse {
    register(State(state), Json(req)).await
}

/// Public connect handler (no auth — token is in the request body).
pub async fn connect_handler(
    State(state): State<Arc<AppState>>,
    Json(req): Json<ConnectRequest>,
) -> impl IntoResponse {
    connect(State(state), Json(req)).await
}

// ── Error type ────────────────────────────────────────────────────────────────

struct ApiError(anyhow::Error, StatusCode);

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (self.1, self.0.to_string()).into_response()
    }
}

impl<E: Into<anyhow::Error>> From<E> for ApiError {
    fn from(e: E) -> Self {
        ApiError(e.into(), StatusCode::INTERNAL_SERVER_ERROR)
    }
}

type ApiResult<T> = Result<T, ApiError>;

fn not_found() -> ApiError {
    ApiError(anyhow::anyhow!("not found"), StatusCode::NOT_FOUND)
}

fn bad_request(msg: &str) -> ApiError {
    ApiError(anyhow::anyhow!("{msg}"), StatusCode::BAD_REQUEST)
}

fn conflict(msg: &str) -> ApiError {
    ApiError(anyhow::anyhow!("{msg}"), StatusCode::CONFLICT)
}

// ── Interface handlers ────────────────────────────────────────────────────────

/// List all WireGuard interfaces.
#[utoipa::path(
    get,
    path = "/v1/interfaces",
    tag = "Interfaces",
    security(("bearer_token" = [])),
    responses(
        (status = 200, description = "List of interfaces", body = Vec<db::Interface>),
        (status = 401, description = "Unauthorized"),
    )
)]
async fn list_interfaces(
    State(state): State<Arc<AppState>>,
) -> ApiResult<Json<Vec<db::Interface>>> {
    Ok(Json(db::list_interfaces(&state.db)?))
}

#[derive(Deserialize, ToSchema)]
pub struct CreateInterfaceBody {
    /// Interface name (alphanumeric, hyphens, underscores).
    name:        String,
    /// WireGuard listen port (default: 51820).
    listen_port: Option<i64>,
    /// Server IPv4 CIDR, e.g. `10.0.0.1/24`. Used for client IP allocation.
    address_v4:  Option<String>,
    /// Server IPv6 CIDR, e.g. `fd00::1/64`. Used for client IP allocation.
    address_v6:  Option<String>,
    /// Interface MTU.
    mtu:         Option<i64>,
    /// DNS server(s) pushed to clients.
    dns:         Option<String>,
    /// Public endpoint advertised to clients, e.g. `vpn.example.com:51820`.
    endpoint:    Option<String>,
    /// Allowed IPs pushed to clients (default: `0.0.0.0/0,::/0`).
    allowed_ips: Option<String>,
    /// Import an existing private key (base64). Omit to generate a new keypair.
    private_key: Option<String>,
    /// Bring the interface up immediately (default: true).
    enabled:     Option<bool>,
}

/// Create a new WireGuard interface.
#[utoipa::path(
    post,
    path = "/v1/interfaces",
    tag = "Interfaces",
    security(("bearer_token" = [])),
    request_body = CreateInterfaceBody,
    responses(
        (status = 200, description = "Created interface", body = db::Interface),
        (status = 400, description = "Invalid name"),
        (status = 401, description = "Unauthorized"),
        (status = 409, description = "Interface name already exists"),
    )
)]
async fn create_interface(
    State(state): State<Arc<AppState>>,
    Json(body): Json<CreateInterfaceBody>,
) -> ApiResult<Json<db::Interface>> {
    if body.name.is_empty()
        || !body
            .name
            .chars()
            .all(|c| c.is_alphanumeric() || c == '_' || c == '-')
    {
        return Err(bad_request("name must be non-empty alphanumeric/hyphen/underscore"));
    }

    let listen_port = body.listen_port.unwrap_or(51820);
    let enabled = body.enabled.unwrap_or(true);

    // Generate or import keypair
    let (private_b64, public_b64) = match body.private_key {
        Some(ref pk) => {
            let priv_key =
                wireguard_control::Key::from_base64(pk).map_err(|_| bad_request("invalid private_key"))?;
            (pk.clone(), priv_key.get_public().to_base64())
        }
        None => tokio::task::spawn_blocking(wg::generate_keypair).await??,
    };

    let iface = db::insert_interface(
        &state.db,
        &db::NewInterface {
            name:        body.name.clone(),
            private_key: private_b64,
            pubkey:      public_b64,
            listen_port,
            address_v4:  body.address_v4.clone(),
            address_v6:  body.address_v6.clone(),
            mtu:         body.mtu,
            dns:         body.dns.clone(),
            endpoint:    body.endpoint.clone(),
            allowed_ips: body.allowed_ips.clone(),
            enabled,
        },
    )
    .map_err(|e| {
        if e.to_string().contains("UNIQUE") {
            conflict("interface name already exists")
        } else {
            e.into()
        }
    })?;

    if enabled {
        bring_up_interface(&state.netlink, &state.db, &iface).await?;
    }

    tracing::info!("api: created interface {} (enabled={})", iface.name, enabled);
    Ok(Json(iface))
}

/// Get a WireGuard interface by name, including live stats if the interface is up.
#[utoipa::path(
    get,
    path = "/v1/interfaces/{name}",
    tag = "Interfaces",
    security(("bearer_token" = [])),
    params(
        ("name" = String, Path, description = "Interface name"),
    ),
    responses(
        (status = 200, description = "Interface with optional live stats (peer_count, rx_bytes, tx_bytes)", body = serde_json::Value),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Not found"),
    )
)]
async fn get_interface(
    State(state): State<Arc<AppState>>,
    Path(name): Path<String>,
) -> ApiResult<Json<serde_json::Value>> {
    let iface = db::get_interface(&state.db, &name)?.ok_or_else(not_found)?;

    // Try to get live stats; non-fatal if interface isn't up yet
    let stats = {
        let n = name.clone();
        tokio::task::spawn_blocking(move || wg::interface_stats(&n))
            .await?
            .ok()
    };

    let mut val = serde_json::to_value(&iface)?;
    if let (Some(stats), Some(obj)) = (stats, val.as_object_mut()) {
        obj.insert("peer_count".into(), stats.peer_count.into());
        obj.insert("rx_bytes".into(), stats.rx_bytes.into());
        obj.insert("tx_bytes".into(), stats.tx_bytes.into());
    }

    Ok(Json(val))
}

#[derive(Deserialize, ToSchema)]
pub struct UpdateInterfaceBody {
    /// New listen port.
    listen_port: Option<i64>,
    /// New IPv4 CIDR, or null to clear.
    address_v4:  Option<Option<String>>,
    /// New IPv6 CIDR, or null to clear.
    address_v6:  Option<Option<String>>,
    /// New MTU, or null to clear.
    mtu:         Option<Option<i64>>,
    /// New DNS, or null to clear.
    dns:         Option<Option<String>>,
    /// New endpoint, or null to clear.
    endpoint:    Option<Option<String>>,
    /// New allowed IPs, or null to clear.
    allowed_ips: Option<Option<String>>,
    /// Enable or disable the interface.
    enabled:     Option<bool>,
}

/// Update a WireGuard interface. Only provided fields are changed.
/// Setting a nullable field to null clears it.
#[utoipa::path(
    patch,
    path = "/v1/interfaces/{name}",
    tag = "Interfaces",
    security(("bearer_token" = [])),
    params(
        ("name" = String, Path, description = "Interface name"),
    ),
    request_body = UpdateInterfaceBody,
    responses(
        (status = 200, description = "Updated interface", body = db::Interface),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Not found"),
    )
)]
async fn update_interface(
    State(state): State<Arc<AppState>>,
    Path(name): Path<String>,
    Json(body): Json<UpdateInterfaceBody>,
) -> ApiResult<Json<db::Interface>> {
    let mut iface = db::get_interface(&state.db, &name)?.ok_or_else(not_found)?;

    let was_enabled = iface.enabled;
    let port_changed = body.listen_port.map(|p| p != iface.listen_port).unwrap_or(false);
    let addr_changed = body.address_v4.is_some() || body.address_v6.is_some();
    let mtu_changed  = body.mtu.is_some();

    // Apply patch
    if let Some(p) = body.listen_port          { iface.listen_port = p; }
    if let Some(v) = body.address_v4           { iface.address_v4 = v; }
    if let Some(v) = body.address_v6           { iface.address_v6 = v; }
    if let Some(v) = body.mtu                  { iface.mtu = v; }
    if let Some(v) = body.dns                  { iface.dns = v; }
    if let Some(v) = body.endpoint             { iface.endpoint = v; }
    if let Some(v) = body.allowed_ips          { iface.allowed_ips = v; }
    if let Some(v) = body.enabled              { iface.enabled = v; }

    db::update_interface(&state.db, &iface)?;

    let handle = state.netlink.clone();

    // Handle enable/disable transitions
    if !was_enabled && iface.enabled {
        // Bringing up: create kernel interface fresh
        bring_up_interface(&handle, &state.db, &iface).await?;
    } else if was_enabled && !iface.enabled {
        // Bringing down: delete kernel interface
        if let Err(e) = net::delete_link(&handle, &name).await {
            tracing::warn!("api: delete_link {name}: {e:#}");
        }
    } else if iface.enabled {
        // Was enabled and stays enabled — apply incremental changes

        // Reconfigure WireGuard if port changed
        if port_changed {
            let peers = db::list_peers_for_iface(&state.db, iface.id)?;
            let iface_c = iface.clone();
            tokio::task::spawn_blocking(move || wg::configure(&iface_c, &peers)).await??;
        }

        // Re-apply addresses if they changed
        if addr_changed {
            let idx = net::link_index(&handle, &name)
                .await?
                .ok_or_else(|| anyhow::anyhow!("interface not found in kernel"))?;
            net::flush_addresses(&handle, idx).await?;
            if let Some(cidr) = &iface.address_v4 {
                net::add_address(&handle, idx, cidr).await?;
            }
            if let Some(cidr) = &iface.address_v6 {
                net::add_address(&handle, idx, cidr).await?;
            }
        }

        // Apply MTU if changed
        if mtu_changed
            && let Some(mtu) = iface.mtu {
                let idx = net::link_index(&handle, &name)
                    .await?
                    .ok_or_else(|| anyhow::anyhow!("interface not found in kernel"))?;
                net::set_mtu(&handle, idx, mtu as u32).await?;
            }
    }

    tracing::info!("api: updated interface {name}");
    Ok(Json(iface))
}

/// Delete a WireGuard interface and revoke all its peers.
#[utoipa::path(
    delete,
    path = "/v1/interfaces/{name}",
    tag = "Interfaces",
    security(("bearer_token" = [])),
    params(
        ("name" = String, Path, description = "Interface name"),
    ),
    responses(
        (status = 204, description = "Deleted"),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Not found"),
    )
)]
async fn delete_interface(
    State(state): State<Arc<AppState>>,
    Path(name): Path<String>,
) -> ApiResult<StatusCode> {
    // Remove kernel interface first (kills all WG peers automatically)
    net::delete_link(&state.netlink, &name).await?;

    let pubkeys = db::delete_interface(&state.db, &name)?
        .ok_or_else(not_found)?;

    tracing::info!("api: deleted interface {name} ({} peers revoked)", pubkeys.len());
    Ok(StatusCode::NO_CONTENT)
}

// ── Session handler ───────────────────────────────────────────────────────────

#[derive(Deserialize, ToSchema)]
pub struct CreateSessionBody {
    /// Interface ID to bind the session token to.
    iface_id: i64,
}

#[derive(Serialize, ToSchema)]
pub struct SessionResponse {
    /// Session token (valid for 2 hours).
    token:   String,
    /// Unix timestamp when the token expires.
    expires: i64,
}

/// Create a time-limited session token (2 hours) for a principal.
/// The token can be used to call `/v1/connect`.
#[utoipa::path(
    post,
    path = "/v1/principals/{id}/session",
    tag = "Principals",
    security(("bearer_token" = [])),
    params(
        ("id" = i64, Path, description = "Principal ID"),
    ),
    request_body = CreateSessionBody,
    responses(
        (status = 200, description = "Session token", body = SessionResponse),
        (status = 401, description = "Unauthorized"),
        (status = 403, description = "Account suspended"),
        (status = 404, description = "Principal not found"),
    )
)]
async fn create_session(
    State(state): State<Arc<AppState>>,
    Path(id): Path<i64>,
    Json(body): Json<CreateSessionBody>,
) -> ApiResult<Json<SessionResponse>> {
    // Verify principal exists and is active
    let principal = db::get_principal(&state.db, id)?.ok_or_else(not_found)?;
    if principal.status != "active" {
        return Err(ApiError(anyhow::anyhow!("account suspended"), StatusCode::FORBIDDEN));
    }

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    let expires = now + 7200;

    let token = random_token();
    db::create_token(
        &state.db,
        &token,
        id,
        body.iface_id,
        None, // uses_left = None (unlimited within expiry window)
        Some(expires),
    )?;

    Ok(Json(SessionResponse { token, expires }))
}

// ── Connect handler ───────────────────────────────────────────────────────────

#[derive(Deserialize, ToSchema)]
pub struct ConnectRequest {
    /// Registration or session token.
    pub token:       String,
    /// Client WireGuard public key (base64).
    pub pubkey:      String,
    /// Human-readable label for this peer.
    pub label:       Option<String>,
    /// Requested client IPv4 (overrides server allocation if provided).
    pub client_ipv4: Option<String>,
    /// Requested client IPv6 (overrides server allocation if provided).
    pub client_ipv6: Option<String>,
    /// Pre-shared key (base64). Omit to use existing or generate new.
    pub psk:         Option<String>,
}

#[derive(Serialize, ToSchema)]
pub struct ConnectResponse {
    /// Server WireGuard public key.
    pub server_pubkey: String,
    /// Server endpoint to connect to, e.g. `vpn.example.com:51820`.
    pub endpoint:      String,
    /// Allocated client IPv4 as `/32` CIDR.
    pub client_ipv4:   Option<String>,
    /// Allocated client IPv6 as `/128` CIDR.
    pub client_ipv6:   Option<String>,
    /// Pre-shared key for this peer (base64).
    pub psk:           String,
    /// Allowed IPs to route through this tunnel.
    pub allowed_ips:   String,
    /// DNS server(s) for this tunnel.
    pub dns:           String,
    /// `"new"` — peer registered for the first time.
    /// `"existing"` — peer already registered, no changes.
    /// `"updated"` — peer already registered, settings updated.
    pub status:        String,
    /// Human-readable description of what changed (only non-empty when `status = "updated"`).
    pub changes:       Vec<String>,
}

/// Register or reconnect a WireGuard peer using a token.
///
/// On first call, allocates IP addresses and adds the peer to the live interface.
/// On repeat calls with the same public key, returns the existing config
/// (or applies updates if optional fields differ).
#[utoipa::path(
    post,
    path = "/v1/connect",
    tag = "Client",
    request_body = ConnectRequest,
    responses(
        (status = 200, description = "WireGuard client configuration", body = ConnectResponse),
        (status = 403, description = "Invalid/expired token or account suspended"),
        (status = 404, description = "Interface not found"),
        (status = 409, description = "Public key registered to a different account"),
        (status = 503, description = "No address space available"),
    )
)]
async fn connect(
    State(state): State<Arc<AppState>>,
    Json(req): Json<ConnectRequest>,
) -> ApiResult<Json<ConnectResponse>> {
    // Consume token → (principal_id, iface_id)
    let (principal_id, iface_id) = db::consume_token(&state.db, &req.token)?
        .ok_or_else(|| ApiError(anyhow::anyhow!("invalid or expired token"), StatusCode::FORBIDDEN))?;

    // Check principal is active
    let principal = db::get_principal(&state.db, principal_id)?
        .ok_or_else(not_found)?;
    if principal.status != "active" {
        return Err(ApiError(anyhow::anyhow!("account suspended"), StatusCode::FORBIDDEN));
    }

    // Load interface
    let iface = db::get_interface_by_id(&state.db, iface_id)?
        .ok_or_else(not_found)?;

    // Look up existing peer on this interface
    let existing = db::get_peer_on_iface(&state.db, &req.pubkey, iface_id)?;

    match existing {
        Some((peer, existing_principal_id)) => {
            // Public key registered to a different account
            if existing_principal_id != principal_id {
                return Err(conflict("public key already registered to another account"));
            }
            // Peer is revoked
            if peer.status == "revoked" {
                return Err(ApiError(
                    anyhow::anyhow!("peer has been revoked"),
                    StatusCode::FORBIDDEN,
                ));
            }
            // Active peer — diff and possibly update
            let mut changes = Vec::new();

            let new_psk  = req.psk.as_deref().unwrap_or(peer.psk.as_deref().unwrap_or(""));

            let ipv4_changed = req.client_ipv4.is_some()
                && req.client_ipv4.as_deref() != peer.ipv4.as_deref();
            let ipv6_changed = req.client_ipv6.is_some()
                && req.client_ipv6.as_deref() != peer.ipv6.as_deref();
            let psk_changed  = req.psk.is_some()
                && req.psk.as_deref() != peer.psk.as_deref();

            if ipv4_changed { changes.push(format!("ipv4: {:?} -> {:?}", peer.ipv4, req.client_ipv4)); }
            if ipv6_changed { changes.push(format!("ipv6: {:?} -> {:?}", peer.ipv6, req.client_ipv6)); }
            if psk_changed  { changes.push("psk updated".to_string()); }

            let status = if changes.is_empty() { "existing" } else { "updated" };

            let psk_out = if psk_changed {
                new_psk.to_string()
            } else {
                peer.psk.clone().unwrap_or_default()
            };

            Ok(Json(ConnectResponse {
                server_pubkey: iface.pubkey,
                endpoint:      iface.endpoint.unwrap_or_default(),
                client_ipv4:   if ipv4_changed { req.client_ipv4.clone() } else { peer.ipv4.clone() },
                client_ipv6:   if ipv6_changed { req.client_ipv6.clone() } else { peer.ipv6.clone() },
                psk:           psk_out,
                allowed_ips:   iface.allowed_ips.unwrap_or_default(),
                dns:           iface.dns.unwrap_or_default(),
                status:        status.to_string(),
                changes,
            }))
        }

        None => {
            // New peer — allocate IPs, generate PSK, insert
            let ipv4 = iface.address_v4.as_deref().and_then(|cidr| {
                crate::alloc::next_free_ipv4(&state.db, iface_id, cidr).ok()
            });
            let ipv6 = iface.address_v6.as_deref().and_then(|cidr| {
                crate::alloc::next_free_ipv6(&state.db, iface_id, cidr).ok()
            });

            if ipv4.is_none() && ipv6.is_none() {
                return Err(ApiError(
                    anyhow::anyhow!("no address space available"),
                    StatusCode::SERVICE_UNAVAILABLE,
                ));
            }

            let psk = wg::generate_psk();

            let new_peer = db::NewPeer {
                principal_id,
                iface_id,
                pubkey: req.pubkey.clone(),
                psk: Some(psk.clone()),
                ipv4: ipv4.clone(),
                ipv6: ipv6.clone(),
                label: req.label.clone(),
            };
            db::insert_peer(&state.db, &new_peer).map_err(|e| {
                if e.to_string().contains("UNIQUE") {
                    conflict("pubkey already registered")
                } else {
                    e.into()
                }
            })?;

            // Hot-add peer to live interface
            let peer = db::Peer {
                id: 0,
                principal_id,
                iface_id,
                pubkey: req.pubkey.clone(),
                psk: Some(psk.clone()),
                ipv4: ipv4.clone(),
                ipv6: ipv6.clone(),
                label: req.label.clone(),
                created: 0,
                last_seen: None,
                status: "active".into(),
            };
            let iface_name = iface.name.clone();
            tokio::task::spawn_blocking(move || wg::add_peer(&iface_name, &peer)).await??;

            Ok(Json(ConnectResponse {
                server_pubkey: iface.pubkey,
                endpoint:      iface.endpoint.unwrap_or_default(),
                client_ipv4:   ipv4,
                client_ipv6:   ipv6,
                psk,
                allowed_ips:   iface.allowed_ips.unwrap_or_default(),
                dns:           iface.dns.unwrap_or_default(),
                status:        "new".to_string(),
                changes:       vec![],
            }))
        }
    }
}

// ── Register handler (legacy) ─────────────────────────────────────────────────

#[derive(Deserialize, ToSchema)]
pub struct RegisterRequest {
    /// Client WireGuard public key (base64).
    pub pubkey: String,
    /// One-time registration token.
    pub token:  String,
    /// Human-readable label for this peer.
    pub label:  Option<String>,
}

#[derive(Serialize, ToSchema)]
pub struct RegisterResponse {
    /// Server WireGuard public key.
    pub server_pubkey: String,
    /// Server endpoint, e.g. `vpn.example.com:51820`.
    pub endpoint:      String,
    /// Allocated client IPv4 as `/32` CIDR.
    pub client_ipv4:   Option<String>,
    /// Allocated client IPv6 as `/128` CIDR.
    pub client_ipv6:   Option<String>,
    /// Pre-shared key for this peer (base64).
    pub psk:           String,
    /// Allowed IPs to route through this tunnel.
    pub allowed_ips:   String,
    /// DNS server(s) for this tunnel.
    pub dns:           String,
}

/// Legacy peer registration endpoint. Prefer `/v1/connect` for new clients.
///
/// Validates a one-time token, allocates IP addresses, and adds the peer
/// to the live WireGuard interface. Returns the client configuration.
#[utoipa::path(
    post,
    path = "/v1/register",
    tag = "Client",
    request_body = RegisterRequest,
    responses(
        (status = 200, description = "WireGuard client configuration", body = RegisterResponse),
        (status = 403, description = "Invalid/expired token or account suspended"),
        (status = 404, description = "Interface not found"),
        (status = 409, description = "Public key already registered"),
        (status = 503, description = "No address space available"),
    )
)]
async fn register(
    State(state): State<Arc<AppState>>,
    Json(req): Json<RegisterRequest>,
) -> ApiResult<Json<RegisterResponse>> {
    // Validate token
    let (principal_id, iface_id) = db::consume_token(&state.db, &req.token)?
        .ok_or_else(|| ApiError(anyhow::anyhow!("invalid or expired token"), StatusCode::FORBIDDEN))?;

    // Check principal is active
    let principal = db::get_principal(&state.db, principal_id)?
        .ok_or_else(not_found)?;
    if principal.status != "active" {
        return Err(ApiError(anyhow::anyhow!("account suspended"), StatusCode::FORBIDDEN));
    }

    // Load interface
    let iface = db::get_interface_by_id(&state.db, iface_id)?
        .ok_or_else(not_found)?;

    // Allocate IPs
    let ipv4 = iface.address_v4.as_deref().and_then(|cidr| {
        crate::alloc::next_free_ipv4(&state.db, iface_id, cidr).ok()
    });
    let ipv6 = iface.address_v6.as_deref().and_then(|cidr| {
        crate::alloc::next_free_ipv6(&state.db, iface_id, cidr).ok()
    });

    if ipv4.is_none() && ipv6.is_none() {
        return Err(ApiError(
            anyhow::anyhow!("no address space available"),
            StatusCode::SERVICE_UNAVAILABLE,
        ));
    }

    // Generate PSK
    let psk = wg::generate_psk();

    // Insert peer into DB
    let new_peer = db::NewPeer {
        principal_id,
        iface_id,
        pubkey: req.pubkey.clone(),
        psk: Some(psk.clone()),
        ipv4: ipv4.clone(),
        ipv6: ipv6.clone(),
        label: req.label.clone(),
    };
    db::insert_peer(&state.db, &new_peer).map_err(|e| {
        if e.to_string().contains("UNIQUE") {
            conflict("pubkey already registered")
        } else {
            e.into()
        }
    })?;

    // Hot-add peer to live interface
    let peer = db::Peer {
        id: 0,
        principal_id,
        iface_id,
        pubkey: req.pubkey.clone(),
        psk: Some(psk.clone()),
        ipv4: ipv4.clone(),
        ipv6: ipv6.clone(),
        label: req.label.clone(),
        created: 0,
        last_seen: None,
        status: "active".into(),
    };
    let iface_name = iface.name.clone();
    tokio::task::spawn_blocking(move || wg::add_peer(&iface_name, &peer)).await??;

    Ok(Json(RegisterResponse {
        server_pubkey: iface.pubkey,
        endpoint:      iface.endpoint.unwrap_or_default(),
        client_ipv4:   ipv4,
        client_ipv6:   ipv6,
        psk,
        allowed_ips:   iface.allowed_ips.unwrap_or_default(),
        dns:           iface.dns.unwrap_or_default(),
    }))
}

// ── Peer handlers ─────────────────────────────────────────────────────────────

/// List all active peers across all interfaces.
#[utoipa::path(
    get,
    path = "/v1/peers",
    tag = "Peers",
    security(("bearer_token" = [])),
    responses(
        (status = 200, description = "List of active peers", body = Vec<db::Peer>),
        (status = 401, description = "Unauthorized"),
    )
)]
async fn list_peers(State(state): State<Arc<AppState>>) -> ApiResult<Json<Vec<db::Peer>>> {
    Ok(Json(db::list_peers(&state.db)?))
}

#[derive(Deserialize, ToSchema)]
pub struct UpdatePeerBody {
    /// New human-readable label for this peer.
    label: String,
}

/// Update a peer's label.
#[utoipa::path(
    patch,
    path = "/v1/peers/{pubkey}",
    tag = "Peers",
    security(("bearer_token" = [])),
    params(
        ("pubkey" = String, Path, description = "Peer WireGuard public key (base64)"),
    ),
    request_body = UpdatePeerBody,
    responses(
        (status = 204, description = "Updated"),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Peer not found"),
    )
)]
async fn update_peer(
    State(state): State<Arc<AppState>>,
    Path(pubkey): Path<String>,
    Json(body): Json<UpdatePeerBody>,
) -> ApiResult<StatusCode> {
    if !db::update_peer_label(&state.db, &pubkey, &body.label)? {
        return Err(not_found());
    }
    Ok(StatusCode::NO_CONTENT)
}

/// Revoke a peer, removing it from the live WireGuard interface.
#[utoipa::path(
    delete,
    path = "/v1/peers/{pubkey}",
    tag = "Peers",
    security(("bearer_token" = [])),
    params(
        ("pubkey" = String, Path, description = "Peer WireGuard public key (base64)"),
    ),
    responses(
        (status = 204, description = "Revoked"),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Peer not found or already revoked"),
    )
)]
async fn revoke_peer(
    State(state): State<Arc<AppState>>,
    Path(pubkey): Path<String>,
) -> ApiResult<StatusCode> {
    if !db::revoke_peer(&state.db, &pubkey)? {
        return Err(not_found());
    }

    if let Some((iface_name, _)) = db::peer_iface_name(&state.db, &pubkey)? {
        let pk = pubkey.clone();
        tokio::task::spawn_blocking(move || wg::remove_peer(&iface_name, &pk)).await??;
    }

    tracing::info!("api: revoked peer {}", &pubkey[..8.min(pubkey.len())]);
    Ok(StatusCode::NO_CONTENT)
}

/// List all active peers for a principal.
#[utoipa::path(
    get,
    path = "/v1/principals/{id}/peers",
    tag = "Principals",
    security(("bearer_token" = [])),
    params(
        ("id" = i64, Path, description = "Principal ID"),
    ),
    responses(
        (status = 200, description = "List of active peers", body = Vec<db::Peer>),
        (status = 401, description = "Unauthorized"),
    )
)]
async fn list_principal_peers(
    State(state): State<Arc<AppState>>,
    Path(id): Path<i64>,
) -> ApiResult<Json<Vec<db::Peer>>> {
    Ok(Json(db::list_peers_for_principal(&state.db, id)?))
}

// ── Principal handlers ────────────────────────────────────────────────────────

/// List all principals.
#[utoipa::path(
    get,
    path = "/v1/principals",
    tag = "Principals",
    security(("bearer_token" = [])),
    responses(
        (status = 200, description = "List of principals", body = Vec<db::Principal>),
        (status = 401, description = "Unauthorized"),
    )
)]
async fn list_principals(
    State(state): State<Arc<AppState>>,
) -> ApiResult<Json<Vec<db::Principal>>> {
    Ok(Json(db::list_principals(&state.db)?))
}

/// Get a principal by ID.
#[utoipa::path(
    get,
    path = "/v1/principals/{id}",
    tag = "Principals",
    security(("bearer_token" = [])),
    params(
        ("id" = i64, Path, description = "Principal ID"),
    ),
    responses(
        (status = 200, description = "Principal", body = db::Principal),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Not found"),
    )
)]
async fn get_principal_handler(
    State(state): State<Arc<AppState>>,
    Path(id): Path<i64>,
) -> ApiResult<Json<db::Principal>> {
    Ok(Json(db::get_principal(&state.db, id)?.ok_or_else(not_found)?))
}

#[derive(Deserialize, ToSchema)]
pub struct CreatePrincipalBody {
    /// Optional explicit ID — preserves ID parity with an external identity store.
    id:       Option<i64>,
    /// Unique identity string (e.g. username or UUID from your identity provider).
    identity: String,
    /// Human-readable display name.
    label:    Option<String>,
}

/// Create or upsert a principal.
///
/// If a principal with the given `identity` already exists, returns the existing ID.
/// If `id` is provided, that row ID is used (idempotent with external identity stores).
#[utoipa::path(
    post,
    path = "/v1/principals",
    tag = "Principals",
    security(("bearer_token" = [])),
    request_body = CreatePrincipalBody,
    responses(
        (status = 200, description = "Principal ID", body = serde_json::Value,
            example = json!({"id": 42})),
        (status = 401, description = "Unauthorized"),
    )
)]
async fn create_principal(
    State(state): State<Arc<AppState>>,
    Json(body): Json<CreatePrincipalBody>,
) -> ApiResult<Json<serde_json::Value>> {
    let id = db::upsert_principal(&state.db, body.id, &body.identity, body.label.as_deref())
        .map_err(ApiError::from)?;
    Ok(Json(serde_json::json!({"id": id})))
}

#[derive(Deserialize, ToSchema)]
pub struct UpdatePrincipalBody {
    /// New status: `"active"` or `"suspended"`.
    /// Suspending revokes all peers immediately.
    status: Option<String>,
    /// New display name.
    label:  Option<String>,
}

/// Update a principal's status or label.
#[utoipa::path(
    patch,
    path = "/v1/principals/{id}",
    tag = "Principals",
    security(("bearer_token" = [])),
    params(
        ("id" = i64, Path, description = "Principal ID"),
    ),
    request_body = UpdatePrincipalBody,
    responses(
        (status = 204, description = "Updated"),
        (status = 400, description = "Invalid status value"),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Not found"),
    )
)]
async fn update_principal(
    State(state): State<Arc<AppState>>,
    Path(id): Path<i64>,
    Json(body): Json<UpdatePrincipalBody>,
) -> ApiResult<StatusCode> {
    if let Some(status) = &body.status {
        if status != "active" && status != "suspended" {
            return Err(bad_request("status must be 'active' or 'suspended'"));
        }
        if !db::update_principal_status(&state.db, id, status)? {
            return Err(not_found());
        }
    }
    if let Some(label) = &body.label {
        db::update_principal_label(&state.db, id, label)?;
    }
    Ok(StatusCode::NO_CONTENT)
}

/// Delete a principal and revoke all their peers and tokens.
#[utoipa::path(
    delete,
    path = "/v1/principals/{id}",
    tag = "Principals",
    security(("bearer_token" = [])),
    params(
        ("id" = i64, Path, description = "Principal ID"),
    ),
    responses(
        (status = 204, description = "Deleted"),
        (status = 401, description = "Unauthorized"),
    )
)]
async fn delete_principal(
    State(state): State<Arc<AppState>>,
    Path(id): Path<i64>,
) -> ApiResult<StatusCode> {
    let revoked_pubkeys = db::delete_principal(&state.db, id)?;

    for pubkey in revoked_pubkeys {
        if let Some((iface_name, _)) = db::peer_iface_name(&state.db, &pubkey)? {
            let pk = pubkey.clone();
            let _ = tokio::task::spawn_blocking(move || wg::remove_peer(&iface_name, &pk)).await;
        }
    }

    Ok(StatusCode::NO_CONTENT)
}

// ── Token handlers ────────────────────────────────────────────────────────────

/// List all tokens.
#[utoipa::path(
    get,
    path = "/v1/tokens",
    tag = "Tokens",
    security(("bearer_token" = [])),
    responses(
        (status = 200, description = "List of tokens", body = Vec<db::Token>),
        (status = 401, description = "Unauthorized"),
    )
)]
async fn list_tokens(State(state): State<Arc<AppState>>) -> ApiResult<Json<Vec<db::Token>>> {
    Ok(Json(db::list_tokens(&state.db)?))
}

#[derive(Deserialize, ToSchema)]
pub struct CreateTokenBody {
    /// Principal this token grants access for.
    principal_id: i64,
    /// Interface this token is valid for.
    iface_id:     i64,
    /// Number of times this token may be used. Omit for unlimited uses.
    uses_left:    Option<i64>,
    /// Unix timestamp after which the token is invalid. Omit for no expiry.
    expires:      Option<i64>,
}

/// Create a registration token for a principal and interface.
#[utoipa::path(
    post,
    path = "/v1/tokens",
    tag = "Tokens",
    security(("bearer_token" = [])),
    request_body = CreateTokenBody,
    responses(
        (status = 200, description = "Generated token", body = serde_json::Value,
            example = json!({"token": "a3f2..."})),
        (status = 401, description = "Unauthorized"),
    )
)]
async fn create_token(
    State(state): State<Arc<AppState>>,
    Json(body): Json<CreateTokenBody>,
) -> ApiResult<Json<serde_json::Value>> {
    let token = random_token();
    db::create_token(
        &state.db,
        &token,
        body.principal_id,
        body.iface_id,
        body.uses_left,
        body.expires,
    )?;
    Ok(Json(serde_json::json!({"token": token})))
}

/// Revoke and delete a token.
#[utoipa::path(
    delete,
    path = "/v1/tokens/{token}",
    tag = "Tokens",
    security(("bearer_token" = [])),
    params(
        ("token" = String, Path, description = "Token string"),
    ),
    responses(
        (status = 204, description = "Deleted"),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Token not found"),
    )
)]
async fn revoke_token(
    State(state): State<Arc<AppState>>,
    Path(token): Path<String>,
) -> ApiResult<StatusCode> {
    if !db::delete_token(&state.db, &token)? {
        return Err(not_found());
    }
    Ok(StatusCode::NO_CONTENT)
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn random_token() -> String {
    use rand::RngExt;
    let bytes: [u8; 32] = rand::rng().random();
    hex::encode(bytes)
}

/// Bring up a WireGuard interface that already exists in the DB.
/// Called on startup (main.rs) and after API creation.
pub async fn bring_up_interface(
    handle: &rtnetlink::Handle,
    db: &db::Db,
    iface: &db::Interface,
) -> anyhow::Result<()> {
    let index = net::create_link(handle, &iface.name).await?;

    let peers = db::list_peers_for_iface(db, iface.id)?;
    let iface_clone = iface.clone();
    tokio::task::spawn_blocking(move || wg::configure(&iface_clone, &peers)).await??;

    if let Some(cidr) = &iface.address_v4 {
        net::add_address(handle, index, cidr).await?;
    }
    if let Some(cidr) = &iface.address_v6 {
        net::add_address(handle, index, cidr).await?;
    }
    if let Some(mtu) = iface.mtu {
        net::set_mtu(handle, index, mtu as u32).await?;
    }
    net::link_up(handle, index).await?;

    tracing::info!("wgdb: {} is up (port {})", iface.name, iface.listen_port);
    Ok(())
}

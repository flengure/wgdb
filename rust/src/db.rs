use anyhow::{Context, Result};
use rusqlite::{Connection, params};
use std::sync::{Arc, Mutex};

pub type Db = Arc<Mutex<Connection>>;

pub fn open(path: &str) -> Result<Db> {
    let conn = Connection::open(path).context("open sqlite")?;
    conn.execute_batch(
        "PRAGMA journal_mode=WAL;
         PRAGMA foreign_keys=ON;
         PRAGMA synchronous=NORMAL;",
    )?;
    migrate(&conn)?;
    Ok(Arc::new(Mutex::new(conn)))
}

fn migrate(conn: &Connection) -> Result<()> {
    conn.execute_batch("CREATE TABLE IF NOT EXISTS schema_version (version INTEGER PRIMARY KEY);")?;

    // Collapse any duplicate rows (can happen if seed script and init binary both ran).
    // Take the MAX version seen, delete all rows, re-insert one canonical row.
    let version: i32 = conn.query_row(
        "SELECT COALESCE(MAX(version), 0) FROM schema_version",
        [],
        |r| r.get(0),
    )?;
    conn.execute_batch("DELETE FROM schema_version")?;
    conn.execute("INSERT INTO schema_version VALUES (?1)", params![version])?;

    if version < 1 {
        conn.execute_batch(SCHEMA_V1)?;
        conn.execute("UPDATE schema_version SET version = 1", [])?;
        tracing::info!("db: migrated to v1");
    }

    if version < 2 {
        // v2: recreate peers table with UNIQUE(pubkey, iface_id) composite constraint
        // (older DBs had UNIQUE(pubkey) only)
        conn.execute_batch(MIGRATION_V2)?;
        conn.execute("UPDATE schema_version SET version = 2", [])?;
        tracing::info!("db: migrated to v2");
    }

    if version < 3 {
        // v3: add `enabled` column to interfaces if not present (absent from early seed scripts)
        let has_enabled: bool = conn
            .query_row(
                "SELECT COUNT(*) FROM pragma_table_info('interfaces') WHERE name='enabled'",
                [],
                |r| r.get::<_, i64>(0),
            )
            .unwrap_or(0)
            != 0;
        if !has_enabled {
            conn.execute_batch(
                "ALTER TABLE interfaces ADD COLUMN enabled INTEGER NOT NULL DEFAULT 1;",
            )?;
        }
        conn.execute("UPDATE schema_version SET version = 3", [])?;
        tracing::info!("db: migrated to v3");
    }

    Ok(())
}

const SCHEMA_V1: &str = "
CREATE TABLE IF NOT EXISTS interfaces (
    id          INTEGER PRIMARY KEY,
    name        TEXT    NOT NULL UNIQUE,
    private_key TEXT    NOT NULL,
    pubkey      TEXT    NOT NULL,
    listen_port INTEGER NOT NULL DEFAULT 51820,
    address_v4  TEXT,
    address_v6  TEXT,
    mtu         INTEGER,
    dns         TEXT,
    endpoint    TEXT,
    allowed_ips TEXT,
    enabled     INTEGER NOT NULL DEFAULT 1,
    updated     INTEGER NOT NULL DEFAULT (unixepoch())
);

CREATE TABLE IF NOT EXISTS principals (
    id       INTEGER PRIMARY KEY,
    identity TEXT    NOT NULL UNIQUE,
    label    TEXT,
    status   TEXT    NOT NULL DEFAULT 'active',
    created  INTEGER NOT NULL DEFAULT (unixepoch())
);

CREATE TABLE IF NOT EXISTS peers (
    id           INTEGER PRIMARY KEY,
    principal_id INTEGER NOT NULL REFERENCES principals(id),
    iface_id     INTEGER NOT NULL REFERENCES interfaces(id),
    pubkey       TEXT    NOT NULL,
    psk          TEXT,
    ipv4         TEXT,
    ipv6         TEXT,
    label        TEXT,
    created      INTEGER NOT NULL DEFAULT (unixepoch()),
    last_seen    INTEGER,
    status       TEXT    NOT NULL DEFAULT 'active',
    UNIQUE(pubkey, iface_id)
);

CREATE TABLE IF NOT EXISTS tokens (
    id           INTEGER PRIMARY KEY,
    token        TEXT    NOT NULL UNIQUE,
    principal_id INTEGER NOT NULL REFERENCES principals(id),
    iface_id     INTEGER NOT NULL REFERENCES interfaces(id),
    uses_left    INTEGER,
    expires      INTEGER,
    created      INTEGER NOT NULL DEFAULT (unixepoch())
);
";

/// v2: fix peers unique constraint from UNIQUE(pubkey) to UNIQUE(pubkey, iface_id)
/// for DBs created before this migration existed.
const MIGRATION_V2: &str = "
CREATE TABLE IF NOT EXISTS peers_new (
    id           INTEGER PRIMARY KEY,
    principal_id INTEGER NOT NULL REFERENCES principals(id),
    iface_id     INTEGER NOT NULL REFERENCES interfaces(id),
    pubkey       TEXT    NOT NULL,
    psk          TEXT,
    ipv4         TEXT,
    ipv6         TEXT,
    label        TEXT,
    created      INTEGER NOT NULL DEFAULT (unixepoch()),
    last_seen    INTEGER,
    status       TEXT    NOT NULL DEFAULT 'active',
    UNIQUE(pubkey, iface_id)
);
INSERT OR IGNORE INTO peers_new
    SELECT id, principal_id, iface_id, pubkey, psk, ipv4, ipv6,
           label, created, last_seen, status
    FROM peers;
DROP TABLE peers;
ALTER TABLE peers_new RENAME TO peers;
";

// ── Row types ─────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, utoipa::ToSchema)]
pub struct Interface {
    pub id: i64,
    pub name: String,
    #[serde(skip_serializing)]
    pub private_key: String,
    pub pubkey: String,
    pub listen_port: i64,
    pub address_v4: Option<String>,
    pub address_v6: Option<String>,
    pub mtu: Option<i64>,
    pub dns: Option<String>,
    pub endpoint: Option<String>,
    pub allowed_ips: Option<String>,
    pub enabled: bool,
    pub updated: i64,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, utoipa::ToSchema)]
pub struct Principal {
    pub id: i64,
    pub identity: String,
    pub label: Option<String>,
    pub status: String,
    pub created: i64,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, utoipa::ToSchema)]
pub struct Peer {
    pub id: i64,
    pub principal_id: i64,
    pub iface_id: i64,
    pub pubkey: String,
    pub psk: Option<String>,
    pub ipv4: Option<String>,
    pub ipv6: Option<String>,
    pub label: Option<String>,
    pub created: i64,
    pub last_seen: Option<i64>,
    pub status: String,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, utoipa::ToSchema)]
pub struct Token {
    pub id: i64,
    pub token: String,
    pub principal_id: i64,
    pub iface_id: i64,
    pub uses_left: Option<i64>,
    pub expires: Option<i64>,
    pub created: i64,
}

pub struct NewInterface {
    pub name: String,
    pub private_key: String,
    pub pubkey: String,
    pub listen_port: i64,
    pub address_v4: Option<String>,
    pub address_v6: Option<String>,
    pub mtu: Option<i64>,
    pub dns: Option<String>,
    pub endpoint: Option<String>,
    pub allowed_ips: Option<String>,
    pub enabled: bool,
}

pub struct NewPeer {
    pub principal_id: i64,
    pub iface_id: i64,
    pub pubkey: String,
    pub psk: Option<String>,
    pub ipv4: Option<String>,
    pub ipv6: Option<String>,
    pub label: Option<String>,
}

// ── Interface queries ─────────────────────────────────────────────────────────

pub fn list_interfaces(db: &Db) -> Result<Vec<Interface>> {
    let conn = db.lock().unwrap();
    let mut stmt = conn.prepare(
        "SELECT id, name, private_key, pubkey, listen_port,
                address_v4, address_v6, mtu, dns, endpoint, allowed_ips, enabled, updated
         FROM interfaces ORDER BY name",
    )?;
    let rows = stmt.query_map([], row_to_interface)?;
    Ok(rows.collect::<rusqlite::Result<_>>()?)
}

pub fn get_interface(db: &Db, name: &str) -> Result<Option<Interface>> {
    let conn = db.lock().unwrap();
    let mut stmt = conn.prepare(
        "SELECT id, name, private_key, pubkey, listen_port,
                address_v4, address_v6, mtu, dns, endpoint, allowed_ips, enabled, updated
         FROM interfaces WHERE name = ?1",
    )?;
    let mut rows = stmt.query_map(params![name], row_to_interface)?;
    Ok(rows.next().transpose()?)
}

pub fn get_interface_by_id(db: &Db, id: i64) -> Result<Option<Interface>> {
    let conn = db.lock().unwrap();
    let mut stmt = conn.prepare(
        "SELECT id, name, private_key, pubkey, listen_port,
                address_v4, address_v6, mtu, dns, endpoint, allowed_ips, enabled, updated
         FROM interfaces WHERE id = ?1",
    )?;
    Ok(stmt
        .query_map(params![id], row_to_interface)?
        .next()
        .transpose()?)
}

pub fn insert_interface(db: &Db, iface: &NewInterface) -> Result<Interface> {
    let conn = db.lock().unwrap();
    conn.execute(
        "INSERT INTO interfaces
             (name, private_key, pubkey, listen_port, address_v4, address_v6,
              mtu, dns, endpoint, allowed_ips, enabled)
         VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11)",
        params![
            iface.name,
            iface.private_key,
            iface.pubkey,
            iface.listen_port,
            iface.address_v4,
            iface.address_v6,
            iface.mtu,
            iface.dns,
            iface.endpoint,
            iface.allowed_ips,
            iface.enabled as i64,
        ],
    )?;
    let id = conn.last_insert_rowid();
    let row = conn.query_row(
        "SELECT id, name, private_key, pubkey, listen_port,
                address_v4, address_v6, mtu, dns, endpoint, allowed_ips, enabled, updated
         FROM interfaces WHERE id = ?1",
        params![id],
        row_to_interface,
    )?;
    Ok(row)
}

/// Full update of all mutable fields by interface id.
pub fn update_interface(db: &Db, iface: &Interface) -> Result<bool> {
    let conn = db.lock().unwrap();
    let n = conn.execute(
        "UPDATE interfaces SET
             private_key=?1, pubkey=?2, listen_port=?3,
             address_v4=?4, address_v6=?5, mtu=?6,
             dns=?7, endpoint=?8, allowed_ips=?9,
             enabled=?10, updated=unixepoch()
         WHERE id=?11",
        params![
            iface.private_key,
            iface.pubkey,
            iface.listen_port,
            iface.address_v4,
            iface.address_v6,
            iface.mtu,
            iface.dns,
            iface.endpoint,
            iface.allowed_ips,
            iface.enabled as i64,
            iface.id,
        ],
    )?;
    Ok(n > 0)
}

/// Delete interface and cascade-revoke all its peers and tokens.
/// Returns the revoked active peer pubkeys (so caller can remove from kernel).
pub fn delete_interface(db: &Db, name: &str) -> Result<Option<Vec<String>>> {
    let conn = db.lock().unwrap();
    let iface_id: Option<i64> = conn
        .query_row(
            "SELECT id FROM interfaces WHERE name = ?1",
            params![name],
            |r| r.get(0),
        )
        .optional()?;
    let iface_id = match iface_id {
        None => return Ok(None),
        Some(id) => id,
    };
    let mut stmt =
        conn.prepare("SELECT pubkey FROM peers WHERE iface_id = ?1 AND status = 'active'")?;
    let pubkeys: Vec<String> = stmt
        .query_map(params![iface_id], |r| r.get(0))?
        .collect::<rusqlite::Result<_>>()?;
    conn.execute(
        "UPDATE peers SET status='revoked' WHERE iface_id=?1",
        params![iface_id],
    )?;
    conn.execute("DELETE FROM tokens WHERE iface_id=?1", params![iface_id])?;
    conn.execute("DELETE FROM interfaces WHERE id=?1", params![iface_id])?;
    Ok(Some(pubkeys))
}

fn row_to_interface(r: &rusqlite::Row) -> rusqlite::Result<Interface> {
    Ok(Interface {
        id: r.get(0)?,
        name: r.get(1)?,
        private_key: r.get(2)?,
        pubkey: r.get(3)?,
        listen_port: r.get(4)?,
        address_v4: r.get(5)?,
        address_v6: r.get(6)?,
        mtu: r.get(7)?,
        dns: r.get(8)?,
        endpoint: r.get(9)?,
        allowed_ips: r.get(10)?,
        enabled: r.get::<_, i64>(11)? != 0,
        updated: r.get(12)?,
    })
}

// ── Principal queries ─────────────────────────────────────────────────────────

pub fn list_principals(db: &Db) -> Result<Vec<Principal>> {
    let conn = db.lock().unwrap();
    let mut stmt = conn
        .prepare("SELECT id, identity, label, status, created FROM principals ORDER BY created")?;
    let rows = stmt.query_map([], row_to_principal)?;
    Ok(rows.collect::<rusqlite::Result<_>>()?)
}

pub fn get_principal(db: &Db, id: i64) -> Result<Option<Principal>> {
    let conn = db.lock().unwrap();
    let mut stmt =
        conn.prepare("SELECT id, identity, label, status, created FROM principals WHERE id = ?1")?;
    Ok(stmt
        .query_map(params![id], row_to_principal)?
        .next()
        .transpose()?)
}

/// Insert or ignore a principal by identity, returning its id.
/// If `explicit_id` is provided it is used as the row id (preserves parity with portal.db).
/// If the identity already exists the existing id is returned (idempotent).
pub fn upsert_principal(
    db: &Db,
    explicit_id: Option<i64>,
    identity: &str,
    label: Option<&str>,
) -> Result<i64> {
    let conn = db.lock().unwrap();
    if let Some(id) = explicit_id {
        conn.execute(
            "INSERT OR IGNORE INTO principals (id, identity, label) VALUES (?1, ?2, ?3)",
            params![id, identity, label],
        )?;
    } else {
        conn.execute(
            "INSERT OR IGNORE INTO principals (identity, label) VALUES (?1, ?2)",
            params![identity, label],
        )?;
    }
    Ok(conn.query_row(
        "SELECT id FROM principals WHERE identity = ?1",
        params![identity],
        |r| r.get(0),
    )?)
}

pub fn update_principal_label(db: &Db, id: i64, label: &str) -> Result<bool> {
    let conn = db.lock().unwrap();
    let n = conn.execute(
        "UPDATE principals SET label = ?1 WHERE id = ?2",
        params![label, id],
    )?;
    Ok(n > 0)
}

pub fn update_principal_status(db: &Db, id: i64, status: &str) -> Result<bool> {
    let conn = db.lock().unwrap();
    let n = conn.execute(
        "UPDATE principals SET status = ?1 WHERE id = ?2",
        params![status, id],
    )?;
    Ok(n > 0)
}

pub fn delete_principal(db: &Db, id: i64) -> Result<Vec<String>> {
    let conn = db.lock().unwrap();
    let mut stmt =
        conn.prepare("SELECT pubkey FROM peers WHERE principal_id = ?1 AND status = 'active'")?;
    let pubkeys: Vec<String> = stmt
        .query_map(params![id], |r| r.get(0))?
        .collect::<rusqlite::Result<_>>()?;

    conn.execute(
        "UPDATE peers SET status = 'revoked' WHERE principal_id = ?1",
        params![id],
    )?;
    conn.execute("DELETE FROM tokens WHERE principal_id = ?1", params![id])?;
    conn.execute("DELETE FROM principals WHERE id = ?1", params![id])?;
    Ok(pubkeys)
}

fn row_to_principal(r: &rusqlite::Row) -> rusqlite::Result<Principal> {
    Ok(Principal {
        id: r.get(0)?,
        identity: r.get(1)?,
        label: r.get(2)?,
        status: r.get(3)?,
        created: r.get(4)?,
    })
}

// ── Peer queries ──────────────────────────────────────────────────────────────

/// Returns (iface_name, iface_id) for the interface a peer belongs to.
pub fn peer_iface_name(db: &Db, pubkey: &str) -> Result<Option<(String, i64)>> {
    let conn = db.lock().unwrap();
    let result = conn.query_row(
        "SELECT i.name, i.id FROM peers p
         JOIN interfaces i ON i.id = p.iface_id
         WHERE p.pubkey = ?1",
        params![pubkey],
        |r| Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?)),
    );
    match result {
        Ok(v) => Ok(Some(v)),
        Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
        Err(e) => Err(e.into()),
    }
}

/// Returns (peer, principal_id) for a peer on a specific interface.
pub fn get_peer_on_iface(db: &Db, pubkey: &str, iface_id: i64) -> Result<Option<(Peer, i64)>> {
    let conn = db.lock().unwrap();
    let result = conn.query_row(
        "SELECT id, principal_id, iface_id, pubkey, psk, ipv4, ipv6,
                label, created, last_seen, status
         FROM peers WHERE pubkey = ?1 AND iface_id = ?2",
        params![pubkey, iface_id],
        |r| {
            let peer = row_to_peer(r)?;
            let principal_id = peer.principal_id;
            Ok((peer, principal_id))
        },
    );
    match result {
        Ok(v) => Ok(Some(v)),
        Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
        Err(e) => Err(e.into()),
    }
}

pub fn list_peers(db: &Db) -> Result<Vec<Peer>> {
    let conn = db.lock().unwrap();
    let mut stmt = conn.prepare(
        "SELECT id, principal_id, iface_id, pubkey, psk, ipv4, ipv6,
                label, created, last_seen, status
         FROM peers WHERE status = 'active' ORDER BY created",
    )?;
    let rows = stmt.query_map([], row_to_peer)?;
    Ok(rows.collect::<rusqlite::Result<_>>()?)
}

pub fn list_peers_for_iface(db: &Db, iface_id: i64) -> Result<Vec<Peer>> {
    let conn = db.lock().unwrap();
    let mut stmt = conn.prepare(
        "SELECT id, principal_id, iface_id, pubkey, psk, ipv4, ipv6,
                label, created, last_seen, status
         FROM peers WHERE iface_id = ?1 AND status = 'active' ORDER BY created",
    )?;
    let rows = stmt.query_map(params![iface_id], row_to_peer)?;
    Ok(rows.collect::<rusqlite::Result<_>>()?)
}

pub fn list_peers_for_principal(db: &Db, principal_id: i64) -> Result<Vec<Peer>> {
    let conn = db.lock().unwrap();
    let mut stmt = conn.prepare(
        "SELECT id, principal_id, iface_id, pubkey, psk, ipv4, ipv6,
                label, created, last_seen, status
         FROM peers WHERE principal_id = ?1 AND status = 'active' ORDER BY created",
    )?;
    let rows = stmt.query_map(params![principal_id], row_to_peer)?;
    Ok(rows.collect::<rusqlite::Result<_>>()?)
}

pub fn insert_peer(db: &Db, peer: &NewPeer) -> Result<i64> {
    let conn = db.lock().unwrap();
    conn.execute(
        "INSERT INTO peers (principal_id, iface_id, pubkey, psk, ipv4, ipv6, label)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        params![
            peer.principal_id,
            peer.iface_id,
            peer.pubkey,
            peer.psk,
            peer.ipv4,
            peer.ipv6,
            peer.label,
        ],
    )?;
    Ok(conn.last_insert_rowid())
}

pub fn revoke_peer(db: &Db, pubkey: &str) -> Result<bool> {
    let conn = db.lock().unwrap();
    let n = conn.execute(
        "UPDATE peers SET status = 'revoked' WHERE pubkey = ?1 AND status = 'active'",
        params![pubkey],
    )?;
    Ok(n > 0)
}

pub fn update_peer_label(db: &Db, pubkey: &str, label: &str) -> Result<bool> {
    let conn = db.lock().unwrap();
    let n = conn.execute(
        "UPDATE peers SET label = ?1 WHERE pubkey = ?2 AND status = 'active'",
        params![label, pubkey],
    )?;
    Ok(n > 0)
}

pub fn update_peer_last_seen(db: &Db, pubkey: &str, ts: i64) -> Result<()> {
    let conn = db.lock().unwrap();
    conn.execute(
        "UPDATE peers SET last_seen = ?1 WHERE pubkey = ?2",
        params![ts, pubkey],
    )?;
    Ok(())
}

fn row_to_peer(r: &rusqlite::Row) -> rusqlite::Result<Peer> {
    Ok(Peer {
        id: r.get(0)?,
        principal_id: r.get(1)?,
        iface_id: r.get(2)?,
        pubkey: r.get(3)?,
        psk: r.get(4)?,
        ipv4: r.get(5)?,
        ipv6: r.get(6)?,
        label: r.get(7)?,
        created: r.get(8)?,
        last_seen: r.get(9)?,
        status: r.get(10)?,
    })
}

// ── Token queries ─────────────────────────────────────────────────────────────

pub fn list_tokens(db: &Db) -> Result<Vec<Token>> {
    let conn = db.lock().unwrap();
    let mut stmt = conn.prepare(
        "SELECT id, token, principal_id, iface_id, uses_left, expires, created
         FROM tokens ORDER BY created",
    )?;
    let rows = stmt.query_map([], row_to_token)?;
    Ok(rows.collect::<rusqlite::Result<_>>()?)
}

pub fn create_token(
    db: &Db,
    token: &str,
    principal_id: i64,
    iface_id: i64,
    uses_left: Option<i64>,
    expires: Option<i64>,
) -> Result<i64> {
    let conn = db.lock().unwrap();
    conn.execute(
        "INSERT INTO tokens (token, principal_id, iface_id, uses_left, expires)
         VALUES (?1, ?2, ?3, ?4, ?5)",
        params![token, principal_id, iface_id, uses_left, expires],
    )?;
    Ok(conn.last_insert_rowid())
}

type TokenRow = (i64, i64, i64, Option<i64>, Option<i64>);

/// Validates a token and returns (principal_id, iface_id) if valid.
/// Decrements uses_left; deletes if it reaches 0.
pub fn consume_token(db: &Db, token: &str) -> Result<Option<(i64, i64)>> {
    let conn = db.lock().unwrap();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;

    let row: Option<TokenRow> = conn
        .query_row(
            "SELECT id, principal_id, iface_id, uses_left, expires
             FROM tokens WHERE token = ?1",
            params![token],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)),
        )
        .optional()?;

    let (id, principal_id, iface_id, uses_left, expires) = match row {
        None => return Ok(None),
        Some(r) => r,
    };

    // Check expiry
    if let Some(exp) = expires
        && now > exp
    {
        return Ok(None);
    }

    // Check and decrement uses_left
    if let Some(uses) = uses_left {
        if uses <= 0 {
            return Ok(None);
        }
        if uses == 1 {
            conn.execute("DELETE FROM tokens WHERE id = ?1", params![id])?;
        } else {
            conn.execute(
                "UPDATE tokens SET uses_left = uses_left - 1 WHERE id = ?1",
                params![id],
            )?;
        }
    }

    Ok(Some((principal_id, iface_id)))
}

pub fn delete_token(db: &Db, token: &str) -> Result<bool> {
    let conn = db.lock().unwrap();
    let n = conn.execute("DELETE FROM tokens WHERE token = ?1", params![token])?;
    Ok(n > 0)
}

fn row_to_token(r: &rusqlite::Row) -> rusqlite::Result<Token> {
    Ok(Token {
        id: r.get(0)?,
        token: r.get(1)?,
        principal_id: r.get(2)?,
        iface_id: r.get(3)?,
        uses_left: r.get(4)?,
        expires: r.get(5)?,
        created: r.get(6)?,
    })
}

// ── Extension trait for optional query results ────────────────────────────────

trait OptionalExt<T> {
    fn optional(self) -> rusqlite::Result<Option<T>>;
}

impl<T> OptionalExt<T> for rusqlite::Result<T> {
    fn optional(self) -> rusqlite::Result<Option<T>> {
        match self {
            Ok(v) => Ok(Some(v)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(e),
        }
    }
}

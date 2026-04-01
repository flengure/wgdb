package main

import (
	"database/sql"
	"fmt"
	"time"

	"github.com/jmoiron/sqlx"
	_ "modernc.org/sqlite"
)

// ── Row types ─────────────────────────────────────────────────────────────────

// Interface is stored in the DB with private_key hidden from JSON.
type Interface struct {
	ID         int64   `json:"id"          db:"id"`
	Name       string  `json:"name"        db:"name"`
	PrivateKey string  `json:"-"           db:"private_key"`
	Pubkey     string  `json:"pubkey"      db:"pubkey"`
	ListenPort int64   `json:"listen_port" db:"listen_port"`
	AddressV4  *string `json:"address_v4"  db:"address_v4"`
	AddressV6  *string `json:"address_v6"  db:"address_v6"`
	Mtu        *int64  `json:"mtu"         db:"mtu"`
	Dns        *string `json:"dns"         db:"dns"`
	Endpoint   *string `json:"endpoint"    db:"endpoint"`
	AllowedIPs *string `json:"allowed_ips" db:"allowed_ips"`
	Enabled    bool    `json:"enabled"     db:"enabled"`
	PreUp      *string `json:"pre_up"      db:"pre_up"`
	PostUp     *string `json:"post_up"     db:"post_up"`
	PreDown    *string `json:"pre_down"    db:"pre_down"`
	PostDown   *string `json:"post_down"   db:"post_down"`
	Updated    int64   `json:"updated"     db:"updated"`
}

type Principal struct {
	ID       int64   `json:"id"       db:"id"`
	Identity string  `json:"identity" db:"identity"`
	Label    *string `json:"label"    db:"label"`
	Status   string  `json:"status"   db:"status"`
	Created  int64   `json:"created"  db:"created"`
}

type Peer struct {
	ID          int64   `json:"id"           db:"id"`
	PrincipalID int64   `json:"principal_id" db:"principal_id"`
	IfaceID     int64   `json:"iface_id"     db:"iface_id"`
	Pubkey      string  `json:"pubkey"       db:"pubkey"`
	Psk         *string `json:"psk"          db:"psk"`
	Ipv4        *string `json:"ipv4"         db:"ipv4"`
	Ipv6        *string `json:"ipv6"         db:"ipv6"`
	Label       *string `json:"label"        db:"label"`
	Created     int64   `json:"created"      db:"created"`
	LastSeen    *int64  `json:"last_seen"    db:"last_seen"`
	Status      string  `json:"status"       db:"status"`
}

type Token struct {
	ID          int64  `json:"id"           db:"id"`
	Token       string `json:"token"        db:"token"`
	PrincipalID int64  `json:"principal_id" db:"principal_id"`
	IfaceID     int64  `json:"iface_id"     db:"iface_id"`
	UsesLeft    *int64 `json:"uses_left"    db:"uses_left"`
	Expires     *int64 `json:"expires"      db:"expires"`
	Created     int64  `json:"created"      db:"created"`
}

// ── Open + migrate ────────────────────────────────────────────────────────────

func openDB(path string) (*sqlx.DB, error) {
	db, err := sqlx.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("open sqlite %s: %w", path, err)
	}
	// single writer connection — prevents SQLITE_BUSY
	db.SetMaxOpenConns(1)
	if _, err := db.Exec(`PRAGMA journal_mode=WAL; PRAGMA foreign_keys=ON; PRAGMA synchronous=NORMAL;`); err != nil {
		return nil, fmt.Errorf("pragmas: %w", err)
	}
	if err := migrate(db); err != nil {
		return nil, fmt.Errorf("migrate: %w", err)
	}
	return db, nil
}

const schemaV1 = `
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
`

const migrationV2 = `
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
           label, created, last_seen, status FROM peers;
DROP TABLE peers;
ALTER TABLE peers_new RENAME TO peers;
`

func migrate(db *sqlx.DB) error {
	if _, err := db.Exec(`CREATE TABLE IF NOT EXISTS schema_version (version INTEGER PRIMARY KEY)`); err != nil {
		return err
	}
	var version int
	_ = db.QueryRow(`SELECT COALESCE(MAX(version),0) FROM schema_version`).Scan(&version)
	db.Exec(`DELETE FROM schema_version`)
	db.Exec(`INSERT INTO schema_version VALUES (?)`, version)

	if version < 1 {
		if _, err := db.Exec(schemaV1); err != nil {
			return fmt.Errorf("schema v1: %w", err)
		}
		db.Exec(`UPDATE schema_version SET version=1`)
	}
	if version < 2 {
		if _, err := db.Exec(migrationV2); err != nil {
			return fmt.Errorf("migration v2: %w", err)
		}
		db.Exec(`UPDATE schema_version SET version=2`)
	}
	if version < 3 {
		var hasEnabled int
		db.QueryRow(`SELECT COUNT(*) FROM pragma_table_info('interfaces') WHERE name='enabled'`).Scan(&hasEnabled)
		if hasEnabled == 0 {
			db.Exec(`ALTER TABLE interfaces ADD COLUMN enabled INTEGER NOT NULL DEFAULT 1`)
		}
		db.Exec(`UPDATE schema_version SET version=3`)
	}
	if version < 4 {
		for _, col := range []string{"pre_up", "post_up", "pre_down", "post_down"} {
			var cnt int
			db.QueryRow(`SELECT COUNT(*) FROM pragma_table_info('interfaces') WHERE name=?`, col).Scan(&cnt)
			if cnt == 0 {
				db.Exec(`ALTER TABLE interfaces ADD COLUMN ` + col + ` TEXT`)
			}
		}
		db.Exec(`UPDATE schema_version SET version=4`)
	}
	return nil
}

// ── Interface queries ─────────────────────────────────────────────────────────

func dbListInterfaces(db *sqlx.DB) ([]Interface, error) {
	rows := []Interface{}
	err := db.Select(&rows, `SELECT id,name,private_key,pubkey,listen_port,address_v4,address_v6,mtu,dns,endpoint,allowed_ips,enabled,pre_up,post_up,pre_down,post_down,updated FROM interfaces ORDER BY name`)
	return rows, err
}

func dbGetInterface(db *sqlx.DB, name string) (*Interface, error) {
	var row Interface
	err := db.Get(&row, `SELECT id,name,private_key,pubkey,listen_port,address_v4,address_v6,mtu,dns,endpoint,allowed_ips,enabled,pre_up,post_up,pre_down,post_down,updated FROM interfaces WHERE name=?`, name)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	return &row, err
}

func dbGetInterfaceByID(db *sqlx.DB, id int64) (*Interface, error) {
	var row Interface
	err := db.Get(&row, `SELECT id,name,private_key,pubkey,listen_port,address_v4,address_v6,mtu,dns,endpoint,allowed_ips,enabled,pre_up,post_up,pre_down,post_down,updated FROM interfaces WHERE id=?`, id)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	return &row, err
}

func dbInsertInterface(db *sqlx.DB, iface *Interface) (*Interface, error) {
	res, err := db.Exec(
		`INSERT INTO interfaces (name,private_key,pubkey,listen_port,address_v4,address_v6,mtu,dns,endpoint,allowed_ips,enabled,pre_up,post_up,pre_down,post_down) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		iface.Name, iface.PrivateKey, iface.Pubkey, iface.ListenPort,
		iface.AddressV4, iface.AddressV6, iface.Mtu, iface.Dns,
		iface.Endpoint, iface.AllowedIPs, iface.Enabled,
		iface.PreUp, iface.PostUp, iface.PreDown, iface.PostDown,
	)
	if err != nil {
		return nil, err
	}
	id, _ := res.LastInsertId()
	return dbGetInterfaceByID(db, id)
}

func dbUpdateInterface(db *sqlx.DB, iface *Interface) error {
	_, err := db.Exec(
		`UPDATE interfaces SET private_key=?,pubkey=?,listen_port=?,address_v4=?,address_v6=?,mtu=?,dns=?,endpoint=?,allowed_ips=?,enabled=?,pre_up=?,post_up=?,pre_down=?,post_down=?,updated=unixepoch() WHERE id=?`,
		iface.PrivateKey, iface.Pubkey, iface.ListenPort,
		iface.AddressV4, iface.AddressV6, iface.Mtu, iface.Dns,
		iface.Endpoint, iface.AllowedIPs, iface.Enabled,
		iface.PreUp, iface.PostUp, iface.PreDown, iface.PostDown, iface.ID,
	)
	return err
}

// dbDeleteInterface cascade-revokes peers/tokens and deletes the interface.
// Returns the revoked peer pubkeys (nil if not found).
func dbDeleteInterface(db *sqlx.DB, name string) ([]string, error) {
	var ifaceID int64
	err := db.QueryRow(`SELECT id FROM interfaces WHERE name=?`, name).Scan(&ifaceID)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var pubkeys []string
	rows, err := db.Query(`SELECT pubkey FROM peers WHERE iface_id=? AND status='active'`, ifaceID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var pk string
		rows.Scan(&pk)
		pubkeys = append(pubkeys, pk)
	}
	db.Exec(`UPDATE peers SET status='revoked' WHERE iface_id=?`, ifaceID)
	db.Exec(`DELETE FROM tokens WHERE iface_id=?`, ifaceID)
	db.Exec(`DELETE FROM interfaces WHERE id=?`, ifaceID)
	return pubkeys, nil
}

// ── Principal queries ─────────────────────────────────────────────────────────

func dbListPrincipals(db *sqlx.DB) ([]Principal, error) {
	rows := []Principal{}
	err := db.Select(&rows, `SELECT id,identity,label,status,created FROM principals ORDER BY created`)
	return rows, err
}

func dbGetPrincipal(db *sqlx.DB, id int64) (*Principal, error) {
	var row Principal
	err := db.Get(&row, `SELECT id,identity,label,status,created FROM principals WHERE id=?`, id)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	return &row, err
}

func dbUpsertPrincipal(db *sqlx.DB, explicitID *int64, identity string, label *string) (int64, error) {
	if explicitID != nil {
		db.Exec(`INSERT OR IGNORE INTO principals (id,identity,label) VALUES (?,?,?)`, *explicitID, identity, label)
	} else {
		db.Exec(`INSERT OR IGNORE INTO principals (identity,label) VALUES (?,?)`, identity, label)
	}
	var id int64
	err := db.QueryRow(`SELECT id FROM principals WHERE identity=?`, identity).Scan(&id)
	return id, err
}

func dbUpdatePrincipalStatus(db *sqlx.DB, id int64, status string) (bool, error) {
	res, err := db.Exec(`UPDATE principals SET status=? WHERE id=?`, status, id)
	if err != nil {
		return false, err
	}
	n, _ := res.RowsAffected()
	return n > 0, nil
}

func dbUpdatePrincipalLabel(db *sqlx.DB, id int64, label string) error {
	_, err := db.Exec(`UPDATE principals SET label=? WHERE id=?`, label, id)
	return err
}

func dbDeletePrincipal(db *sqlx.DB, id int64) ([]string, error) {
	var pubkeys []string
	rows, err := db.Query(`SELECT pubkey FROM peers WHERE principal_id=? AND status='active'`, id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var pk string
		rows.Scan(&pk)
		pubkeys = append(pubkeys, pk)
	}
	db.Exec(`UPDATE peers SET status='revoked' WHERE principal_id=?`, id)
	db.Exec(`DELETE FROM tokens WHERE principal_id=?`, id)
	db.Exec(`DELETE FROM principals WHERE id=?`, id)
	return pubkeys, nil
}

// ── Peer queries ──────────────────────────────────────────────────────────────

func dbListPeers(db *sqlx.DB) ([]Peer, error) {
	rows := []Peer{}
	err := db.Select(&rows, `SELECT id,principal_id,iface_id,pubkey,psk,ipv4,ipv6,label,created,last_seen,status FROM peers WHERE status='active' ORDER BY created`)
	return rows, err
}

func dbListPeersForIface(db *sqlx.DB, ifaceID int64) ([]Peer, error) {
	rows := []Peer{}
	err := db.Select(&rows, `SELECT id,principal_id,iface_id,pubkey,psk,ipv4,ipv6,label,created,last_seen,status FROM peers WHERE iface_id=? AND status='active' ORDER BY created`, ifaceID)
	return rows, err
}

func dbListPeersForPrincipal(db *sqlx.DB, principalID int64) ([]Peer, error) {
	rows := []Peer{}
	err := db.Select(&rows, `SELECT id,principal_id,iface_id,pubkey,psk,ipv4,ipv6,label,created,last_seen,status FROM peers WHERE principal_id=? AND status='active' ORDER BY created`, principalID)
	return rows, err
}

// dbGetPeerOnIface returns (peer, principalID) or (nil, 0) if not found.
func dbGetPeerOnIface(db *sqlx.DB, pubkey string, ifaceID int64) (*Peer, int64, error) {
	var row Peer
	err := db.Get(&row, `SELECT id,principal_id,iface_id,pubkey,psk,ipv4,ipv6,label,created,last_seen,status FROM peers WHERE pubkey=? AND iface_id=?`, pubkey, ifaceID)
	if err == sql.ErrNoRows {
		return nil, 0, nil
	}
	return &row, row.PrincipalID, err
}

// dbPeerIfaceName returns (ifaceName, ifaceID) for the interface a peer belongs to.
func dbPeerIfaceName(db *sqlx.DB, pubkey string) (string, int64, error) {
	var name string
	var id int64
	err := db.QueryRow(`SELECT i.name,i.id FROM peers p JOIN interfaces i ON i.id=p.iface_id WHERE p.pubkey=?`, pubkey).Scan(&name, &id)
	if err == sql.ErrNoRows {
		return "", 0, nil
	}
	return name, id, err
}

func dbInsertPeer(db *sqlx.DB, peer *Peer) (int64, error) {
	res, err := db.Exec(
		`INSERT INTO peers (principal_id,iface_id,pubkey,psk,ipv4,ipv6,label) VALUES (?,?,?,?,?,?,?)`,
		peer.PrincipalID, peer.IfaceID, peer.Pubkey, peer.Psk, peer.Ipv4, peer.Ipv6, peer.Label,
	)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

func dbRevokePeer(db *sqlx.DB, pubkey string) (bool, error) {
	res, err := db.Exec(`UPDATE peers SET status='revoked' WHERE pubkey=? AND status='active'`, pubkey)
	if err != nil {
		return false, err
	}
	n, _ := res.RowsAffected()
	return n > 0, nil
}

func dbUpdatePeerLabel(db *sqlx.DB, pubkey, label string) (bool, error) {
	res, err := db.Exec(`UPDATE peers SET label=? WHERE pubkey=? AND status='active'`, label, pubkey)
	if err != nil {
		return false, err
	}
	n, _ := res.RowsAffected()
	return n > 0, nil
}

func dbUpdatePeerLastSeen(db *sqlx.DB, pubkey string, ts int64) error {
	_, err := db.Exec(`UPDATE peers SET last_seen=? WHERE pubkey=?`, ts, pubkey)
	return err
}

// ── Token queries ─────────────────────────────────────────────────────────────

func dbListTokens(db *sqlx.DB) ([]Token, error) {
	rows := []Token{}
	err := db.Select(&rows, `SELECT id,token,principal_id,iface_id,uses_left,expires,created FROM tokens ORDER BY created`)
	return rows, err
}

func dbCreateToken(db *sqlx.DB, token string, principalID, ifaceID int64, usesLeft, expires *int64) (int64, error) {
	res, err := db.Exec(
		`INSERT INTO tokens (token,principal_id,iface_id,uses_left,expires) VALUES (?,?,?,?,?)`,
		token, principalID, ifaceID, usesLeft, expires,
	)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

// dbConsumeToken validates the token, decrements uses_left (deletes at 0).
// Returns (principalID, ifaceID, ok).
func dbConsumeToken(db *sqlx.DB, token string) (int64, int64, bool, error) {
	now := time.Now().Unix()

	var id, principalID, ifaceID int64
	var usesLeft, expires sql.NullInt64
	err := db.QueryRow(
		`SELECT id,principal_id,iface_id,uses_left,expires FROM tokens WHERE token=?`, token,
	).Scan(&id, &principalID, &ifaceID, &usesLeft, &expires)
	if err == sql.ErrNoRows {
		return 0, 0, false, nil
	}
	if err != nil {
		return 0, 0, false, err
	}
	if expires.Valid && now > expires.Int64 {
		return 0, 0, false, nil
	}
	if usesLeft.Valid {
		if usesLeft.Int64 <= 0 {
			return 0, 0, false, nil
		}
		if usesLeft.Int64 == 1 {
			db.Exec(`DELETE FROM tokens WHERE id=?`, id)
		} else {
			db.Exec(`UPDATE tokens SET uses_left=uses_left-1 WHERE id=?`, id)
		}
	}
	return principalID, ifaceID, true, nil
}

func dbDeleteToken(db *sqlx.DB, token string) (bool, error) {
	res, err := db.Exec(`DELETE FROM tokens WHERE token=?`, token)
	if err != nil {
		return false, err
	}
	n, _ := res.RowsAffected()
	return n > 0, nil
}

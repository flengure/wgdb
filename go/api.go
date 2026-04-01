package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/jmoiron/sqlx"
)

// ── App state ─────────────────────────────────────────────────────────────────

type AppState struct {
	db         *sqlx.DB
	wg         *WGManager
	adminToken string
}

// ── Router ────────────────────────────────────────────────────────────────────

func setupRouter(state *AppState) *gin.Engine {
	gin.SetMode(gin.ReleaseMode)
	r := gin.New()
	r.Use(gin.Recovery())

	// Public endpoints
	r.POST("/v1/register", state.register)
	r.POST("/v1/connect", state.connect)

	// Admin endpoints (bearer token required)
	admin := r.Group("/v1", state.bearerAuth())

	// Interfaces
	admin.GET("/interfaces", state.listInterfaces)
	admin.POST("/interfaces", state.createInterface)
	admin.GET("/interfaces/:name", state.getInterface)
	admin.PATCH("/interfaces/:name", state.updateInterface)
	admin.DELETE("/interfaces/:name", state.deleteInterface)

	// Peers
	admin.GET("/peers", state.listPeers)
	admin.PATCH("/peers/:pubkey", state.updatePeer)
	admin.DELETE("/peers/:pubkey", state.revokePeer)

	// Principals
	admin.GET("/principals", state.listPrincipals)
	admin.POST("/principals", state.createPrincipal)
	admin.GET("/principals/:id", state.getPrincipal)
	admin.PATCH("/principals/:id", state.updatePrincipal)
	admin.DELETE("/principals/:id", state.deletePrincipal)
	admin.GET("/principals/:id/peers", state.listPrincipalPeers)
	admin.POST("/principals/:id/session", state.createSession)

	// Tokens
	admin.GET("/tokens", state.listTokens)
	admin.POST("/tokens", state.createToken)
	admin.DELETE("/tokens/:token", state.revokeToken)

	return r
}

// ── Auth middleware ───────────────────────────────────────────────────────────

func (s *AppState) bearerAuth() gin.HandlerFunc {
	return func(c *gin.Context) {
		auth := c.GetHeader("Authorization")
		token, ok := strings.CutPrefix(auth, "Bearer ")
		if !ok || token != s.adminToken {
			c.AbortWithStatus(http.StatusUnauthorized)
			return
		}
		c.Next()
	}
}

// ── Error helpers ─────────────────────────────────────────────────────────────

func apiErr(c *gin.Context, status int, msg string) {
	c.JSON(status, gin.H{"error": msg})
}

func apiServerErr(c *gin.Context, err error) {
	slog.Error("api error", "err", err)
	c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
}

// ── Interface handlers ────────────────────────────────────────────────────────

func (s *AppState) listInterfaces(c *gin.Context) {
	ifaces, err := dbListInterfaces(s.db)
	if err != nil {
		apiServerErr(c, err)
		return
	}
	c.JSON(http.StatusOK, ifaces)
}

type CreateInterfaceBody struct {
	Name       string  `json:"name"`
	ListenPort *int64  `json:"listen_port"`
	AddressV4  *string `json:"address_v4"`
	AddressV6  *string `json:"address_v6"`
	Mtu        *int64  `json:"mtu"`
	Dns        *string `json:"dns"`
	Endpoint   *string `json:"endpoint"`
	AllowedIPs *string `json:"allowed_ips"`
	PrivateKey *string `json:"private_key"`
	Enabled    *bool   `json:"enabled"`
}

func (s *AppState) createInterface(c *gin.Context) {
	var body CreateInterfaceBody
	if err := c.ShouldBindJSON(&body); err != nil {
		apiErr(c, http.StatusBadRequest, err.Error())
		return
	}
	if body.Name == "" || !validIfName(body.Name) {
		apiErr(c, http.StatusBadRequest, "name must be non-empty alphanumeric/hyphen/underscore")
		return
	}

	listenPort := int64(51820)
	if body.ListenPort != nil {
		listenPort = *body.ListenPort
	}
	enabled := true
	if body.Enabled != nil {
		enabled = *body.Enabled
	}

	var privB64, pubB64 string
	var err error
	if body.PrivateKey != nil {
		privB64, pubB64, err = ImportPrivateKey(*body.PrivateKey)
		if err != nil {
			apiErr(c, http.StatusBadRequest, "invalid private_key")
			return
		}
	} else {
		privB64, pubB64, err = GenerateKeypair()
		if err != nil {
			apiServerErr(c, err)
			return
		}
	}

	iface := &Interface{
		Name: body.Name, PrivateKey: privB64, Pubkey: pubB64,
		ListenPort: listenPort, AddressV4: body.AddressV4, AddressV6: body.AddressV6,
		Mtu: body.Mtu, Dns: body.Dns, Endpoint: body.Endpoint,
		AllowedIPs: body.AllowedIPs, Enabled: enabled,
	}
	created, err := dbInsertInterface(s.db, iface)
	if err != nil {
		if strings.Contains(err.Error(), "UNIQUE") {
			apiErr(c, http.StatusConflict, "interface name already exists")
			return
		}
		apiServerErr(c, err)
		return
	}

	if enabled {
		if err := s.wg.BringUpInterface(s.db, created); err != nil {
			slog.Warn("bring up interface", "name", created.Name, "err", err)
		}
	}

	slog.Info("created interface", "name", created.Name, "enabled", enabled)
	c.JSON(http.StatusOK, created)
}

func (s *AppState) getInterface(c *gin.Context) {
	name := c.Param("name")
	iface, err := dbGetInterface(s.db, name)
	if err != nil {
		apiServerErr(c, err)
		return
	}
	if iface == nil {
		c.Status(http.StatusNotFound)
		return
	}

	// Augment with live stats if available
	stats, _ := s.wg.Stats(name)

	type response struct {
		*Interface
		PeerCount *int    `json:"peer_count,omitempty"`
		RxBytes   *uint64 `json:"rx_bytes,omitempty"`
		TxBytes   *uint64 `json:"tx_bytes,omitempty"`
	}
	resp := response{Interface: iface}
	if stats != nil {
		resp.PeerCount = &stats.PeerCount
		resp.RxBytes = &stats.RxBytes
		resp.TxBytes = &stats.TxBytes
	}
	c.JSON(http.StatusOK, resp)
}

func (s *AppState) updateInterface(c *gin.Context) {
	name := c.Param("name")
	iface, err := dbGetInterface(s.db, name)
	if err != nil {
		apiServerErr(c, err)
		return
	}
	if iface == nil {
		c.Status(http.StatusNotFound)
		return
	}

	// Use raw map to distinguish absent vs explicit null.
	var raw map[string]json.RawMessage
	if err := c.ShouldBindJSON(&raw); err != nil {
		apiErr(c, http.StatusBadRequest, err.Error())
		return
	}

	wasEnabled := iface.Enabled
	portChanged := false
	addrChanged := false
	mtuChanged := false

	if v, ok := raw["listen_port"]; ok {
		var p int64
		if err := json.Unmarshal(v, &p); err == nil {
			portChanged = p != iface.ListenPort
			iface.ListenPort = p
		}
	}
	if _, ok := raw["address_v4"]; ok {
		addrChanged = true
		iface.AddressV4 = jsonNullableString(raw["address_v4"])
	}
	if _, ok := raw["address_v6"]; ok {
		addrChanged = true
		iface.AddressV6 = jsonNullableString(raw["address_v6"])
	}
	if _, ok := raw["mtu"]; ok {
		mtuChanged = true
		iface.Mtu = jsonNullableInt64(raw["mtu"])
	}
	if _, ok := raw["dns"]; ok {
		iface.Dns = jsonNullableString(raw["dns"])
	}
	if _, ok := raw["endpoint"]; ok {
		iface.Endpoint = jsonNullableString(raw["endpoint"])
	}
	if _, ok := raw["allowed_ips"]; ok {
		iface.AllowedIPs = jsonNullableString(raw["allowed_ips"])
	}
	if v, ok := raw["enabled"]; ok {
		var b bool
		json.Unmarshal(v, &b)
		iface.Enabled = b
	}

	if err := dbUpdateInterface(s.db, iface); err != nil {
		apiServerErr(c, err)
		return
	}

	if !wasEnabled && iface.Enabled {
		if err := s.wg.BringUpInterface(s.db, iface); err != nil {
			slog.Warn("bring up interface", "name", name, "err", err)
		}
	} else if wasEnabled && !iface.Enabled {
		if err := s.wg.DeleteLink(name); err != nil {
			slog.Warn("delete link", "name", name, "err", err)
		}
	} else if iface.Enabled {
		if portChanged {
			peers, _ := dbListPeersForIface(s.db, iface.ID)
			if err := s.wg.Configure(name, iface, peers); err != nil {
				slog.Warn("configure interface", "name", name, "err", err)
			}
		}
		if addrChanged {
			if err := s.wg.FlushAndReaddresses(iface); err != nil {
				slog.Warn("flush/readd addresses", "name", name, "err", err)
			}
		}
		if mtuChanged && iface.Mtu != nil {
			if err := s.wg.SetMTU(name, int(*iface.Mtu)); err != nil {
				slog.Warn("set mtu", "name", name, "err", err)
			}
		}
	}

	slog.Info("updated interface", "name", name)
	c.JSON(http.StatusOK, iface)
}

func (s *AppState) deleteInterface(c *gin.Context) {
	name := c.Param("name")
	s.wg.DeleteLink(name) // best-effort; ignore error
	pubkeys, err := dbDeleteInterface(s.db, name)
	if err != nil {
		apiServerErr(c, err)
		return
	}
	if pubkeys == nil {
		c.Status(http.StatusNotFound)
		return
	}
	slog.Info("deleted interface", "name", name, "peers_revoked", len(pubkeys))
	c.Status(http.StatusNoContent)
}

// ── Session handler ───────────────────────────────────────────────────────────

func (s *AppState) createSession(c *gin.Context) {
	id, err := strconv.ParseInt(c.Param("id"), 10, 64)
	if err != nil {
		apiErr(c, http.StatusBadRequest, "invalid id")
		return
	}
	var body struct {
		IfaceID int64 `json:"iface_id"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		apiErr(c, http.StatusBadRequest, err.Error())
		return
	}
	principal, err := dbGetPrincipal(s.db, id)
	if err != nil {
		apiServerErr(c, err)
		return
	}
	if principal == nil {
		c.Status(http.StatusNotFound)
		return
	}
	if principal.Status != "active" {
		apiErr(c, http.StatusForbidden, "account suspended")
		return
	}

	now := unixNow()
	expires := now + 7200
	token := randomToken()
	if _, err := dbCreateToken(s.db, token, id, body.IfaceID, nil, &expires); err != nil {
		apiServerErr(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"token": token, "expires": expires})
}

// ── Connect handler ───────────────────────────────────────────────────────────

type ConnectRequest struct {
	Token      string  `json:"token"`
	Pubkey     string  `json:"pubkey"`
	Label      *string `json:"label"`
	ClientIPv4 *string `json:"client_ipv4"`
	ClientIPv6 *string `json:"client_ipv6"`
	Psk        *string `json:"psk"`
}

type ConnectResponse struct {
	ServerPubkey string   `json:"server_pubkey"`
	Endpoint     string   `json:"endpoint"`
	ClientIPv4   *string  `json:"client_ipv4"`
	ClientIPv6   *string  `json:"client_ipv6"`
	Psk          string   `json:"psk"`
	AllowedIPs   string   `json:"allowed_ips"`
	Dns          string   `json:"dns"`
	Status       string   `json:"status"`
	Changes      []string `json:"changes"`
}

func (s *AppState) connect(c *gin.Context) {
	var req ConnectRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		apiErr(c, http.StatusBadRequest, err.Error())
		return
	}

	principalID, ifaceID, ok, err := dbConsumeToken(s.db, req.Token)
	if err != nil {
		apiServerErr(c, err)
		return
	}
	if !ok {
		apiErr(c, http.StatusForbidden, "invalid or expired token")
		return
	}

	principal, err := dbGetPrincipal(s.db, principalID)
	if err != nil || principal == nil {
		c.Status(http.StatusNotFound)
		return
	}
	if principal.Status != "active" {
		apiErr(c, http.StatusForbidden, "account suspended")
		return
	}

	iface, err := dbGetInterfaceByID(s.db, ifaceID)
	if err != nil || iface == nil {
		c.Status(http.StatusNotFound)
		return
	}

	existing, existingPrincipalID, err := dbGetPeerOnIface(s.db, req.Pubkey, ifaceID)
	if err != nil {
		apiServerErr(c, err)
		return
	}

	if existing != nil {
		if existingPrincipalID != principalID {
			apiErr(c, http.StatusConflict, "public key already registered to another account")
			return
		}
		if existing.Status == "revoked" {
			apiErr(c, http.StatusForbidden, "peer has been revoked")
			return
		}

		changes := []string{}
		ipv4Changed := req.ClientIPv4 != nil && derefStr(req.ClientIPv4) != derefStr(existing.Ipv4)
		ipv6Changed := req.ClientIPv6 != nil && derefStr(req.ClientIPv6) != derefStr(existing.Ipv6)
		pskChanged := req.Psk != nil && derefStr(req.Psk) != derefStr(existing.Psk)

		if ipv4Changed {
			changes = append(changes, fmt.Sprintf("ipv4: %v -> %v", existing.Ipv4, req.ClientIPv4))
		}
		if ipv6Changed {
			changes = append(changes, fmt.Sprintf("ipv6: %v -> %v", existing.Ipv6, req.ClientIPv6))
		}
		if pskChanged {
			changes = append(changes, "psk updated")
		}

		status := "existing"
		if len(changes) > 0 {
			status = "updated"
		}

		outPsk := derefStr(existing.Psk)
		if pskChanged {
			outPsk = derefStr(req.Psk)
		}
		outIPv4 := existing.Ipv4
		if ipv4Changed {
			outIPv4 = req.ClientIPv4
		}
		outIPv6 := existing.Ipv6
		if ipv6Changed {
			outIPv6 = req.ClientIPv6
		}

		c.JSON(http.StatusOK, ConnectResponse{
			ServerPubkey: iface.Pubkey,
			Endpoint:     derefStr(iface.Endpoint),
			ClientIPv4:   outIPv4,
			ClientIPv6:   outIPv6,
			Psk:          outPsk,
			AllowedIPs:   derefStr(iface.AllowedIPs),
			Dns:          derefStr(iface.Dns),
			Status:       status,
			Changes:      changes,
		})
		return
	}

	// New peer — allocate IPs, generate PSK, insert
	var ipv4, ipv6 *string
	if iface.AddressV4 != nil {
		if addr, err := nextFreeIPv4(s.db, ifaceID, *iface.AddressV4); err == nil {
			ipv4 = &addr
		}
	}
	if iface.AddressV6 != nil {
		if addr, err := nextFreeIPv6(s.db, ifaceID, *iface.AddressV6); err == nil {
			ipv6 = &addr
		}
	}
	if ipv4 == nil && ipv6 == nil {
		apiErr(c, http.StatusServiceUnavailable, "no address space available")
		return
	}

	psk, err := GeneratePSK()
	if err != nil {
		apiServerErr(c, err)
		return
	}

	newPeer := &Peer{
		PrincipalID: principalID, IfaceID: ifaceID,
		Pubkey: req.Pubkey, Psk: &psk,
		Ipv4: ipv4, Ipv6: ipv6, Label: req.Label,
	}
	if _, err := dbInsertPeer(s.db, newPeer); err != nil {
		if strings.Contains(err.Error(), "UNIQUE") {
			apiErr(c, http.StatusConflict, "pubkey already registered")
			return
		}
		apiServerErr(c, err)
		return
	}

	if err := s.wg.AddPeer(iface.Name, newPeer); err != nil {
		slog.Warn("add peer to interface", "iface", iface.Name, "err", err)
	}

	slog.Info("connected peer", "iface", iface.Name, "pubkey", req.Pubkey[:min(8, len(req.Pubkey))])
	c.JSON(http.StatusOK, ConnectResponse{
		ServerPubkey: iface.Pubkey,
		Endpoint:     derefStr(iface.Endpoint),
		ClientIPv4:   ipv4,
		ClientIPv6:   ipv6,
		Psk:          psk,
		AllowedIPs:   derefStr(iface.AllowedIPs),
		Dns:          derefStr(iface.Dns),
		Status:       "new",
		Changes:      []string{},
	})
}

// ── Register handler (legacy) ─────────────────────────────────────────────────

type RegisterRequest struct {
	Pubkey string  `json:"pubkey"`
	Token  string  `json:"token"`
	Label  *string `json:"label"`
}

type RegisterResponse struct {
	ServerPubkey string  `json:"server_pubkey"`
	Endpoint     string  `json:"endpoint"`
	ClientIPv4   *string `json:"client_ipv4"`
	ClientIPv6   *string `json:"client_ipv6"`
	Psk          string  `json:"psk"`
	AllowedIPs   string  `json:"allowed_ips"`
	Dns          string  `json:"dns"`
}

func (s *AppState) register(c *gin.Context) {
	var req RegisterRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		apiErr(c, http.StatusBadRequest, err.Error())
		return
	}

	principalID, ifaceID, ok, err := dbConsumeToken(s.db, req.Token)
	if err != nil {
		apiServerErr(c, err)
		return
	}
	if !ok {
		apiErr(c, http.StatusForbidden, "invalid or expired token")
		return
	}

	principal, err := dbGetPrincipal(s.db, principalID)
	if err != nil || principal == nil {
		c.Status(http.StatusNotFound)
		return
	}
	if principal.Status != "active" {
		apiErr(c, http.StatusForbidden, "account suspended")
		return
	}

	iface, err := dbGetInterfaceByID(s.db, ifaceID)
	if err != nil || iface == nil {
		c.Status(http.StatusNotFound)
		return
	}

	var ipv4, ipv6 *string
	if iface.AddressV4 != nil {
		if addr, err := nextFreeIPv4(s.db, ifaceID, *iface.AddressV4); err == nil {
			ipv4 = &addr
		}
	}
	if iface.AddressV6 != nil {
		if addr, err := nextFreeIPv6(s.db, ifaceID, *iface.AddressV6); err == nil {
			ipv6 = &addr
		}
	}
	if ipv4 == nil && ipv6 == nil {
		apiErr(c, http.StatusServiceUnavailable, "no address space available")
		return
	}

	psk, err := GeneratePSK()
	if err != nil {
		apiServerErr(c, err)
		return
	}

	newPeer := &Peer{
		PrincipalID: principalID, IfaceID: ifaceID,
		Pubkey: req.Pubkey, Psk: &psk,
		Ipv4: ipv4, Ipv6: ipv6, Label: req.Label,
	}
	if _, err := dbInsertPeer(s.db, newPeer); err != nil {
		if strings.Contains(err.Error(), "UNIQUE") {
			apiErr(c, http.StatusConflict, "pubkey already registered")
			return
		}
		apiServerErr(c, err)
		return
	}

	if err := s.wg.AddPeer(iface.Name, newPeer); err != nil {
		slog.Warn("add peer to interface", "iface", iface.Name, "err", err)
	}

	c.JSON(http.StatusOK, RegisterResponse{
		ServerPubkey: iface.Pubkey,
		Endpoint:     derefStr(iface.Endpoint),
		ClientIPv4:   ipv4,
		ClientIPv6:   ipv6,
		Psk:          psk,
		AllowedIPs:   derefStr(iface.AllowedIPs),
		Dns:          derefStr(iface.Dns),
	})
}

// ── Peer handlers ─────────────────────────────────────────────────────────────

func (s *AppState) listPeers(c *gin.Context) {
	peers, err := dbListPeers(s.db)
	if err != nil {
		apiServerErr(c, err)
		return
	}
	c.JSON(http.StatusOK, peers)
}

func (s *AppState) updatePeer(c *gin.Context) {
	pubkey := c.Param("pubkey")
	var body struct {
		Label string `json:"label"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		apiErr(c, http.StatusBadRequest, err.Error())
		return
	}
	ok, err := dbUpdatePeerLabel(s.db, pubkey, body.Label)
	if err != nil {
		apiServerErr(c, err)
		return
	}
	if !ok {
		c.Status(http.StatusNotFound)
		return
	}
	c.Status(http.StatusNoContent)
}

func (s *AppState) revokePeer(c *gin.Context) {
	pubkey := c.Param("pubkey")
	ok, err := dbRevokePeer(s.db, pubkey)
	if err != nil {
		apiServerErr(c, err)
		return
	}
	if !ok {
		c.Status(http.StatusNotFound)
		return
	}
	if ifaceName, _, err := dbPeerIfaceName(s.db, pubkey); err == nil && ifaceName != "" {
		if err := s.wg.RemovePeer(ifaceName, pubkey); err != nil {
			slog.Warn("remove peer from interface", "iface", ifaceName, "err", err)
		}
	}
	slog.Info("revoked peer", "pubkey", pubkey[:min(8, len(pubkey))])
	c.Status(http.StatusNoContent)
}

func (s *AppState) listPrincipalPeers(c *gin.Context) {
	id, err := strconv.ParseInt(c.Param("id"), 10, 64)
	if err != nil {
		apiErr(c, http.StatusBadRequest, "invalid id")
		return
	}
	peers, err := dbListPeersForPrincipal(s.db, id)
	if err != nil {
		apiServerErr(c, err)
		return
	}
	c.JSON(http.StatusOK, peers)
}

// ── Principal handlers ────────────────────────────────────────────────────────

func (s *AppState) listPrincipals(c *gin.Context) {
	principals, err := dbListPrincipals(s.db)
	if err != nil {
		apiServerErr(c, err)
		return
	}
	c.JSON(http.StatusOK, principals)
}

func (s *AppState) getPrincipal(c *gin.Context) {
	id, err := strconv.ParseInt(c.Param("id"), 10, 64)
	if err != nil {
		apiErr(c, http.StatusBadRequest, "invalid id")
		return
	}
	p, err := dbGetPrincipal(s.db, id)
	if err != nil {
		apiServerErr(c, err)
		return
	}
	if p == nil {
		c.Status(http.StatusNotFound)
		return
	}
	c.JSON(http.StatusOK, p)
}

func (s *AppState) createPrincipal(c *gin.Context) {
	var body struct {
		ID       *int64  `json:"id"`
		Identity string  `json:"identity"`
		Label    *string `json:"label"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		apiErr(c, http.StatusBadRequest, err.Error())
		return
	}
	id, err := dbUpsertPrincipal(s.db, body.ID, body.Identity, body.Label)
	if err != nil {
		apiServerErr(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"id": id})
}

func (s *AppState) updatePrincipal(c *gin.Context) {
	id, err := strconv.ParseInt(c.Param("id"), 10, 64)
	if err != nil {
		apiErr(c, http.StatusBadRequest, "invalid id")
		return
	}
	var body struct {
		Status *string `json:"status"`
		Label  *string `json:"label"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		apiErr(c, http.StatusBadRequest, err.Error())
		return
	}
	if body.Status != nil {
		if *body.Status != "active" && *body.Status != "suspended" {
			apiErr(c, http.StatusBadRequest, "status must be 'active' or 'suspended'")
			return
		}
		ok, err := dbUpdatePrincipalStatus(s.db, id, *body.Status)
		if err != nil {
			apiServerErr(c, err)
			return
		}
		if !ok {
			c.Status(http.StatusNotFound)
			return
		}
	}
	if body.Label != nil {
		if err := dbUpdatePrincipalLabel(s.db, id, *body.Label); err != nil {
			apiServerErr(c, err)
			return
		}
	}
	c.Status(http.StatusNoContent)
}

func (s *AppState) deletePrincipal(c *gin.Context) {
	id, err := strconv.ParseInt(c.Param("id"), 10, 64)
	if err != nil {
		apiErr(c, http.StatusBadRequest, "invalid id")
		return
	}
	pubkeys, err := dbDeletePrincipal(s.db, id)
	if err != nil {
		apiServerErr(c, err)
		return
	}
	for _, pk := range pubkeys {
		if ifaceName, _, err := dbPeerIfaceName(s.db, pk); err == nil && ifaceName != "" {
			s.wg.RemovePeer(ifaceName, pk)
		}
	}
	c.Status(http.StatusNoContent)
}

// ── Token handlers ────────────────────────────────────────────────────────────

func (s *AppState) listTokens(c *gin.Context) {
	tokens, err := dbListTokens(s.db)
	if err != nil {
		apiServerErr(c, err)
		return
	}
	c.JSON(http.StatusOK, tokens)
}

func (s *AppState) createToken(c *gin.Context) {
	var body struct {
		PrincipalID int64  `json:"principal_id"`
		IfaceID     int64  `json:"iface_id"`
		UsesLeft    *int64 `json:"uses_left"`
		Expires     *int64 `json:"expires"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		apiErr(c, http.StatusBadRequest, err.Error())
		return
	}
	token := randomToken()
	if _, err := dbCreateToken(s.db, token, body.PrincipalID, body.IfaceID, body.UsesLeft, body.Expires); err != nil {
		apiServerErr(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"token": token})
}

func (s *AppState) revokeToken(c *gin.Context) {
	token := c.Param("token")
	ok, err := dbDeleteToken(s.db, token)
	if err != nil {
		apiServerErr(c, err)
		return
	}
	if !ok {
		c.Status(http.StatusNotFound)
		return
	}
	c.Status(http.StatusNoContent)
}

// ── Helpers ───────────────────────────────────────────────────────────────────

func validIfName(name string) bool {
	for _, r := range name {
		if !((r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') ||
			(r >= '0' && r <= '9') || r == '-' || r == '_') {
			return false
		}
	}
	return true
}

func randomToken() string {
	b := make([]byte, 32)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func derefStr(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

// jsonNullableString decodes a json.RawMessage as *string.
// "null" → nil, `"value"` → &"value".
func jsonNullableString(raw json.RawMessage) *string {
	if string(raw) == "null" {
		return nil
	}
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		return &s
	}
	return nil
}

// jsonNullableInt64 decodes a json.RawMessage as *int64.
func jsonNullableInt64(raw json.RawMessage) *int64 {
	if string(raw) == "null" {
		return nil
	}
	var n int64
	if err := json.Unmarshal(raw, &n); err == nil {
		return &n
	}
	return nil
}

func unixNow() int64 {
	return timeNow().Unix()
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

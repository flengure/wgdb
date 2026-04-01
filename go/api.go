package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"reflect"
	"strings"

	"github.com/danielgtaylor/huma/v2"
	"github.com/danielgtaylor/huma/v2/adapters/humachi"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/jmoiron/sqlx"
)

// OmittableNullable distinguishes absent (not sent) vs null vs a value.
type OmittableNullable[T any] struct {
	Sent  bool
	Null  bool
	Value T
}

func (o *OmittableNullable[T]) UnmarshalJSON(b []byte) error {
	if len(b) > 0 {
		o.Sent = true
		if string(b) == "null" {
			o.Null = true
			return nil
		}
		return json.Unmarshal(b, &o.Value)
	}
	return nil
}

func (o OmittableNullable[T]) Schema(r huma.Registry) *huma.Schema {
	s := r.Schema(reflect.TypeOf(o.Value), true, "")
	s.Nullable = true
	return s
}

func (o OmittableNullable[T]) IsOmitted() bool { return !o.Sent }
func (o OmittableNullable[T]) IsNull() bool     { return o.Sent && o.Null }
func (o OmittableNullable[T]) Get() (T, bool)   { return o.Value, o.Sent && !o.Null }

// ── App state ─────────────────────────────────────────────────────────────────

type AppState struct {
	db         *sqlx.DB
	wg         *WGManager
	adminToken string
}

// ── Router ────────────────────────────────────────────────────────────────────

func setupRouter(state *AppState) http.Handler {
	r := chi.NewRouter()
	r.Use(middleware.Recoverer)

	api := humachi.New(r, huma.DefaultConfig("wgdb API", "1.0.0"))

	// Public endpoints
	huma.Register(api, huma.Operation{
		OperationID: "register",
		Method:      http.MethodPost,
		Path:        "/v1/register",
	}, state.register)

	huma.Register(api, huma.Operation{
		OperationID: "connect",
		Method:      http.MethodPost,
		Path:        "/v1/connect",
	}, state.connect)

	// Admin subrouter with bearer token middleware
	ar := chi.NewRouter()
	ar.Use(state.bearerAuth)
	r.Mount("/", ar)

	adminAPI := humachi.New(ar, huma.DefaultConfig("wgdb API", "1.0.0"))

	// Interfaces
	huma.Register(adminAPI, huma.Operation{
		OperationID: "list-interfaces",
		Method:      http.MethodGet,
		Path:        "/v1/interfaces",
	}, state.listInterfaces)

	huma.Register(adminAPI, huma.Operation{
		OperationID: "create-interface",
		Method:      http.MethodPost,
		Path:        "/v1/interfaces",
	}, state.createInterface)

	huma.Register(adminAPI, huma.Operation{
		OperationID: "get-interface",
		Method:      http.MethodGet,
		Path:        "/v1/interfaces/{name}",
	}, state.getInterface)

	huma.Register(adminAPI, huma.Operation{
		OperationID: "update-interface",
		Method:      http.MethodPatch,
		Path:        "/v1/interfaces/{name}",
	}, state.updateInterface)

	huma.Register(adminAPI, huma.Operation{
		OperationID: "delete-interface",
		Method:      http.MethodDelete,
		Path:        "/v1/interfaces/{name}",
	}, state.deleteInterface)

	huma.Register(adminAPI, huma.Operation{
		OperationID: "import-interface",
		Method:      http.MethodPost,
		Path:        "/v1/interfaces/import",
	}, state.importInterface)

	huma.Register(adminAPI, huma.Operation{
		OperationID: "export-interface",
		Method:      http.MethodGet,
		Path:        "/v1/interfaces/{name}/export",
	}, state.exportInterface)

	// Peers
	huma.Register(adminAPI, huma.Operation{
		OperationID: "list-peers",
		Method:      http.MethodGet,
		Path:        "/v1/peers",
	}, state.listPeers)

	huma.Register(adminAPI, huma.Operation{
		OperationID: "update-peer",
		Method:      http.MethodPatch,
		Path:        "/v1/peers/{pubkey}",
	}, state.updatePeer)

	huma.Register(adminAPI, huma.Operation{
		OperationID: "revoke-peer",
		Method:      http.MethodDelete,
		Path:        "/v1/peers/{pubkey}",
	}, state.revokePeer)

	// Principals
	huma.Register(adminAPI, huma.Operation{
		OperationID: "list-principals",
		Method:      http.MethodGet,
		Path:        "/v1/principals",
	}, state.listPrincipals)

	huma.Register(adminAPI, huma.Operation{
		OperationID: "create-principal",
		Method:      http.MethodPost,
		Path:        "/v1/principals",
	}, state.createPrincipal)

	huma.Register(adminAPI, huma.Operation{
		OperationID: "get-principal",
		Method:      http.MethodGet,
		Path:        "/v1/principals/{id}",
	}, state.getPrincipal)

	huma.Register(adminAPI, huma.Operation{
		OperationID: "update-principal",
		Method:      http.MethodPatch,
		Path:        "/v1/principals/{id}",
	}, state.updatePrincipal)

	huma.Register(adminAPI, huma.Operation{
		OperationID: "delete-principal",
		Method:      http.MethodDelete,
		Path:        "/v1/principals/{id}",
	}, state.deletePrincipal)

	huma.Register(adminAPI, huma.Operation{
		OperationID: "list-principal-peers",
		Method:      http.MethodGet,
		Path:        "/v1/principals/{id}/peers",
	}, state.listPrincipalPeers)

	huma.Register(adminAPI, huma.Operation{
		OperationID: "create-session",
		Method:      http.MethodPost,
		Path:        "/v1/principals/{id}/session",
	}, state.createSession)

	// Tokens
	huma.Register(adminAPI, huma.Operation{
		OperationID: "list-tokens",
		Method:      http.MethodGet,
		Path:        "/v1/tokens",
	}, state.listTokens)

	huma.Register(adminAPI, huma.Operation{
		OperationID: "create-token",
		Method:      http.MethodPost,
		Path:        "/v1/tokens",
	}, state.createToken)

	huma.Register(adminAPI, huma.Operation{
		OperationID: "revoke-token",
		Method:      http.MethodDelete,
		Path:        "/v1/tokens/{token}",
	}, state.revokeToken)

	return r
}

// ── Auth middleware ───────────────────────────────────────────────────────────

func (s *AppState) bearerAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		token, ok := strings.CutPrefix(auth, "Bearer ")
		if !ok || token != s.adminToken {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// ── Interface handlers ────────────────────────────────────────────────────────

type ListInterfacesOutput struct {
	Body []Interface
}

func (s *AppState) listInterfaces(_ context.Context, _ *struct{}) (*ListInterfacesOutput, error) {
	ifaces, err := dbListInterfaces(s.db)
	if err != nil {
		return nil, huma.Error500InternalServerError(err.Error())
	}
	if ifaces == nil {
		ifaces = []Interface{}
	}
	return &ListInterfacesOutput{Body: ifaces}, nil
}

type CreateInterfaceInput struct {
	Body struct {
		Name       string  `json:"name"`
		ListenPort *int64  `json:"listen_port,omitempty"`
		AddressV4  *string `json:"address_v4,omitempty"`
		AddressV6  *string `json:"address_v6,omitempty"`
		Mtu        *int64  `json:"mtu,omitempty"`
		Dns        *string `json:"dns,omitempty"`
		Endpoint   *string `json:"endpoint,omitempty"`
		AllowedIPs *string `json:"allowed_ips,omitempty"`
		PrivateKey *string `json:"private_key,omitempty"`
		Enabled    *bool   `json:"enabled,omitempty"`
		PreUp      *string `json:"pre_up,omitempty"`
		PostUp     *string `json:"post_up,omitempty"`
		PreDown    *string `json:"pre_down,omitempty"`
		PostDown   *string `json:"post_down,omitempty"`
	}
}

type InterfaceOutput struct {
	Body *Interface
}

func (s *AppState) createInterface(_ context.Context, input *CreateInterfaceInput) (*InterfaceOutput, error) {
	body := input.Body
	if body.Name == "" || !validIfName(body.Name) {
		return nil, huma.Error400BadRequest("name must be non-empty alphanumeric/hyphen/underscore")
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
			return nil, huma.Error400BadRequest("invalid private_key")
		}
	} else {
		privB64, pubB64, err = GenerateKeypair()
		if err != nil {
			return nil, huma.Error500InternalServerError(err.Error())
		}
	}

	iface := &Interface{
		Name: body.Name, PrivateKey: privB64, Pubkey: pubB64,
		ListenPort: listenPort, AddressV4: body.AddressV4, AddressV6: body.AddressV6,
		Mtu: body.Mtu, Dns: body.Dns, Endpoint: body.Endpoint,
		AllowedIPs: body.AllowedIPs, Enabled: enabled,
		PreUp: body.PreUp, PostUp: body.PostUp, PreDown: body.PreDown, PostDown: body.PostDown,
	}
	created, err := dbInsertInterface(s.db, iface)
	if err != nil {
		if strings.Contains(err.Error(), "UNIQUE") {
			return nil, huma.Error409Conflict("interface name already exists")
		}
		return nil, huma.Error500InternalServerError(err.Error())
	}

	if enabled {
		if err := s.wg.BringUpInterface(s.db, created); err != nil {
			slog.Warn("bring up interface", "name", created.Name, "err", err)
		}
	}

	slog.Info("created interface", "name", created.Name, "enabled", enabled)
	return &InterfaceOutput{Body: created}, nil
}

type InterfaceNameParam struct {
	Name string `path:"name"`
}

type GetInterfaceOutput struct {
	Body struct {
		*Interface
		PeerCount *int    `json:"peer_count,omitempty"`
		RxBytes   *uint64 `json:"rx_bytes,omitempty"`
		TxBytes   *uint64 `json:"tx_bytes,omitempty"`
	}
}

func (s *AppState) getInterface(_ context.Context, input *InterfaceNameParam) (*GetInterfaceOutput, error) {
	iface, err := dbGetInterface(s.db, input.Name)
	if err != nil {
		return nil, huma.Error500InternalServerError(err.Error())
	}
	if iface == nil {
		return nil, huma.Error404NotFound("interface not found")
	}

	out := &GetInterfaceOutput{}
	out.Body.Interface = iface
	stats, _ := s.wg.Stats(input.Name)
	if stats != nil {
		out.Body.PeerCount = &stats.PeerCount
		out.Body.RxBytes = &stats.RxBytes
		out.Body.TxBytes = &stats.TxBytes
	}
	return out, nil
}

type UpdateInterfaceInput struct {
	Name string `path:"name"`
	Body struct {
		ListenPort OmittableNullable[int64]  `json:"listen_port,omitempty"`
		AddressV4  OmittableNullable[string] `json:"address_v4,omitempty"`
		AddressV6  OmittableNullable[string] `json:"address_v6,omitempty"`
		Mtu        OmittableNullable[int64]  `json:"mtu,omitempty"`
		Dns        OmittableNullable[string] `json:"dns,omitempty"`
		Endpoint   OmittableNullable[string] `json:"endpoint,omitempty"`
		AllowedIPs OmittableNullable[string] `json:"allowed_ips,omitempty"`
		Enabled    OmittableNullable[bool]   `json:"enabled,omitempty"`
		PreUp      OmittableNullable[string] `json:"pre_up,omitempty"`
		PostUp     OmittableNullable[string] `json:"post_up,omitempty"`
		PreDown    OmittableNullable[string] `json:"pre_down,omitempty"`
		PostDown   OmittableNullable[string] `json:"post_down,omitempty"`
	}
}

func (s *AppState) updateInterface(_ context.Context, input *UpdateInterfaceInput) (*InterfaceOutput, error) {
	iface, err := dbGetInterface(s.db, input.Name)
	if err != nil {
		return nil, huma.Error500InternalServerError(err.Error())
	}
	if iface == nil {
		return nil, huma.Error404NotFound("interface not found")
	}

	wasEnabled := iface.Enabled
	portChanged := false
	addrChanged := false
	mtuChanged := false

	body := input.Body
	if !body.ListenPort.IsNull() && !body.ListenPort.IsOmitted() {
		v, _ := body.ListenPort.Get()
		portChanged = v != iface.ListenPort
		iface.ListenPort = v
	}
	if !body.AddressV4.IsOmitted() {
		addrChanged = true
		if body.AddressV4.IsNull() {
			iface.AddressV4 = nil
		} else {
			v, _ := body.AddressV4.Get()
			iface.AddressV4 = &v
		}
	}
	if !body.AddressV6.IsOmitted() {
		addrChanged = true
		if body.AddressV6.IsNull() {
			iface.AddressV6 = nil
		} else {
			v, _ := body.AddressV6.Get()
			iface.AddressV6 = &v
		}
	}
	if !body.Mtu.IsOmitted() {
		mtuChanged = true
		if body.Mtu.IsNull() {
			iface.Mtu = nil
		} else {
			v, _ := body.Mtu.Get()
			iface.Mtu = &v
		}
	}
	if !body.Dns.IsOmitted() {
		if body.Dns.IsNull() {
			iface.Dns = nil
		} else {
			v, _ := body.Dns.Get()
			iface.Dns = &v
		}
	}
	if !body.Endpoint.IsOmitted() {
		if body.Endpoint.IsNull() {
			iface.Endpoint = nil
		} else {
			v, _ := body.Endpoint.Get()
			iface.Endpoint = &v
		}
	}
	if !body.AllowedIPs.IsOmitted() {
		if body.AllowedIPs.IsNull() {
			iface.AllowedIPs = nil
		} else {
			v, _ := body.AllowedIPs.Get()
			iface.AllowedIPs = &v
		}
	}
	if !body.Enabled.IsOmitted() && !body.Enabled.IsNull() {
		v, _ := body.Enabled.Get()
		iface.Enabled = v
	}
	if !body.PreUp.IsOmitted() {
		if body.PreUp.IsNull() {
			iface.PreUp = nil
		} else {
			v, _ := body.PreUp.Get()
			iface.PreUp = &v
		}
	}
	if !body.PostUp.IsOmitted() {
		if body.PostUp.IsNull() {
			iface.PostUp = nil
		} else {
			v, _ := body.PostUp.Get()
			iface.PostUp = &v
		}
	}
	if !body.PreDown.IsOmitted() {
		if body.PreDown.IsNull() {
			iface.PreDown = nil
		} else {
			v, _ := body.PreDown.Get()
			iface.PreDown = &v
		}
	}
	if !body.PostDown.IsOmitted() {
		if body.PostDown.IsNull() {
			iface.PostDown = nil
		} else {
			v, _ := body.PostDown.Get()
			iface.PostDown = &v
		}
	}

	if err := dbUpdateInterface(s.db, iface); err != nil {
		return nil, huma.Error500InternalServerError(err.Error())
	}

	if !wasEnabled && iface.Enabled {
		if err := s.wg.BringUpInterface(s.db, iface); err != nil {
			slog.Warn("bring up interface", "name", input.Name, "err", err)
		}
	} else if wasEnabled && !iface.Enabled {
		if err := s.wg.DeleteLinkWithHooks(input.Name, iface); err != nil {
			slog.Warn("delete link", "name", input.Name, "err", err)
		}
	} else if iface.Enabled {
		if portChanged {
			peers, _ := dbListPeersForIface(s.db, iface.ID)
			if err := s.wg.Configure(input.Name, iface, peers); err != nil {
				slog.Warn("configure interface", "name", input.Name, "err", err)
			}
		}
		if addrChanged {
			if err := s.wg.FlushAndReaddresses(iface); err != nil {
				slog.Warn("flush/readd addresses", "name", input.Name, "err", err)
			}
		}
		if mtuChanged && iface.Mtu != nil {
			if err := s.wg.SetMTU(input.Name, int(*iface.Mtu)); err != nil {
				slog.Warn("set mtu", "name", input.Name, "err", err)
			}
		}
	}

	slog.Info("updated interface", "name", input.Name)
	return &InterfaceOutput{Body: iface}, nil
}

type DeleteInterfaceOutput struct {
	Status int
}

func (s *AppState) deleteInterface(_ context.Context, input *InterfaceNameParam) (*struct{}, error) {
	iface, _ := dbGetInterface(s.db, input.Name)
	s.wg.DeleteLinkWithHooks(input.Name, iface)
	pubkeys, err := dbDeleteInterface(s.db, input.Name)
	if err != nil {
		return nil, huma.Error500InternalServerError(err.Error())
	}
	if pubkeys == nil {
		return nil, huma.Error404NotFound("interface not found")
	}
	slog.Info("deleted interface", "name", input.Name, "peers_revoked", len(pubkeys))
	return nil, nil
}

// ── Session handler ───────────────────────────────────────────────────────────

type CreateSessionInput struct {
	ID   int64 `path:"id"`
	Body struct {
		IfaceID int64 `json:"iface_id"`
	}
}

type CreateSessionOutput struct {
	Body struct {
		Token   string `json:"token"`
		Expires int64  `json:"expires"`
	}
}

func (s *AppState) createSession(_ context.Context, input *CreateSessionInput) (*CreateSessionOutput, error) {
	principal, err := dbGetPrincipal(s.db, input.ID)
	if err != nil {
		return nil, huma.Error500InternalServerError(err.Error())
	}
	if principal == nil {
		return nil, huma.Error404NotFound("principal not found")
	}
	if principal.Status != "active" {
		return nil, huma.Error403Forbidden("account suspended")
	}

	now := unixNow()
	expires := now + 7200
	token := randomToken()
	if _, err := dbCreateToken(s.db, token, input.ID, input.Body.IfaceID, nil, &expires); err != nil {
		return nil, huma.Error500InternalServerError(err.Error())
	}
	out := &CreateSessionOutput{}
	out.Body.Token = token
	out.Body.Expires = expires
	return out, nil
}

// ── Connect handler ───────────────────────────────────────────────────────────

type ConnectRequest struct {
	Token      string  `json:"token"`
	Pubkey     string  `json:"pubkey"`
	Label      *string `json:"label,omitempty"`
	ClientIPv4 *string `json:"client_ipv4,omitempty"`
	ClientIPv6 *string `json:"client_ipv6,omitempty"`
	Psk        *string `json:"psk,omitempty"`
}

type ConnectResponse struct {
	ServerPubkey string   `json:"server_pubkey"`
	Endpoint     string   `json:"endpoint"`
	ClientIPv4   *string  `json:"client_ipv4,omitempty"`
	ClientIPv6   *string  `json:"client_ipv6,omitempty"`
	Psk          string   `json:"psk"`
	AllowedIPs   string   `json:"allowed_ips"`
	Dns          string   `json:"dns"`
	Status       string   `json:"status"`
	Changes      []string `json:"changes"`
}

type ConnectInput struct {
	Body ConnectRequest
}

type ConnectOutput struct {
	Body ConnectResponse
}

func (s *AppState) connect(_ context.Context, input *ConnectInput) (*ConnectOutput, error) {
	req := input.Body

	principalID, ifaceID, ok, err := dbConsumeToken(s.db, req.Token)
	if err != nil {
		return nil, huma.Error500InternalServerError(err.Error())
	}
	if !ok {
		return nil, huma.Error403Forbidden("invalid or expired token")
	}

	principal, err := dbGetPrincipal(s.db, principalID)
	if err != nil || principal == nil {
		return nil, huma.Error404NotFound("principal not found")
	}
	if principal.Status != "active" {
		return nil, huma.Error403Forbidden("account suspended")
	}

	iface, err := dbGetInterfaceByID(s.db, ifaceID)
	if err != nil || iface == nil {
		return nil, huma.Error404NotFound("interface not found")
	}

	existing, existingPrincipalID, err := dbGetPeerOnIface(s.db, req.Pubkey, ifaceID)
	if err != nil {
		return nil, huma.Error500InternalServerError(err.Error())
	}

	if existing != nil {
		if existingPrincipalID != principalID {
			return nil, huma.Error409Conflict("public key already registered to another account")
		}
		if existing.Status == "revoked" {
			return nil, huma.Error403Forbidden("peer has been revoked")
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

		return &ConnectOutput{Body: ConnectResponse{
			ServerPubkey: iface.Pubkey,
			Endpoint:     derefStr(iface.Endpoint),
			ClientIPv4:   outIPv4,
			ClientIPv6:   outIPv6,
			Psk:          outPsk,
			AllowedIPs:   derefStr(iface.AllowedIPs),
			Dns:          derefStr(iface.Dns),
			Status:       status,
			Changes:      changes,
		}}, nil
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
		return nil, huma.Error503ServiceUnavailable("no address space available")
	}

	psk, err := GeneratePSK()
	if err != nil {
		return nil, huma.Error500InternalServerError(err.Error())
	}

	newPeer := &Peer{
		PrincipalID: principalID, IfaceID: ifaceID,
		Pubkey: req.Pubkey, Psk: &psk,
		Ipv4: ipv4, Ipv6: ipv6, Label: req.Label,
	}
	if _, err := dbInsertPeer(s.db, newPeer); err != nil {
		if strings.Contains(err.Error(), "UNIQUE") {
			return nil, huma.Error409Conflict("pubkey already registered")
		}
		return nil, huma.Error500InternalServerError(err.Error())
	}

	if err := s.wg.AddPeer(iface.Name, newPeer); err != nil {
		slog.Warn("add peer to interface", "iface", iface.Name, "err", err)
	}

	slog.Info("connected peer", "iface", iface.Name, "pubkey", req.Pubkey[:min(8, len(req.Pubkey))])
	return &ConnectOutput{Body: ConnectResponse{
		ServerPubkey: iface.Pubkey,
		Endpoint:     derefStr(iface.Endpoint),
		ClientIPv4:   ipv4,
		ClientIPv6:   ipv6,
		Psk:          psk,
		AllowedIPs:   derefStr(iface.AllowedIPs),
		Dns:          derefStr(iface.Dns),
		Status:       "new",
		Changes:      []string{},
	}}, nil
}

// ── Register handler (legacy) ─────────────────────────────────────────────────

type RegisterRequest struct {
	Pubkey string  `json:"pubkey"`
	Token  string  `json:"token"`
	Label  *string `json:"label,omitempty"`
}

type RegisterResponse struct {
	ServerPubkey string  `json:"server_pubkey"`
	Endpoint     string  `json:"endpoint"`
	ClientIPv4   *string `json:"client_ipv4,omitempty"`
	ClientIPv6   *string `json:"client_ipv6,omitempty"`
	Psk          string  `json:"psk"`
	AllowedIPs   string  `json:"allowed_ips"`
	Dns          string  `json:"dns"`
}

type RegisterInput struct {
	Body RegisterRequest
}

type RegisterOutput struct {
	Body RegisterResponse
}

func (s *AppState) register(_ context.Context, input *RegisterInput) (*RegisterOutput, error) {
	req := input.Body

	principalID, ifaceID, ok, err := dbConsumeToken(s.db, req.Token)
	if err != nil {
		return nil, huma.Error500InternalServerError(err.Error())
	}
	if !ok {
		return nil, huma.Error403Forbidden("invalid or expired token")
	}

	principal, err := dbGetPrincipal(s.db, principalID)
	if err != nil || principal == nil {
		return nil, huma.Error404NotFound("principal not found")
	}
	if principal.Status != "active" {
		return nil, huma.Error403Forbidden("account suspended")
	}

	iface, err := dbGetInterfaceByID(s.db, ifaceID)
	if err != nil || iface == nil {
		return nil, huma.Error404NotFound("interface not found")
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
		return nil, huma.Error503ServiceUnavailable("no address space available")
	}

	psk, err := GeneratePSK()
	if err != nil {
		return nil, huma.Error500InternalServerError(err.Error())
	}

	newPeer := &Peer{
		PrincipalID: principalID, IfaceID: ifaceID,
		Pubkey: req.Pubkey, Psk: &psk,
		Ipv4: ipv4, Ipv6: ipv6, Label: req.Label,
	}
	if _, err := dbInsertPeer(s.db, newPeer); err != nil {
		if strings.Contains(err.Error(), "UNIQUE") {
			return nil, huma.Error409Conflict("pubkey already registered")
		}
		return nil, huma.Error500InternalServerError(err.Error())
	}

	if err := s.wg.AddPeer(iface.Name, newPeer); err != nil {
		slog.Warn("add peer to interface", "iface", iface.Name, "err", err)
	}

	return &RegisterOutput{Body: RegisterResponse{
		ServerPubkey: iface.Pubkey,
		Endpoint:     derefStr(iface.Endpoint),
		ClientIPv4:   ipv4,
		ClientIPv6:   ipv6,
		Psk:          psk,
		AllowedIPs:   derefStr(iface.AllowedIPs),
		Dns:          derefStr(iface.Dns),
	}}, nil
}

// ── Peer handlers ─────────────────────────────────────────────────────────────

type ListPeersOutput struct {
	Body []Peer
}

func (s *AppState) listPeers(_ context.Context, _ *struct{}) (*ListPeersOutput, error) {
	peers, err := dbListPeers(s.db)
	if err != nil {
		return nil, huma.Error500InternalServerError(err.Error())
	}
	if peers == nil {
		peers = []Peer{}
	}
	return &ListPeersOutput{Body: peers}, nil
}

type PeerPubkeyParam struct {
	Pubkey string `path:"pubkey"`
}

type UpdatePeerInput struct {
	Pubkey string `path:"pubkey"`
	Body   struct {
		Label string `json:"label"`
	}
}

func (s *AppState) updatePeer(_ context.Context, input *UpdatePeerInput) (*struct{}, error) {
	ok, err := dbUpdatePeerLabel(s.db, input.Pubkey, input.Body.Label)
	if err != nil {
		return nil, huma.Error500InternalServerError(err.Error())
	}
	if !ok {
		return nil, huma.Error404NotFound("peer not found")
	}
	return nil, nil
}

func (s *AppState) revokePeer(_ context.Context, input *PeerPubkeyParam) (*struct{}, error) {
	ok, err := dbRevokePeer(s.db, input.Pubkey)
	if err != nil {
		return nil, huma.Error500InternalServerError(err.Error())
	}
	if !ok {
		return nil, huma.Error404NotFound("peer not found")
	}
	if ifaceName, _, err := dbPeerIfaceName(s.db, input.Pubkey); err == nil && ifaceName != "" {
		if err := s.wg.RemovePeer(ifaceName, input.Pubkey); err != nil {
			slog.Warn("remove peer from interface", "iface", ifaceName, "err", err)
		}
	}
	slog.Info("revoked peer", "pubkey", input.Pubkey[:min(8, len(input.Pubkey))])
	return nil, nil
}

type ListPrincipalPeersInput struct {
	ID int64 `path:"id"`
}

func (s *AppState) listPrincipalPeers(_ context.Context, input *ListPrincipalPeersInput) (*ListPeersOutput, error) {
	peers, err := dbListPeersForPrincipal(s.db, input.ID)
	if err != nil {
		return nil, huma.Error500InternalServerError(err.Error())
	}
	if peers == nil {
		peers = []Peer{}
	}
	return &ListPeersOutput{Body: peers}, nil
}

// ── Principal handlers ────────────────────────────────────────────────────────

type ListPrincipalsOutput struct {
	Body []Principal
}

func (s *AppState) listPrincipals(_ context.Context, _ *struct{}) (*ListPrincipalsOutput, error) {
	principals, err := dbListPrincipals(s.db)
	if err != nil {
		return nil, huma.Error500InternalServerError(err.Error())
	}
	if principals == nil {
		principals = []Principal{}
	}
	return &ListPrincipalsOutput{Body: principals}, nil
}

type PrincipalIDParam struct {
	ID int64 `path:"id"`
}

type PrincipalOutput struct {
	Body *Principal
}

func (s *AppState) getPrincipal(_ context.Context, input *PrincipalIDParam) (*PrincipalOutput, error) {
	p, err := dbGetPrincipal(s.db, input.ID)
	if err != nil {
		return nil, huma.Error500InternalServerError(err.Error())
	}
	if p == nil {
		return nil, huma.Error404NotFound("principal not found")
	}
	return &PrincipalOutput{Body: p}, nil
}

type CreatePrincipalInput struct {
	Body struct {
		ID       *int64  `json:"id,omitempty"`
		Identity string  `json:"identity"`
		Label    *string `json:"label,omitempty"`
	}
}

type CreatePrincipalOutput struct {
	Body struct {
		ID int64 `json:"id"`
	}
}

func (s *AppState) createPrincipal(_ context.Context, input *CreatePrincipalInput) (*CreatePrincipalOutput, error) {
	id, err := dbUpsertPrincipal(s.db, input.Body.ID, input.Body.Identity, input.Body.Label)
	if err != nil {
		return nil, huma.Error500InternalServerError(err.Error())
	}
	out := &CreatePrincipalOutput{}
	out.Body.ID = id
	return out, nil
}

type UpdatePrincipalInput struct {
	ID   int64 `path:"id"`
	Body struct {
		Status *string `json:"status,omitempty"`
		Label  *string `json:"label,omitempty"`
	}
}

func (s *AppState) updatePrincipal(_ context.Context, input *UpdatePrincipalInput) (*struct{}, error) {
	body := input.Body
	if body.Status != nil {
		if *body.Status != "active" && *body.Status != "suspended" {
			return nil, huma.Error400BadRequest("status must be 'active' or 'suspended'")
		}
		ok, err := dbUpdatePrincipalStatus(s.db, input.ID, *body.Status)
		if err != nil {
			return nil, huma.Error500InternalServerError(err.Error())
		}
		if !ok {
			return nil, huma.Error404NotFound("principal not found")
		}
	}
	if body.Label != nil {
		if err := dbUpdatePrincipalLabel(s.db, input.ID, *body.Label); err != nil {
			return nil, huma.Error500InternalServerError(err.Error())
		}
	}
	return nil, nil
}

func (s *AppState) deletePrincipal(_ context.Context, input *PrincipalIDParam) (*struct{}, error) {
	pubkeys, err := dbDeletePrincipal(s.db, input.ID)
	if err != nil {
		return nil, huma.Error500InternalServerError(err.Error())
	}
	for _, pk := range pubkeys {
		if ifaceName, _, err := dbPeerIfaceName(s.db, pk); err == nil && ifaceName != "" {
			s.wg.RemovePeer(ifaceName, pk)
		}
	}
	return nil, nil
}

// ── Token handlers ────────────────────────────────────────────────────────────

type ListTokensOutput struct {
	Body []Token
}

func (s *AppState) listTokens(_ context.Context, _ *struct{}) (*ListTokensOutput, error) {
	tokens, err := dbListTokens(s.db)
	if err != nil {
		return nil, huma.Error500InternalServerError(err.Error())
	}
	if tokens == nil {
		tokens = []Token{}
	}
	return &ListTokensOutput{Body: tokens}, nil
}

type CreateTokenInput struct {
	Body struct {
		PrincipalID int64  `json:"principal_id"`
		IfaceID     int64  `json:"iface_id"`
		UsesLeft    *int64 `json:"uses_left,omitempty"`
		Expires     *int64 `json:"expires,omitempty"`
	}
}

type CreateTokenOutput struct {
	Body struct {
		Token string `json:"token"`
	}
}

func (s *AppState) createToken(_ context.Context, input *CreateTokenInput) (*CreateTokenOutput, error) {
	token := randomToken()
	if _, err := dbCreateToken(s.db, token, input.Body.PrincipalID, input.Body.IfaceID, input.Body.UsesLeft, input.Body.Expires); err != nil {
		return nil, huma.Error500InternalServerError(err.Error())
	}
	out := &CreateTokenOutput{}
	out.Body.Token = token
	return out, nil
}

type TokenParam struct {
	Token string `path:"token"`
}

func (s *AppState) revokeToken(_ context.Context, input *TokenParam) (*struct{}, error) {
	ok, err := dbDeleteToken(s.db, input.Token)
	if err != nil {
		return nil, huma.Error500InternalServerError(err.Error())
	}
	if !ok {
		return nil, huma.Error404NotFound("token not found")
	}
	return nil, nil
}

// ── Import / Export handlers ──────────────────────────────────────────────────

type ImportInterfaceInput struct {
	RawBody []byte
}

func (s *AppState) importInterface(_ context.Context, input *ImportInterfaceInput) (*InterfaceOutput, error) {
	conf, err := parseWGConf(string(input.RawBody))
	if err != nil {
		return nil, huma.Error400BadRequest("invalid wg config: " + err.Error())
	}

	if conf.Name == "" {
		conf.Name = "wg0"
	}
	if !validIfName(conf.Name) {
		return nil, huma.Error400BadRequest("invalid interface name in config")
	}

	var privB64, pubB64 string
	if conf.PrivateKey != "" {
		privB64, pubB64, err = ImportPrivateKey(conf.PrivateKey)
		if err != nil {
			return nil, huma.Error400BadRequest("invalid PrivateKey")
		}
	} else {
		privB64, pubB64, err = GenerateKeypair()
		if err != nil {
			return nil, huma.Error500InternalServerError(err.Error())
		}
	}

	port := int64(51820)
	if conf.ListenPort > 0 {
		port = int64(conf.ListenPort)
	}

	iface := &Interface{
		Name: conf.Name, PrivateKey: privB64, Pubkey: pubB64,
		ListenPort: port, Enabled: true,
	}
	if conf.AddressV4 != "" {
		iface.AddressV4 = &conf.AddressV4
	}
	if conf.AddressV6 != "" {
		iface.AddressV6 = &conf.AddressV6
	}
	if conf.DNS != "" {
		iface.Dns = &conf.DNS
	}
	if conf.MTU > 0 {
		m := int64(conf.MTU)
		iface.Mtu = &m
	}
	if conf.PreUp != "" {
		iface.PreUp = &conf.PreUp
	}
	if conf.PostUp != "" {
		iface.PostUp = &conf.PostUp
	}
	if conf.PreDown != "" {
		iface.PreDown = &conf.PreDown
	}
	if conf.PostDown != "" {
		iface.PostDown = &conf.PostDown
	}

	created, err := dbInsertInterface(s.db, iface)
	if err != nil {
		if strings.Contains(err.Error(), "UNIQUE") {
			return nil, huma.Error409Conflict("interface name already exists")
		}
		return nil, huma.Error500InternalServerError(err.Error())
	}

	// Insert peers from [Peer] sections using a synthetic principal per pubkey.
	for _, cp := range conf.Peers {
		principalID, err := dbUpsertPrincipal(s.db, nil, "imported:"+cp.PublicKey, nil)
		if err != nil {
			slog.Warn("import peer principal", "pubkey", cp.PublicKey[:min(8, len(cp.PublicKey))], "err", err)
			continue
		}
		peer := &Peer{
			PrincipalID: principalID, IfaceID: created.ID,
			Pubkey: cp.PublicKey,
		}
		if cp.PresharedKey != "" {
			peer.Psk = &cp.PresharedKey
		}
		if cp.AllowedIPs != "" {
			// Store first IPv4 and IPv6 from AllowedIPs list.
			for _, cidr := range strings.Split(cp.AllowedIPs, ",") {
				cidr = strings.TrimSpace(cidr)
				if strings.Contains(cidr, ":") {
					if peer.Ipv6 == nil {
						peer.Ipv6 = &cidr
					}
				} else {
					if peer.Ipv4 == nil {
						peer.Ipv4 = &cidr
					}
				}
			}
		}
		if _, err := dbInsertPeer(s.db, peer); err != nil {
			slog.Warn("import peer insert", "pubkey", cp.PublicKey[:min(8, len(cp.PublicKey))], "err", err)
		}
	}

	if err := s.wg.BringUpInterface(s.db, created); err != nil {
		slog.Warn("bring up imported interface", "name", created.Name, "err", err)
	}

	slog.Info("imported interface", "name", created.Name)
	return &InterfaceOutput{Body: created}, nil
}

type ExportInterfaceInput struct {
	Name string `path:"name"`
}

type ExportInterfaceOutput struct {
	Body   string
	Status int
}

func (s *AppState) exportInterface(_ context.Context, input *ExportInterfaceInput) (*huma.StreamResponse, error) {
	iface, err := dbGetInterface(s.db, input.Name)
	if err != nil {
		return nil, huma.Error500InternalServerError(err.Error())
	}
	if iface == nil {
		return nil, huma.Error404NotFound("interface not found")
	}
	peers, err := dbListPeersForIface(s.db, iface.ID)
	if err != nil {
		return nil, huma.Error500InternalServerError(err.Error())
	}

	text := generateWGConf(iface, peers)
	return &huma.StreamResponse{
		Body: func(ctx huma.Context) {
			ctx.SetHeader("Content-Type", "text/plain; charset=utf-8")
			ctx.SetStatus(http.StatusOK)
			io.WriteString(ctx.BodyWriter(), text)
		},
	}, nil
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

func unixNow() int64 {
	return timeNow().Unix()
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

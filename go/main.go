package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"
)

func main() {
	dbPath := flag.String("db", "wgdb.db", "path to SQLite database")
	addr := flag.String("addr", "127.0.0.1:51800", "HTTP listen address")
	adminToken := flag.String("admin-token", "changeme", "admin bearer token (env: WGDB_ADMIN_TOKEN)")
	flag.Parse()

	// Positional args override flags (backwards compat with Rust CLI).
	if args := flag.Args(); len(args) >= 1 {
		*dbPath = args[0]
	}
	if args := flag.Args(); len(args) >= 2 {
		*addr = args[1]
	}

	// Env var overrides flag.
	if t := os.Getenv("WGDB_ADMIN_TOKEN"); t != "" {
		*adminToken = t
	}

	slog.Info("wgdb starting", "db", *dbPath, "addr", *addr)

	// Ensure parent directory exists.
	if dir := filepath.Dir(*dbPath); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			fatalf("create db directory: %v", err)
		}
	}

	db, err := openDB(*dbPath)
	if err != nil {
		fatalf("open db: %v", err)
	}
	defer db.Close()

	wg := newWGManager()

	state := &AppState{db: db, wg: wg, adminToken: *adminToken}

	// Bring up all enabled interfaces.
	ifaces, err := dbListInterfaces(db)
	if err != nil {
		fatalf("list interfaces: %v", err)
	}
	var ifaceNames []string
	for _, iface := range ifaces {
		ifaceNames = append(ifaceNames, iface.Name)
		if iface.Enabled {
			if err := wg.BringUpInterface(db, &iface); err != nil {
				slog.Warn("bring up interface on startup", "name", iface.Name, "err", err)
			}
		}
	}

	// Background handshake poller.
	go pollHandshakes(state, ifaceNames)

	// HTTP server.
	router := setupRouter(state)
	srv := &http.Server{Addr: *addr, Handler: router}

	// Graceful shutdown on signal.
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)

	go func() {
		slog.Info("wgdb listening", "addr", *addr)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			fatalf("listen: %v", err)
		}
	}()

	<-stop
	slog.Info("wgdb shutting down")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	srv.Shutdown(ctx)

	slog.Info("wgdb stopped")
}

// pollHandshakes polls all active interfaces every 30 seconds for peer
// handshake timestamps and persists them to the DB.
func pollHandshakes(state *AppState, ifaceNames []string) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		for _, name := range ifaceNames {
			hs, err := state.wg.Handshakes(name)
			if err != nil {
				slog.Debug("poll handshakes", "iface", name, "err", err)
				continue
			}
			for pubkey, ts := range hs {
				if err := dbUpdatePeerLastSeen(state.db, pubkey, ts); err != nil {
					slog.Debug("update last_seen", "pubkey", pubkey[:min(8, len(pubkey))], "err", err)
				}
			}
		}
	}
}

// timeNow is a thin wrapper so tests can override it (also used in api.go).
func timeNow() time.Time { return time.Now() }

func fatalf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "wgdb: "+format+"\n", args...)
	os.Exit(1)
}

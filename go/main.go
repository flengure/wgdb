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

	// Env var overrides flag.
	if t := os.Getenv("WGDB_ADMIN_TOKEN"); t != "" {
		*adminToken = t
	}

	// Check for service subcommands (Windows) or backwards-compat positional args.
	args := flag.Args()
	if len(args) > 0 {
		if handleServiceCommand(args[0], *dbPath, *addr, *adminToken) {
			return
		}
		// Positional args: backwards compat with Rust CLI.
		*dbPath = args[0]
		if len(args) >= 2 {
			*addr = args[1]
		}
	}

	// Running as a Windows service — hand off to service runner.
	if isWindowsService() {
		if err := initWintun(); err != nil {
			fatalf("init wintun: %v", err)
		}
		runWindowsService(*dbPath, *addr, *adminToken)
		return
	}

	checkPrivileges()

	if err := initWintun(); err != nil {
		fatalf("init wintun: %v", err)
	}

	// Interactive mode — stop on OS signal.
	stopCh := make(chan struct{})
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigCh
		close(stopCh)
	}()

	run(*dbPath, *addr, *adminToken, stopCh)
}

func run(dbPath, addr, adminToken string, stop <-chan struct{}) {
	slog.Info("wgdb starting", "db", dbPath, "addr", addr)

	if dir := filepath.Dir(dbPath); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			fatalf("create db directory: %v", err)
		}
	}

	db, err := openDB(dbPath)
	if err != nil {
		fatalf("open db: %v", err)
	}
	defer db.Close()

	wg := newWGManager()
	state := &AppState{db: db, wg: wg, adminToken: adminToken}

	ifaces, err := dbListInterfaces(db)
	if err != nil {
		fatalf("list interfaces: %v", err)
	}
	var ifaceNames []string
	for _, iface := range ifaces {
		ifaceNames = append(ifaceNames, iface.Name)
		if iface.Enabled {
			if err := wg.BringUpInterface(db, &iface); err != nil {
				slog.Error("failed to bring up interface on startup", "name", iface.Name, "err", err)
			}
		}
	}

	go pollHandshakes(state, ifaceNames)

	router := setupRouter(state)
	srv := &http.Server{Addr: addr, Handler: router}

	go func() {
		slog.Info("wgdb listening", "addr", addr)
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

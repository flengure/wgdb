# wgdb

A WireGuard VPN management daemon — a self-hosted HTTP API server that automates the lifecycle of WireGuard interfaces and peers on Linux.

An admin defines VPN interfaces and issues single-use (or limited-use) tokens to clients. A client redeems a token via the REST API, gets an IP allocated automatically, and receives a ready-to-use WireGuard config in response — no manual key exchange or config editing required.

The stack is intentionally minimal: one Rust binary, one SQLite file, no subprocesses. It speaks directly to the Linux kernel via rtnetlink (interface management) and the WireGuard kernel module (peer config), and keeps peer last-seen timestamps up to date with a background poller.

## Usage

```bash
cargo build --release
WGDB_ADMIN_TOKEN=secret ./target/release/wgdb wgdb.db 127.0.0.1:51800
```

API documentation is available at `/docs` when the server is running.

## Requirements

- Linux
- WireGuard kernel module
- Root or `CAP_NET_ADMIN` capability

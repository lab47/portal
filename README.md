# Admin helper

A small coordinator, server, and client for running commands over [go-iroh](https://github.com/tmc/go-iroh). The coordinator keeps short-lived in-memory inventory; the server checks in every 30 seconds and accepts commands from holders of SSH **user** certificates signed by its trusted CA. The client looks up the server, connects to its authenticated iroh endpoint, and signs a fresh challenge bound to the command arguments. Commands run directly (not through a shell) as the server process's OS user.

Requires Go 1.26 and outbound access to an iroh relay from both server and client. Inventory contains only an endpoint ID and relay URL, never a server UDP address. Iroh establishes the connection via the relay, then discovers and selects a direct UDP path when reachable, retaining the relay as fallback. Build the CLI with `go build -o adminhelper ./cmd/adminhelper`.

The importable `github.com/miren/portal` package exposes `NewCoordinator(token)` as an HTTP handler, `Server.Serve(ctx)` for registration and command serving, and `Client.Run(ctx, argv)` for lookup and execution. `Client.Run` returns a `Result` containing output and remote exit status; the CLI in `cmd/adminhelper` uses `miren.dev/mflags` for subcommands and flags. Use `--` before the remote command to pass flag-like arguments through unchanged.

## Local walkthrough

In a temporary directory, generate a CA and client key, then sign a one-hour user certificate with the `admin` principal:

```sh
./adminhelper cert keygen -out ca
./adminhelper cert keygen -out operator
./adminhelper cert sign -ca-key ca -pub operator.pub -principal admin \
  -id operator -valid-for 1h -out operator-cert.pub
./adminhelper cert inspect -cert operator-cert.pub -ca ca.pub -principal admin
```

The same `cert keygen` command creates either a CA or a user key; private keys are unencrypted and written with mode 0600. These commands never overwrite existing files. `cert inspect` checks the CA signature, principal, and validity period using the same policy as the server (but does not prove possession of the user private key). Certificates expire; there is no revocation list in this version, so issue short-lived certificates and protect the CA private key.

Start the coordinator in one terminal (use a long random token in practice):

```sh
ADMINHELPER_TOKEN=local-test-token ./adminhelper coordinator -listen 127.0.0.1:8080
```

Start a server in another terminal; it registers itself before accepting commands:

```sh
ADMINHELPER_TOKEN=local-test-token ./adminhelper server \
  -name node-a -coordinator http://127.0.0.1:8080 -ca ca.pub
```

Query the inventory and run a command from the client:

```sh
curl http://127.0.0.1:8080/servers/node-a
./adminhelper client -name node-a -coordinator http://127.0.0.1:8080 \
  -key operator -cert operator-cert.pub -- /usr/bin/id
```

By default the server selects a number0 production relay. To use a relay you operate, pass `-relay https://relay.example.com/` to the server; the client learns that relay through inventory. The relay must accept both endpoints. For a directly reachable interface, the server can use `-listen SERVER_IP:PORT` to offer that address to iroh's in-band path discovery (not to coordinator inventory). The default bind uses an OS-assigned dual-stack port; direct upgrades depend on iroh discovering routable candidates and network/firewall reachability. A short command may finish before the upgrade and remain relayed. The coordinator is still reached via HTTP(S) for check-in and lookup; only the command channel uses iroh. Registrations expire after 90 seconds without a refresh and disappear on coordinator restart; servers re-register at their next check-in. The lookup endpoint is read-only and public to anyone who can access the coordinator; registration requires the shared token.

**Security:** Serve the coordinator over HTTPS (or behind a trusted TLS reverse proxy) outside a local test; otherwise inventory and the registration token can be intercepted or changed. Protect the token and CA signing key. The client trusts inventory returned by that coordinator for the server endpoint identity, while iroh verifies the connected endpoint matches that identity. The server verifies the CA signature, expiry, explicit principal, and proof of possession of the certificate's private key. Limit the server process's OS privileges appropriately: an authorized certificate can run arbitrary executables as that user. This is a bounded-output (1 MiB), 60-second command facility, not an interactive shell or job supervisor.

Run tests with `go test ./... -count=1`.

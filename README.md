# Portal

A small coordinator, server, and client for running commands over [go-iroh](https://github.com/tmc/go-iroh). The coordinator keeps short-lived in-memory inventory; the server checks in every 30 seconds and accepts commands from holders of SSH **user** certificates signed by its trusted CA, subject to its local authorization policy. The client looks up the server, connects to its authenticated iroh endpoint, and signs a fresh challenge bound to the command arguments. Commands run directly (not through a shell) as the server process's OS user unless another account is requested and allowed.

Requires Go 1.26 and outbound access to an iroh relay from both server and client. Inventory contains only an endpoint ID and relay URL, never a server UDP address. Iroh establishes the connection via the relay, then discovers and selects a direct UDP path when reachable, retaining the relay as fallback. Build the CLI with `go build -o portal ./cmd/portal`.

The importable `github.com/lab47/portal` package exposes `NewCoordinator(token)` as an HTTP handler, `Server.Serve(ctx)` for registration and command serving, and `Client.Run(ctx, argv)` for lookup and execution. `Client.Run` returns a `Result` containing output and remote exit status; the CLI in `cmd/portal` uses `miren.dev/mflags` for subcommands and flags. Use `--` before the remote command to pass flag-like arguments through unchanged.

## Local walkthrough

In a temporary directory, generate a CA and client key, then sign a one-hour user certificate with the `admin` principal:

```sh
./portal cert keygen --out ca
./portal cert keygen --out operator
./portal cert sign --ca-key ca --pub operator.pub --principal admin \
  --id operator --valid-for 1h --out operator-cert.pub
./portal cert inspect --cert operator-cert.pub --ca ca.pub --principal admin
```

The same `cert keygen` command creates either a CA or a user key; private keys are unencrypted and written with mode 0600. These commands never overwrite existing files. `cert inspect` checks the CA signature, principal, and validity period, but does not check the server's authorization policy or prove possession of the user private key. Certificates expire; there is no revocation list in this version, so protect the CA private key and restrict access through each server's policy.

Start the coordinator in one terminal (use a long random token in practice):

```sh
PORTAL_TOKEN=local-test-token ./portal coordinator --listen 127.0.0.1:8080
```

Create a policy on the server mapping each CA-signed certificate key ID (`cert sign -id`) to the local accounts it may use. For this walkthrough, allow `operator` to run as the current server user:

```sh
printf '{"identities":{"operator":["%s"]}}\n' "$(id -un)" > policy.json
```

Start a server in another terminal; it validates its policy before registering or accepting commands:

```sh
PORTAL_TOKEN=local-test-token ./portal server \
  --name node-a --coordinator http://127.0.0.1:8080 --ca ca.pub --policy policy.json \
  --label role=worker --label region=us-west
```

Query the inventory and run a command from the client:

```sh
curl http://127.0.0.1:8080/servers/node-a
./portal client --name node-a --coordinator http://127.0.0.1:8080 \
  --key operator --cert operator-cert.pub --user "$(id -un)" -- /usr/bin/id
```

Each repeated `-label KEY=VALUE` adds an inventory label; omit the flags for no labels. Values may contain commas and `=`. Labels are advertised on check-in and returned as `"labels":{"role":"worker","region":"us-west"}` by `GET /servers/node-a`. They are metadata only, not authorization rules or connection addresses. Inventory lookup is public to anyone who can reach the coordinator, so do not put secrets in labels.

`-user` selects a local account on the server. Omit it to request the server process's effective account; that account must still be allowed by the policy. An unmapped certificate identity or account is denied, including `root`: to permit root, explicitly list `"root"` for that identity. Account names in the policy are resolved to UIDs at startup, so aliases cannot bypass authorization; unknown accounts and malformed policies prevent startup. Restart the server after changing its policy. Switching to another UID/GID requires the server process to run as root; an unprivileged switch is rejected. Explicit-user commands start in `/` with only `PATH`, `HOME`, `USER`, and `LOGNAME` in their environment; they do not inherit server-side secrets. The account name is included in the signed command request.

## Passkey-backed CA

Run the certificate authority **separately** from the inventory coordinator. Create a dedicated SSH CA key with `portal cert keygen --out ca`, and provision a random enrollment token of at least 32 characters as `PORTAL_CA_ENROLL_TOKEN`. Keep both off the coordinator. The CA needs a stable HTTPS origin (the WebAuthn relying-party origin); bind its HTTP listener only to a trusted TLS reverse proxy, not directly to the internet. Keep the `--state` file on persistent storage, back it up, and restrict access to the CA key and state. For example:

```sh
umask 077
openssl rand -hex 32 > ca-enroll-token   # securely deliver to the initial user, then delete
PORTAL_CA_ENROLL_TOKEN="$(cat ca-enroll-token)" portal ca serve \
  --listen 127.0.0.1:8081 --origin https://ca.example.com \
  --identity operator --principal admin --ca-key ca --state ca-state.json
```

After enrollment, remove `PORTAL_CA_ENROLL_TOKEN` from the CA environment and delete the token file; passkeys are persisted in the state file. This first version serves one configured identity per CA instance. An administrator must independently distribute `ca.pub` to clients and servers, and add `operator` to each server's local policy with only the accounts it may use. Passkey enrollment does **not** grant access by itself.

On any machine, request a certificate without copying the old private key:

```sh
mkdir -p ~/.config/portal
portal cert request --ca-url https://ca.example.com --ca ca.pub \
  --key ~/.config/portal/operator --cert ~/.config/portal/operator-cert.pub
```

The command generates a local Ed25519 key if absent, shows its fingerprint, and prints an approval URL. Open that URL in a browser, compare the fingerprint, and approve with a passkey. On first enrollment, enter the one-time enrollment token. The client receives a **48-hour SSH user certificate** for the new public key, verifies it against its pinned CA public key, and writes it to `--cert`. It also stores a refresh token in `<key>.refresh` with mode 0600. The CA never receives the client's private key.

Headless clients can renew without a browser using the **same private key** and their refresh token:

```sh
portal cert refresh --ca-url https://ca.example.com --ca ca.pub \
  --key ~/.config/portal/operator --cert ~/.config/portal/operator-cert.pub
```

The CA requires a signature from that key, rotates the refresh token on each successful use, and returns a new 48-hour certificate. The token is bound to that key and expires **30 days after the most recent passkey approval**, not 30 days after each refresh. Schedule `cert refresh` before the certificate expires (for example, once daily); after 30 days, rerun `cert request` and approve in the browser to start another 30-day period. If the client loses the rotated token due to a crash or failed write, browser approval is required again. Keep the token file and private key together and restrict them to the client account; neither should be logged or committed.

Approval requests expire after five minutes and are not durable across CA restarts. The CA keeps passkey credentials and hashed refresh tokens on disk, while challenges and pending certificates live in memory. This version does not include automatic scheduling, multiple users per CA instance, or revocation; a stolen private key and certificate can remain usable for up to 48 hours unless each server's policy is changed and reloaded or its trusted CA is rotated. Protect the enrollment token and avoid logging approval URLs. Do not mount the CA signing key into the public coordinator.

## MCP tool

Run `portal mcp-server` as a stdio MCP server to expose **only** the `client` command as an MCP tool. For an MCP host that launches stdio servers:

```json
{"mcpServers":{"portal":{"command":"/absolute/path/to/portal","args":["mcp-server"]}}}
```

The MCP `client` tool takes `name`, `coordinator`, `key`, `cert`, optional `user`, and an `arguments` array for the remote command. For example, `{"name":"node-a","coordinator":"https://coordinator.example.com","key":"/path/operator","cert":"/path/operator-cert.pub","user":"deploy","arguments":["--","/usr/bin/id","-u"]}` runs `id -u` on `node-a`. Begin the array with `"--"` to protect remote flags from mflags' CLI parsing; it is a separator, not sent to the server. The MCP host must be able to read the client key and certificate files. Remote commands still require the server's certificate authentication and authorization policy. This CLI serves an MCP tool to MCP clients; it does not itself connect to external MCP servers.

The command protocol remains `adminhelper/2` for wire compatibility; upgrade clients and servers together if changing the protocol separately. Existing SSH user certificates with a nonempty key ID may continue to work if that identity is listed in the policy; certificates without a key ID cannot be authorized.

By default the server selects a number0 production relay. To use a relay you operate, pass `-relay https://relay.example.com/` to the server; the client learns that relay through inventory. The relay must accept both endpoints. For a directly reachable interface, the server can use `-listen SERVER_IP:PORT` to offer that address to iroh's in-band path discovery (not to coordinator inventory). The default bind uses an OS-assigned dual-stack port; direct upgrades depend on iroh discovering routable candidates and network/firewall reachability. A short command may finish before the upgrade and remain relayed. The coordinator is still reached via HTTP(S) for check-in and lookup; only the command channel uses iroh. Registrations expire after 90 seconds without a refresh and disappear on coordinator restart; servers re-register at their next check-in. The lookup endpoint is read-only and public to anyone who can access the coordinator; registration requires the shared token.

**Security:** Serve the coordinator over HTTPS (or behind a trusted TLS reverse proxy) outside a local test; otherwise inventory and the registration token can be intercepted or changed. Protect the token, policy file, and CA signing key. The client trusts inventory returned by that coordinator for the server endpoint identity, while iroh verifies the connected endpoint matches that identity. The server verifies the CA signature, expiry, explicit principal, and proof of possession of the certificate's private key before applying its policy. Limit the server process's OS privileges appropriately: an authorized certificate can run arbitrary executables as an allowed user. This is a bounded-output (1 MiB), 60-second command facility, not an interactive shell or job supervisor.

Run tests with `go test ./... -count=1`.

# Portal

A small coordinator, server, and client for running commands over [go-iroh](https://github.com/tmc/go-iroh). The coordinator keeps short-lived in-memory inventory; the server checks in every 30 seconds and accepts commands from ordinary SSH keys in its account's `authorized_keys` when no CA is configured, or SSH **user** certificates signed by its trusted CA, subject to its local authorization policy. The client looks up the server, connects to its authenticated iroh endpoint, and signs a fresh challenge bound to the command arguments. Commands run directly (not through a shell) as the server process's OS user unless another account is requested and allowed.

Requires outbound access to an iroh relay from both server and client. Inventory contains only an endpoint ID and relay URL, never a server UDP address. Iroh establishes the connection via the relay, then discovers and selects a direct UDP path when reachable, retaining the relay as fallback. Building from source requires Go 1.26: `go build -o portal ./cmd/portal`.

The importable `github.com/lab47/portal` package exposes `NewCoordinator(token)` as an HTTP handler, `Server.Serve(ctx)` for registration and command serving, and `Client.Run(ctx, argv)` for lookup and execution. `Client.Run` returns a `Result` containing output and remote exit status; the CLI in `cmd/portal` uses `miren.dev/mflags` for subcommands and flags. Use `--` before the remote command to pass flag-like arguments through unchanged.

## Standalone query engine

Import `github.com/lab47/portal/query` to use the same DSL, validation,
collectors, aggregations, and report processing locally, without importing
Portal's iroh transport or authentication code:

```go
request, err := query.ParseMonitorQuery("memory")
if err != nil {
    return err
}
snapshot, err := (query.Engine{}).Query(ctx, request)
```

The zero-value `query.Engine` uses the built-in local collectors.
`Engine.Query` executes snapshots, event or sampled aggregates, and scripts;
`Engine.Monitor` streams matching events until cancellation or a callback error.
To supply your product's own data, set `Engine.Events` and/or `Engine.Snapshots`
to callbacks using the shared request/event/snapshot models. Collectors must
honor context cancellation and propagate callback errors. Event predicates
are applied by the engine; snapshot collectors apply their source selections.

Local queries run with the calling process's OS privileges. Linux/eBPF and
other collector requirements still apply; the engine does not authenticate or
authorize callers, so an embedding product must enforce its own access policy.
The `capabilities` source remains Portal-specific because its response describes
the authenticated caller's permissions. Existing `portal.Client.Query`,
`portal.Client.Monitor`, models, and DSL entry point remain compatible and use
the extracted engine behind the same signed, authorized protocol.

## Using existing SSH keys

When no CA is configured, Portal automatically uses ordinary SSH keys instead of
certificates. Put the client's ordinary
SSH public key in the **server account's** `~/.ssh/authorized_keys`, just as for
OpenSSH login (for example, using `ssh-copy-id`). Then, on the server:

```sh
portal server init --name node-a \
  --coordinator 'https://coordinator.example/register/REGISTRATION_TOKEN'
portal server
```

The registration URL is still secret; SSH-key authentication removes certificate enrollment,
not coordinator registration. Initialization stores it in the existing owner-only
server config and never overwrites an existing config. To use a nonstandard trust
file, add `--authorized-keys /absolute/path/authorized_keys`. Flag-only startup is
also supported: `portal server --name node-a --coordinator '…'`.

On the client:

```sh
portal config init --coordinator https://coordinator.example
portal client --name node-a -- uname -a
portal query --name node-a --query 'process'
```

Without a saved config, add `--coordinator https://coordinator.example`
to any client, query, capabilities, or monitor command. The same flags/config also
work through MCP. The client selects the first existing `~/.ssh/id_ed25519`,
`id_ecdsa`, or `id_rsa`, in that order; `--key PATH` chooses another key explicitly.
It does not offer multiple keys after rejection. Encrypted keys must already be
loaded with `ssh-add`; Portal uses the matching plain key through `SSH_AUTH_SOCK`
without asking for a passphrase. With no default key file, it uses the first plain
key in the agent. Unix-domain agents are supported; native Windows named-pipe
agents, hardware-key files, and `ssh_config`/`sshd_config` overrides are not read.

**Trust and privileges:** command access follows the requested account's keys.
`portal client --name node-a --user root -- id` checks root's
`~/.ssh/authorized_keys`; `--user alice` checks Alice's file. With no `--user`,
the server account is the target. A key accepted for one account does not grant
access to another. Switching accounts requires a root server on Unix; Windows
and non-root servers accept only their own account. `--authorized-keys` overrides
the server account's file only, never another requested account's file.
Queries, capabilities and monitors have no target account and use the server
account's keys. For root-only tracing, deliberately run the server as root;
the default then becomes `/root/.ssh/authorized_keys` on Linux, not a sudo caller's
home. Keys in that file also grant arbitrary root commands. Each authentication
requires the key file, its parent and grandparent to be owned by the target account
or root and not group/world writable; Windows relies on filesystem ACLs.
Only unrestricted plain-key lines are accepted: entries with any SSH options
(including `command=`, `from=`, `restrict`, or `cert-authority`) and certificate
entries are skipped. Missing, unsafe or empty key files reject requests for that
account, without falling back to another account's keys. Files are read on each
new request, so edits and revocations need no restart; already-running commands
and streams are not terminated. Startup does not require a key file for the
server account when it will only serve commands for other accounts.

### Delegating queries without command access

In plain SSH-key mode, `--query-authorized-keys PATH` adds a separate trust file
for queries, capability discovery, streaming monitors, and registered-monitor
creation/read/delete. It never authorizes commands, even with `--user root`.
Normal server-account keys continue to work for both commands and queries.

For a root server, store delegates' ordinary SSH public keys in a root-controlled
file outside `/root/.ssh/authorized_keys`, for example:

```sh
sudo install -d -m 700 /etc/portal
sudo install -m 600 analyst.pub /etc/portal/query_authorized_keys
sudo portal server --query-authorized-keys /etc/portal/query_authorized_keys
```

The server command uses its existing server config; initialization can also save
the option with `portal server init ... --query-authorized-keys PATH`.
In JSON, set `"query_authorized_keys": "/etc/portal/query_authorized_keys"`;
relative paths resolve beside the server config. Go callers use
`Server.QueryAuthorizedKeysFile`.

Delegates use the normal client key discovery or `--key`, without a special
client flag. They receive all query sources available to the server account,
including root-level tracing on a root server, **not** unrestricted commands.
This is powerful observability access: traces can expose sensitive data and
consume resources; it is not a sandbox or a per-source policy. Monitor ownership
still belongs to its creating key. Keep delegates' keys out of every account's
command `authorized_keys` if they must not get command access there.

The additional file has the same ownership, permissions, size and SSH-option
restrictions as account key files. It is read on each new request; revocation
blocks later queries and monitor reads without stopping existing streams.
Delegation works even when the server account has no command keys. This option
cannot be combined with a configured CA; certificate policy is unchanged.

Each side selects its authentication method from its own resolved configuration:
`ca`/`--ca` selects certificates; an absent CA selects plain SSH keys. The server's
inline `CAPublicKey` also selects certificate authentication. Configure both sides
consistently; mismatched modes are rejected. A configured but missing, malformed,
or untrusted CA is an error, never a fallback to plain keys. Certificate-specific
settings (certificate, renewal, principal, or certificate policy) without a CA are
rejected rather than silently ignored. Existing saved CA configs keep using
certificates; use separate files with `--config PATH` for SSH-key configurations.
Go callers can omit `CAFile`/`CAPublicKey` and use
`Server{AuthorizedKeysFile: optionalPath, …}`. Clients and servers must both be updated
for plain-key authentication.

## Installation

Install the latest published build on Linux or macOS (amd64 or arm64):

```sh
curl -fsSL https://raw.githubusercontent.com/lab47/portal/main/install.sh | bash
```

The installer needs Bash, curl, and either `sha256sum` or `shasum`; Go and sudo are not required. It installs to `~/.local/bin/portal`. If that directory is not already on your PATH, add this to your shell's startup file:

```sh
export PATH="$HOME/.local/bin:$PATH"
```

Override the destination or select a specific release tag:

```sh
curl -fsSL https://raw.githubusercontent.com/lab47/portal/main/install.sh | PORTAL_INSTALL_DIR=/your/bin bash
curl -fsSL https://raw.githubusercontent.com/lab47/portal/main/install.sh | PORTAL_VERSION=build-42-1 bash
```

To inspect the script before running it, download it with `curl -fsSL https://raw.githubusercontent.com/lab47/portal/main/install.sh -o install.sh`, review it, then run `bash install.sh`.

The installer verifies the binary against the release's `SHA256SUMS` before replacing an existing installation atomically. Run it again to upgrade. The build workflow publishes all four platform binaries after tests and builds succeed on current `main`; “latest” means the latest published main build, not a semantic-versioned release. The first successful run of this workflow on `main` must publish a release before installation is available. Find actual tags on the [releases page](https://github.com/lab47/portal/releases).

## Coordinator configuration

Create the coordinator's local config and a copy/paste registration URL:

```sh
portal coordinator init --url https://inventory.example.com --config ./coordinator.json
portal coordinator --config ./coordinator.json --listen 127.0.0.1:8080
```

Initialization generates a cryptographically random 256-bit token, saves it in the coordinator's local config with owner-only permissions (0600), and prints a URL like `https://inventory.example.com/register/TOKEN` on stdout. Existing files are never overwritten. Put the coordinator behind a trusted HTTPS reverse proxy outside local testing. Copy/paste this **secret URL** to managed servers; no JSON document needs to be transferred. Lookup-only clients need just `https://inventory.example.com`, not the registration URL. There is no separate token file or registration-token environment variable.

Without `--config`, these commands use `portal/coordinator.json` in the OS user-config directory. Retrieve the registration URL later with `portal coordinator url --config ./coordinator.json`. The coordinator keeps its config locally; servers save the registration URL as one string in `server.json`. When rotating the token, update the coordinator's config and each server's URL, then restart the services.

The server decodes `/register/TOKEN` locally and sends registration requests to the base URL with the existing Bearer authorization header. The secret path is **not** sent to the coordinator or reverse proxy, and no new HTTP routes are required. Base path prefixes are preserved (for example `https://inventory.example.com/portal/register/TOKEN`). Tokens are URL-escaped as one path component; queries, fragments, userinfo, and missing or malformed tokens are rejected. Do not open registration URLs in a browser or expose them in logs, shell history, or screenshots; these are enrollment credentials, not web pages.

## Server configuration

Bundle server settings into a single file, including the registration token, trusted CA **public key contents**, and account policy:

```sh
portal server init \
  --name node-a --coordinator 'https://inventory.example.com/register/TOKEN' \
  --ca https://ca.example.com/ca.pub --identity operator --user "$(id -un)"
portal server
```

`server init` writes an owner-only (0600) `portal/server.json` in the OS user-config directory and refuses to overwrite an existing file. `--coordinator` takes the registration URL printed by the coordinator. `--ca` imports a public key from a local file or HTTPS URL, never a CA signing key. The resolved key is embedded, so subsequent server starts do not fetch the URL or depend on the CA service being online. `--identity` is the certificate key ID; repeat `--user` to authorize multiple local accounts. No accounts, including root, are granted implicitly. After initialization, the server needs only `server.json`, not the original CA public-key file or a separate policy file. Do not delete files still used by the coordinator, CA, or clients.

The default path is `$XDG_CONFIG_HOME/portal/server.json` or `~/.config/portal/server.json` on Linux, `~/Library/Application Support/portal/server.json` on macOS, and `%AppData%\portal\server.json` on Windows. For a service running under another account, choose an explicit path with `server init --config /etc/portal/server.json ...` and `portal server --config /etc/portal/server.json`, giving the service account ownership. Unix startup rejects group/world-accessible configs because they contain a secret; restrict access using ACLs on Windows.

Edit the JSON to add more identities, labels, or optional relay/listen settings:

```json
{
  "name": "node-a",
  "coordinator": "https://inventory.example.com/register/YOUR-REGISTRATION-TOKEN",
  "ca": "ssh-ed25519 YOUR-CA-PUBLIC-KEY",
  "identities": {"operator": ["deploy"]},
  "principal": "admin",
  "labels": {"role": "worker", "region": "us-west"}
}
```

Replace the example token/key and use actual local account names. Optional `relay` specifies an iroh relay URL; `listen` specifies a UDP bind IP:port. Restart the server after edits. Configs must contain the token and valid CA/policy even when overrides are supplied; unknown fields, trailing JSON, invalid accounts, and files larger than 64 KiB are rejected.

Existing flag-only startup still works when the default config is absent; a missing explicit `--config` is an error. Nonempty flags override saved settings. Both `server init --coordinator` and `server --coordinator` accept registration URLs. The legacy base URL plus `--token` flags remain supported for direct startup, but registration tokens are no longer read from the environment. Overriding the saved coordinator URL requires supplying that coordinator's token too, either in its URL or explicitly, rather than sending the saved token to another URL. Conflicting URL and explicit tokens are rejected. `--ca` and `--policy` replace the embedded key and policy with external files. Repeated `--label KEY=VALUE` flags merge with saved labels, overriding matching keys. The principal defaults to `admin`. Go callers can use `Server{ConfigFile: path}.Serve(ctx)` or supply `CAPublicKey` and `Identities` directly.

**Treat `server.json` as a secret:** do not commit it or include it in logs. It stores the registration token in plaintext. The CA private key remains separately protected on the CA host.

## Client configuration

Set up shared defaults once:

```sh
portal config init --key "$HOME/.ssh/operator" --ca ./ca.pub \
  --coordinator https://inventory.example.com \
  --ca-url https://ca.example.com
portal cert request              # optional: generate a missing key and request approval
portal client --name node-a -- uname -a
portal query --name node-a --query 'process where name = worker*'
```

The default file is `portal/config.json` inside the OS user-config directory: `$XDG_CONFIG_HOME/portal/config.json` or `~/.config/portal/config.json` on Linux, `~/Library/Application Support/portal/config.json` on macOS, and `%AppData%\portal\config.json` on Windows. `config init --config PATH` selects another output file; `--config PATH` on any client, monitor, query, certificate request or refresh command selects it for use. Initialization refuses to overwrite an existing config, creates its directory, and writes the file with mode 0600 (OS ACLs govern access on Windows). It stores only paths and endpoints, not private keys or refresh tokens. Credential files need not exist yet; `cert request` creates the key using the existing approval workflow. `--ca-url` is optional when a certificate already exists.

The JSON fields are `coordinator`, optional `key`, and optional `ca` (trusted SSH CA **public key file or HTTPS URL**, not a private key). Without `ca`, the client discovers ordinary SSH keys as described above. Certificate configurations also accept `cert`, `ca_url`, `refresh_token` (a **file path**, never token contents), and `principal`. Setup stores absolute credential paths and preserves CA URLs; manually written relative file paths resolve against the config file's directory. With `ca` configured, omitted `cert` defaults to `<key>-cert.pub`, omitted `refresh_token` defaults to `<key>.refresh`, and omitted `principal` defaults to `admin`. Nonempty command-line credential/endpoint options override config defaults. A missing default config allows flag-only usage; an explicitly selected missing file or malformed config returns an error. With `ca` configured, clients check that their user certificate is valid for that CA and principal before connecting; this does not authenticate the server with an SSH host certificate. Use HTTPS for a trusted coordinator connection. Go clients use these defaults too and can set `Client.ConfigFile`, `CAFile`, `Principal`, `CAURL`, and `RefreshTokenFile` explicitly. `cert request` and `cert refresh` inherit the saved CA URL, credentials and token path.

In certificate mode, every client connection (commands, queries, capabilities, monitors and MCP tools) checks its certificate before looking up the server. With both `ca_url` and `ca` configured, certificates expiring within **five minutes**, or already expired, are renewed automatically using the saved key-bound refresh token. Healthy certificates do not contact the renewal endpoint. Flag-only clients can pass `--ca-url` and optionally `--refresh-token`; these also override config. Initial enrollment still requires `cert request`: missing or malformed certificates are not silently replaced. Certificates issued manually without renewal configuration remain usable until expiry.

Renewal is headless, bounded to 30 seconds, and verifies the trusted CA, principal, signature and key before installing the result. A cross-process lock at `<refresh-token-path>.lock` serializes token rotation with manual `cert refresh`; automatic callers reload the certificate after acquiring the lock to avoid duplicate refreshes. The new token is atomically saved with mode 0600 before the certificate is atomically replaced (Windows relies on account ACLs). Renewal does not print credential data or alter query JSON output. A failed configured renewal fails the connection with a recovery instruction instead of silently continuing with stale credentials. After the token's 30-day approval lifetime, use `portal cert request` and approve again. This checks on connection, not on a background timer or during an already-open stream. Go callers can force headless renewal with `Client.Refresh(ctx)`, including recovery of a missing certificate.

## Capability discovery

Ask the target server for its versioned, structured query reference using the
same client config and certificate as other requests:

```sh
portal capabilities --name node-a
portal capabilities --name node-a | jq '.sources[] | select(.name == "packets")'

# The same reference is also available inside a snapshot response:
portal query --name node-a --query 'capabilities'
```

The reference describes every data source, event/snapshot/aggregate modes,
output JSON paths and types, units, DSL field aliases, filters and allowed
values, grouping/numeric fields, all seven aggregate functions, examples,
limits, and registered-monitor lifetime/storage semantics. `version` is the
reference schema version; `os` and `arch` describe the **server**, not the client.
In Go, use `Client.Capabilities(ctx)` or inspect `Snapshot.Capabilities` from
`Client.Query(ctx, MonitorRequest{Source: "capabilities"})`.

Each source reports `platform_supported`, `authorized` for the requesting
identity, requirements, and an `unavailable_reason` when platform or
authorization checks fail. These are not runtime health probes: eBPF loading,
tracepoint formats, Docker access, GPU drivers, and other runtime dependencies
can still fail when queried. Discovery never attaches a monitor or collects
host data, and does not expose the server's policy or credentials.

Discovery requires a trusted certificate and an identity mapped to at least
one local account in the server policy. It does **not** require root or access
to the server process's account just to learn the requirements; it grants no
additional access to those sources. Capability requests are signed and cannot
be used as event monitors or aggregates. Upgrade the managed server and client
to use discovery; the coordinator and CA need no changes.

## Event monitors

Clients can attach a long-lived, authenticated monitor to a server. The `syscalls` source uses eBPF on Linux to stream syscall-entry events by default (UTC receipt time, PID, TID, task name, phase, and numeric syscall ID) as JSON lines:

```sh
./portal monitor --name node-a --coordinator http://127.0.0.1:8080 \
  --key operator --ca ca.pub --cert operator-cert.pub --source syscalls \
  --pid 1234 --syscall 0 --syscall 1
```

Select `phase = completion` to pair syscall entry/exit by thread and measure elapsed monotonic time:

```sh
portal query --name node-a --query 'syscalls where phase = completion and syscall in (:fsync,:fdatasync) and stacks = user sum(duration_ns) over 30s by pid, name, user.stack'
portal query --name node-a --query 'syscalls where phase = completion and syscall in (:fsync,:fdatasync) percentile(duration_ns,95) over 30s by pid, name'
```

Syscall filters accept case-sensitive Linux names prefixed with `:`, such as `syscall = :openat`, or mixed lists like `syscall in (:fsync, :fdatasync, 0)`. Numeric IDs remain architecture-specific. Names are sent unchanged to the server and resolved using its native Linux ABI (tables for amd64, arm64, 386 and arm), independent of the client's platform. Unknown names or unsupported name-table architectures return an error before collection starts; numeric-only filters still work without a name table. Compatibility ABIs (such as 32-bit tasks on a 64-bit server) are not translated. API callers can set `syscall_names: ["fsync", "fdatasync"]` alongside numeric `syscalls`; event `syscall` output remains numeric. Update both client and server before using symbolic filters.

Completion events include `duration_ns` and signed `return_value` (negative kernel errno on failure), retaining the task name and optional stacks from **entry**, not exit. Duration includes scheduling, locks and storage waits; it is caller-observed time, not pure device or journal-commit time. Summing concurrent calls yields accumulated task time, which can exceed wall time. Duration/return-value aggregates require completion mode. Only calls whose entry and exit were both observed produce completion data; non-returning calls and unfinished calls at the window boundary are excluded. Kernel restart attempts can appear separately. Pairing uses a 16,384-entry bounded hash (no silent eviction) with thread-exit cleanup. Completion requires readable `raw_syscalls:sys_exit` tracefs metadata and the `sched_process_exit` hook. Existing syscall account scoping and stack root-policy requirements still apply.

Add `paths = true` to capture the first FD argument for `fsync`, `fdatasync`, `read`, `write`, their positional/vectored variants, `ftruncate`, and `fallocate`. Both entry and completion modes support this:

```sh
portal query --name node-a --query 'syscalls where phase = completion and paths = true and syscall in (:fsync,:fdatasync) count, sum(duration_ns), percentile(duration_ns,95) over 30s by pid, file.path'
```

Events include `file.fd` and either `file.path` or `file.error`; unrelated syscalls omit `file`. These fields can be grouped (FD is also numeric) only when paths are enabled. Paths are **captured inside the kernel at syscall entry** and retained through completion, so closing, unlinking or reusing the FD after the call does not change the captured path. The BTF-driven walk crosses mount boundaries and stops at the task's process root. It is best-effort: concurrent rename or shared FD-table changes can still race. Capture is bounded to 32 walk steps and 256 encoded component bytes; missing descriptors, read failures, unsupported pseudo-files and paths beyond those bounds produce an explicit error, not a partial path. Missing grouping fields (including `file.path` on failures and `file.error` on success) form a JSON null bucket rather than failing the query. Missing optional metric values are skipped, not counted as numeric zero. Native 64-bit syscall ABI, runtime kernel BTF and readable `raw_syscalls:sys_enter` metadata are required. Open/openat pathname arguments and file contents are not captured. API callers use `paths: true`; existing account scoping still applies.

Syscall, disk and generic tracepoint events always capture `pid` (thread-group ID), `tid` and `name` (current task's kernel `comm`, up to 15 bytes, potentially different between threads). Disk identity describes the issuing task, not necessarily the application that caused asynchronous writeback. Packet capture does not infer a process owner.

For directory rollups, group by `file.dir`, a projection of the captured path's parent directory. Add `file.depth = 3` to keep its first three components: `/var/lib/datadb/part-123/bloom` and `/var/lib/datadb/part-456/index` both group under `/var/lib/datadb`. Depth zero (default) keeps the full parent directory; valid depths are 0–32. Requires `paths = true` and aggregate mode. Raw paths are unchanged, and unavailable paths form a null bucket.

```sh
portal query --name node-a --query 'syscalls where phase = completion and paths = true and file.depth = 3 and syscall in (:fsync,:fdatasync) count, sum(duration_ns) over 30s by cgroup.path, process_name, file.dir'
```

These events also expose `process_name`, the best-effort full executable basename from procfs, without the kernel's 15-byte truncation. It is resolved at receipt and cached for up to one second, so it may be unavailable after exit or lag exec/PID reuse; kernel threads have no executable name. `name_group` preserves task comm except verified kernel `kworker/*` tasks group as `kworker`. Group by `process_name` for application names or `name_group` to consolidate kernel workers; the original `name` remains available.

`name`, `process_name`, `name_group` and `cgroup.path` are also server-side `where` filters for syscalls, disk and tracepoints. Disk additionally accepts `device_name` and `rwbs`. Filters are ANDed, case-sensitive, and accept exact strings or one prefix/suffix wildcard; missing metadata does not match. Use one `where` and combine conditions with `and`, e.g. `disk where device_name = nvme0n1 and name = worker*`. These string filters run **after capture and enrichment**, so they do not reduce eBPF ring-buffer traffic; collection counters remain subscription-wide.

Task-context events add JSON `cgroup_path` (query field `cgroup.path`) from the event thread's unified cgroup-v2 membership, letting you correlate a workload with the `cgroups` source's `path` and I/O rates. This is **best-effort receipt-time procfs metadata**, cached per PID/TID for up to one second—not a kernel-time identity. It can be missing for exited/invisible tasks or v1-only hosts, and can lag migration or PID/TID reuse. Paths are relative to the server's cgroup namespace; correlating them requires a matching visible cgroup mount. No container ID, Miren app name, host backing-volume mapping or original writeback owner is guessed: a kernel worker's membership is the worker's, not necessarily the application's. Container-relative file paths remain container-relative.

These eBPF sources attach cumulative `collection` counters to streamed events, and aggregates include a final `.aggregation.collection` snapshot. Counters include `ring_buffer_dropped`, `stack_capture_failures`, `stack_collisions` (a subset of capture failures), `pairing_failures`, and `unmatched_exits`. They are subscription-wide, before generic tracepoint user-space filtering: **do not sum cumulative counters across events**, or treat them as exact per-group loss. Unmatched exits include attachment-boundary calls without a captured entry. Streaming collectors can emit `kind = collection_stats` diagnostic-only records on shutdown; these are not syscall/data events. Registered-monitor overwrite remains a separate cursor/history error. A zero kernel-drop count does not guarantee that every in-flight call or queued boundary event was included in an aggregation window.

To keep collecting while the client is disconnected, register a server-owned monitor instead. The same event queries and authorization rules apply:

```sh
./portal monitor-register --name node-a --coordinator http://127.0.0.1:8080 \
  --key operator --ca ca.pub --cert operator-cert.pub \
  --query 'process where name = worker*' # prints a monitor ID
./portal monitor-read --name node-a --coordinator http://127.0.0.1:8080 \
  --key operator --ca ca.pub --cert operator-cert.pub --id MONITOR_ID --after 0
# Disconnect with Ctrl-C; later, use --after with the last processed sequence.
./portal monitor-delete --name node-a --coordinator http://127.0.0.1:8080 \
  --key operator --ca ca.pub --cert operator-cert.pub --id MONITOR_ID
```

`monitor-read` outputs JSON lines of `{ "sequence": N, "event": { ... } }`, first replaying retained events after `--after` and then following new events. Save the sequence **only after processing** each record; supplying it on the next read avoids both skips and duplicates. A new reader can start from `--after 0`. Multiple readers may use independent cursors.

Every streamed event also has `tai64n`, an `@` followed by 24 lowercase hexadecimal digits (8 bytes of TAI seconds and 4 bytes of nanoseconds, big-endian). The existing UTC `time` remains available. TAI64N is assigned at server ingestion and is strictly increasing per monitor, advancing by one nanosecond on clock ties or backward wall-clock adjustments. Buffered replays preserve the original timestamp. UTC conversion uses the known leap-second table through 2017 (TAI−UTC = 37 seconds); the table must be updated for future leap seconds.

To resume by the last processed event's timestamp, use `monitor-read ... --id MONITOR_ID --after-timestamp '@40000000586846a500000000'`, or `Client.ReadMonitorSince(ctx, id, lastEvent.TAI64N, callback)`. This timestamp is part of the signed request. The read starts with the first retained event **strictly newer** than the timestamp, including when the timestamp falls between events. If it predates retained history, the server starts at the oldest retained event as a best-effort continuation; overwritten events cannot be recovered. If it is at or beyond the latest event, the read waits for newer events while the source remains active. `--after` and `--after-timestamp` cannot be combined. Sequence cursors remain the choice for strict history-loss detection.

Registered monitors have an idle TTL of **15 minutes** by default. Override it at creation with `monitor-register ... --ttl 30m`, or `Client.CreateMonitor(ctx, request, 30*time.Minute)` in Go. Omitting the duration (or using zero) selects `DefaultMonitorTTL`; negative durations are rejected. Every authorized read renews the lifetime, for both sequence and timestamp cursors. An active streaming read keeps the monitor alive even when no events arrive; the full TTL restarts when the last reader disconnects. Event production alone does not renew it. Expiry stops the source, discards the ring buffer, and frees the registration slot; subsequent reads return `monitor not found` and require a new registration. The TTL is included in the signed creation request.

The server retains the last 1,024 matching events per registration in memory (up to 16 registered monitors, 8 KiB per event) until deleted, expired, or the server exits. Sources start asynchronously; startup or collection errors stop the producer and are returned by reads after any buffered events. If a sequence cursor falls behind the ring's oldest event, the read fails with an explicit `monitor history lost` error and the oldest available sequence. Go callers can inspect `*MonitorHistoryLostError` and explicitly resume with `after = OldestSequence - 1` if they choose to skip lost history. Finite storage cannot guarantee lossless reads under arbitrary disconnection or event rates, and sources retain their existing best-effort capture limitations. Registration and history do **not** survive a server restart.

A renewed certificate for the same private key can resume a monitor if its current policy still authorizes the source; a different key cannot read or delete it. In Go, use `Client.CreateMonitor`, `Client.ReadMonitor(ctx, id, after, callback)` and `Client.DeleteMonitor`. The existing `Client.Monitor` and `portal monitor` commands remain connection-scoped.

To show packets sent to TCP destination port 80, select the `packets` source and combine generic header filters:

```sh
./portal monitor --name node-a --coordinator http://127.0.0.1:8080 \
  --key operator --ca ca.pub --cert operator-cert.pub \
  --query 'packets where protocol = tcp and direction = outgoing and dst.port = 80'
```

To watch a process name across starts and exits, use the cross-platform `process` source:

```sh
./portal monitor --name node-a --coordinator http://127.0.0.1:8080 \
  --key operator --ca ca.pub --cert operator-cert.pub \
  --query 'process where name = "worker"'
```

Process names can also use one edge glob: `name = worker*` matches names beginning with `worker`, and `name = '*Helper'` matches names ending in `Helper`. An exact name still requires an exact match; interior `*` and a lone `*` are rejected. The same patterns work with `--process-name`.

Each process event includes a PID and `process` with the exact process name and `start` or `exit` action. Filter by `pid`, `name` and/or `action` (for example, `process where name = "Google Chrome Helper" and action = start`). This source polls the server's process table once per second using native OS process-listing implementations, **not eBPF**. Processes already running when the monitor attaches form its initial baseline, not start events. Processes that start and exit between polls may be missed; timestamps indicate when a change was observed. PID reuse is distinguished by creation time. On Linux and macOS a non-root server reports only its own account's processes, while a root server can report all processes to identities authorized for root. On Windows it reports only processes belonging to the server account. Windows commands cannot switch to another user; eBPF sources require Linux. The process source builds on Linux, macOS and Windows.

To query the current process table instead of waiting for lifecycle events, use the one-shot snapshot mode:

```sh
./portal query --name node-a --coordinator http://127.0.0.1:8080 \
  --key operator --ca ca.pub --cert operator-cert.pub \
  --query 'process where name = worker*'
```

The command returns one JSON object with a `source`, `time`, and a `processes` array of `pid`, `name`, and `started` timestamps. `process` can be filtered by `pid` and/or `name`; no matches returns `"processes":[]`. The Go API is `Client.Query(ctx, MonitorRequest{Source: "process", PID: 1234})`, returning a `Snapshot`. It uses the same signed request and policy checks as `Client.Monitor`, with the snapshot mode included in the signature. The process listing is a best-effort observation during enumeration, not an atomic system-wide instant. `action` is only meaningful for start/exit events and is rejected in snapshots.

Other one-shot sources use the same `portal query --query 'SOURCE [where name = PATTERN]'` command:

| Source | Snapshot field | Data |
| --- | --- | --- |
| `cpu` | `cpu` | Per-core cumulative user/system/idle/I/O-wait/steal seconds; compare samples to calculate utilization |
| `memory` | `memory` | RAM total, available, used, and swap totals in bytes |
| `network` | `network` | Interface name, index, MTU, addresses, flags, and cumulative RX/TX byte and packet counters |
| `kernel` | `kernel` | Boot time, uptime seconds, 1/5/15-minute load averages, and context-switch/running/blocked counters where available |
| `sensors` | `sensors` | Available temperature readings in Celsius, including high/critical thresholds when reported |
| `containers` | `containers` | Docker ID, name, image, and state, including stopped containers |
| `cgroups` | `cgroups` | Linux cgroup v2 paths, identities, CPU accounting/quota, memory accounting/limit, task counts, and per-device I/O accounting |
| `gpu` | `gpus` | Nvidia GPU index, UUID, name, and available temperature, utilization, memory, and power readings |

`network`, `sensors`, `containers`, and `gpu` support `where name = ...` with exact names or one leading/trailing `*` glob, for example `network where name = eth*`. `cgroups` instead supports `where path = ...` with the same edge-glob rules. Other sources do not take filters. An empty collection is returned as `[]`; metric fields unavailable from `nvidia-smi` are omitted. Docker requires Linux, a readable `/var/run/docker.sock`, a root server and **root query authorization** (certificate policy, root account keys, or query-only delegation), because it exposes other workloads' metadata. GPU queries require `nvidia-smi` installed on the server and an Nvidia driver. Missing dependencies and unsupported platforms return errors, not fabricated empty results. Sensors depend on the host's exposed sensors and may legitimately be empty. Packet, syscall, disk, and tracepoint sources represent transient events rather than retained current state, so snapshot mode rejects them.

### Cgroup resource usage

`cgroups` reads the server's visible **cgroup v2** hierarchy at `/sys/fs/cgroup`, independently of Docker or any container runtime. It requires Linux, a root server, and root query authorization (certificate policy, root account keys, or query-only delegation), since groups may expose other workloads. Cgroup v1 and missing/non-v2 mounts return errors. In a cgroup namespace or container, the source only sees the mounted subtree; `/` means that visible root, not necessarily the host root. Paths returned in `cgroups[]` are relative to the mount and begin with `/`.

| Field | Meaning |
| --- | --- |
| `path`, `id` | Visible path and filesystem device/inode identity |
| `cpu_seconds` | Cumulative CPU usage from `cpu.stat` (`usage_usec` converted to seconds) |
| `cpu_limit_cores` | Locally configured `cpu.max` quota divided by period, when finite |
| `memory_bytes` | Current charged memory, including page cache; not process RSS |
| `memory_limit_bytes` | Locally configured finite `memory.max` limit |
| `memory_anon_bytes`, `memory_file_bytes` | Anonymous memory and file cache from `memory.stat` |
| `pids_current` | Current tasks, including threads |
| `io.read_bytes`, `io.write_bytes`, `io.discard_bytes` | Cumulative `io.stat` bytes summed across devices |
| `io.read_ios`, `io.write_ios`, `io.discard_ios` | Cumulative `io.stat` operation counts summed across devices |
| `io.devices[]` | Device `major:minor` and raw `counters` (`rbytes`, `wbytes`, `rios`, `wios`, `dbytes`, `dios`, plus future kernel keys) |

Controller files may be absent, especially on the hierarchy root or when controllers are disabled; unavailable fields are omitted, and unlimited limits (`max`) are omitted rather than encoded as zero. Present zero usage remains zero. Permission/read failures and malformed metrics fail the query. Snapshots are best-effort observations, not atomic reads across controller files. Up to 4,096 matching groups are returned; exceeding that bound fails explicitly, so narrow the path filter on large systems.

Missing `io.stat` omits `io`; an existing empty file yields zero totals and `devices: []`. A total is omitted if any listed device lacks that counter, rather than reporting an incomplete sum. Up to 4,096 devices per group are supported. Device rows retain all counters; malformed/duplicate rows, values, and total overflow fail explicitly. I/O usage includes descendants: do not sum a parent and its children as independent workloads. Attribution follows the kernel's cgroup I/O/writeback accounting and filesystem support; it does not guarantee that journal/shared writeback costs are charged to the originating application, and operation counts are not fsync or flush counts.

Sampled aggregates add `cpu_percent` and `cpu_seconds_per_second` through the generic sampler. **100% means one busy core**, so usage can exceed 100%; it is not normalized to quota. Limits describe the group's own configuration, not effective restrictions from ancestors or cpusets. Directory identity is part of the CPU baseline, so recreating a group at the same path starts a new baseline even when its new counter is larger.

I/O totals are counters, not gauges. Sampled aggregates derive `io.read_bytes_per_second`, `io.write_bytes_per_second`, `io.discard_bytes_per_second` (bytes/s) and `io.read_ios_per_second`, `io.write_ios_per_second`, `io.discard_ios_per_second` (operations/s). These use actual elapsed time and skip the initial baseline, missing values, cgroup recreation, device-set changes and per-device resets—even when a reset is hidden by another device's increasing counter. Sampling aggregates cgroup totals; individual device rows are available in snapshots, not exploded into separate sampled records.

```sh
portal query --name node-a --query 'cgroups where path = /system.slice/*'
portal query --name node-a --query 'cgroups avg(cpu_percent) over 30s every 1s by path'
portal query --name node-a --query 'cgroups max(memory_bytes) over 30s every 1s by path | .aggregation.values | sort_by(.value) | reverse | .[:10]'
portal query --name node-a --query 'cgroups avg(io.read_bytes_per_second), avg(io.write_bytes_per_second), max(io.write_ios_per_second) over 30s every 1s by path'
```

Usage includes descendants: **do not sum overlapping parent and child groups**, which would double-count usage. Prefix globs match all descendant depths; `/system.slice/*` is a literal prefix filter, not a shell glob restricted to one level. Omit `where` to enumerate all visible groups, including `/`. Add `id` to grouping (`by path,id`) to return different lifetimes separately. The source supports snapshots and sampled aggregates, not event monitors; capability discovery describes its fields, units, filters, and requirements.

To observe block requests issued to a device on Linux, use the eBPF `disk` source:

```sh
./portal monitor --name node-a --coordinator http://127.0.0.1:8080 \
  --key operator --ca ca.pub --cert operator-cert.pub \
  --query 'disk where operation = write and device = 0x800'
```

Each disk event includes the kernel device ID, start sector, sector count (512-byte sectors), and operation (`read`, `write`, `discard`, `flush`, or `other`). Filters `device` (decimal or `0x` hex ID) and `operation` (`read`, `write`, `discard`, `flush`) may be combined or omitted; the equivalent flags are `--source disk --device 0x800 --operation write`. By default this traces `block:block_rq_issue`, with issuing PID/TID/name but no filesystem paths or file contents. Operation and device filters in entry mode run inside eBPF before records reach user space, then are checked again before streaming. The source needs a readable tracepoint `format` under tracefs and permission to attach eBPF tracepoints. Its layout is discovered at attachment time; unsupported kernel formats fail explicitly. Capture is best-effort under load.

Select `phase = completion` for block request latency:

```sh
portal query --name node-a --query 'disk where phase = completion count, avg(duration_ns), percentile(duration_ns,95) over 30s by device, pid, name'
portal query --name node-a --query 'disk where phase = completion and operation = write percentile(duration_ns,99) over 30s by device, status'
```

Completions pair by **kernel request pointer**, not device/sector, preserving identity and request metadata from issue. `disk.duration_ns` (aggregate field `duration_ns`) is monotonic time from the **latest issue** to completion of all bytes; it excludes pre-issue scheduler queueing. Partial completions produce a single final event, including for zero-byte flushes. `disk.status` (aggregate field `status`) is zero on success or the last nonzero kernel `blk_status_t` seen across completions—not a negative errno. Reissues reset identity, byte accounting and timestamp, so this is not total latency across retries. Only requests observed issuing and completing within collection contribute. Issuing PID is not definitive application attribution for asynchronous writeback; use cgroup I/O accounting for workload totals.

Completion mode requires a native 64-bit server/kernel ABI, kernel BTF plus supported `request`, `request_queue`, `gendisk` and raw block tracepoint layouts; unsupported kernels fail explicitly without guessing offsets. Pending requests occupy a bounded 16,384-entry hash; requests without final completion remain until collector teardown. `pairing_failures`, `unmatched_exits` (unmatched block completions here), and ring-buffer drops are reported through collection counters. Completion operation/device filters run after pairing in server user space, so counters cover all captured requests, not just filtered groups. Both phases require a root server and root query authorization (certificate policy, root account keys, or query-only delegation). Upgrade client and server together before using these new fields.

Both disk phases expose `rwbs` for grouping: optional leading `F` means preflush, followed by operation `R`/`W`/`D`/`F`/`N` (`DE` is secure erase), then `F` (force-unit-access), `A` (readahead), `S` (sync) and `M` (metadata). For example, `FWFSM` is a preflush write with FUA, sync and metadata—not a flush operation. On supported BTF kernels, both phases reconstruct the string from issue flags using runtime BTF bit positions and expose raw `request_flags`. Entry falls back to the tracefs collector otherwise; it reads the C string only up to the first null, ignoring stale bytes after its terminator. `device_name` adds a best-effort sysfs name such as `nvme0n1` alongside the unchanged numeric device ID.

Disk events also carry `disk.io_cgroup_id`, `io_cgroup_path` and `io_cgroup_error` (query fields `io.cgroup.id`, `io.cgroup.path`, `io.cgroup.error`). The ID is the first bio's block-cgroup association, captured **inside the kernel at issue** through `request.bio.bi_blkg.blkcg.css.cgroup.kn.id`, and retained through completion. Ordinary block-layer merges require matching associations. This is distinct from the issuer's `cgroup.path`, so asynchronous cgroup-aware writeback can retain its workload ownership even when a root-cgroup kernel thread issues it. The ID is a kernel kernfs identifier; it corresponds to the cgroup directory inode on the required native 64-bit ABI, not the `cgroups` source's composite device:inode ID. The optional path is resolved against the server's visible `/sys/fs/cgroup` v2 mount with a bounded cache refreshed at most once a second. It can be unavailable after removal or outside the visible namespace; the captured ID remains available. `io.cgroup.path` accepts exact/edge-glob filters after enrichment.

**Not all kernel writes have an application owner.** Shared journal/metadata writes may genuinely retain root ownership, and synthetic device-wide flushes may have no bio at all. Missing `CONFIG_BLK_CGROUP`, unsupported BTF, failed reads or invisible paths produce explicit errors/null grouping buckets, never an issuing-task fallback. Capturing this association is not proof of backing-volume mapping, per-application ownership of shared journal commits, or one-to-one correspondence between requests and `io.stat` operations.

```sh
portal query --name node-a --query 'disk where operation = write count, sum(sectors) over 30s by device_name, io.cgroup.path'
portal query --name node-a --query 'disk where phase = completion and io.cgroup.path = /apps/postgres* count, percentile(duration_ns,95) over 30s by device_name, io.cgroup.path'
```

Completion diagnostics include `collection.block_issues`, `block_completions`, and `block_reissues`. These count kernel callbacks before output filtering, not distinct I/Os. `block_partial_completions` counts matched callbacks retaining a pending request; `block_final_completions` counts matched final callbacks before ring-buffer output (one data event per final callback, subject to drops and filters). At quiescence, `block_completions = block_partial_completions + block_final_completions + unmatched_exits`; snapshots read during capture may briefly span concurrent updates. `unmatched_exits` counts callbacks without a pending pointer, including repeated/partial callbacks; it is not a count of unique missed requests. Completion callbacks can legitimately outnumber issues. Use these counters together with `pairing_failures` to investigate attachment-boundary requests or other pairing gaps; a large unmatched count alone does not establish the cause.

For probes not covered by a built-in event type, `tracepoint` attaches to a named Linux tracepoint and streams selected scalar integer fields from the **server's** kernel format. For example, to observe processes waking on CPU 2:

```sh
./portal monitor --name node-a --coordinator http://127.0.0.1:8080 \
  --key operator --ca ca.pub --cert operator-cert.pub \
  --query 'tracepoint where event = sched:sched_wakeup and fields in (pid, target_cpu, prio) and field.target_cpu = 2'
```

`common_pid` is supported via the eBPF current-task helper because the kernel hides the trace header from tracepoint programs. Other header fields (`common_type`, `common_flags`, and `common_preempt_count`) are rejected rather than returning invalid data. `common_pid` identifies the task/thread executing the tracepoint, not necessarily the application that originally requested the work. In particular, block I/O may be issued by kernel workers after asynchronous writeback or request merging; grouping `block:block_rq_issue` by `field.common_pid` is issuing-task attribution, not exact per-application disk accounting.

The result has `tracepoint.event` (`sched:sched_wakeup`) and `tracepoint.fields` (a map of exact JSON integer values), alongside the UTC receipt `time`. The probe name is `category:name`; `fields in (...)` selects 1–16 names from `/sys/kernel/tracing/events/CATEGORY/NAME/format` (or debug tracing). Add `field.NAME = NUMBER` for equality filters on selected fields; negative decimal and `0x` hex numbers are accepted. Field names are case-sensitive to the kernel format and numeric filters are applied **on the server after eBPF collection**, before streaming; these filters do not reduce ring-buffer traffic. The running kernel must expose the tracepoint and support ring buffers. Pointer, array, bitfield and dynamic (`__data_loc`) fields are rejected, not decoded as arbitrary memory; no arbitrary ELF/eBPF programs or kprobe/uprobe/XDP hooks are loaded. This source requires a root server **and root query authorization** (certificate policy, root account keys, or query-only delegation) because tracepoints can expose other accounts' activity. It is event-only; on non-Linux servers it returns an unsupported-platform error.

The query DSL has the form `SOURCE [where FIELD = VALUE [and FIELD = VALUE ...]]`. Event sources are `process`, `packets`, `syscalls`, `disk`, and `tracepoint`. Process fields are `pid`, `name` and `action` (`start` or `exit`); `name` accepts exact names or a leading/trailing `*`. Packet fields are `protocol` (`tcp` or `udp`), `direction` (`incoming` or `outgoing`), `src.ip`, `dst.ip`, `src.port`, and `dst.port`. Syscall fields are `pid` and `syscall`; `syscall in (0, 1, 9)` selects several syscall IDs. Disk fields are `device` and `operation`. Tracepoint requires `event = CATEGORY:NAME` and `fields in (NAME, ...)`, with optional `field.NAME = NUMBER` filters. For example, `syscalls where pid = 1234 and syscall in (0, 1)` selects read/write entries for a process. The parser uses PeggySue. Keywords and condition names are case-insensitive; kernel tracepoint field names are case-sensitive. Quote values with spaces or quotes. All conditions are combined with `and`; `or` and negation are not supported. `==` is a synonym for `=`. Numeric event comparisons and range bounds are described below. Omit `where` to match all supported events from sources other than `tracepoint`. The Go API exposes `ParseMonitorQuery(query)` to produce a `MonitorRequest` for `Client.Monitor(ctx, request, callback)`. `--query` cannot be combined with source/filter flags; the existing flags remain available as an alternative.

Each packet JSON event contains `packet` with protocol, direction, source/destination IPs and ports, full frame length, and up to 2048 raw Ethernet-frame bytes in base64 `data`. This shows **individual packets**, not reassembled or decrypted TCP streams. It accepts Ethernet IPv4/IPv6 (including up to two VLAN tags); IPv6 extension headers and noninitial IPv4 fragments are not decoded. Capture is best-effort under load.

Filters are part of the signed request and applied on the server: syscall PID/ID filters run in eBPF before the ring buffer; the packet eBPF socket filter admits IP frames and limits captured bytes, then the server parses and checks packet-header filters before forwarding. Omit `--pid` and `--syscall` to match all syscalls, or packet flags to match all supported TCP/UDP packets. The Go API accepts `Client.Monitor(ctx, MonitorRequest{Source: "packets", Packet: &PacketFilter{Protocol: "tcp", Direction: "outgoing", DestinationPort: 80}}, callback)` (or `Source: "syscalls"` with `PID` and `Syscalls`). Cancel the context or return an error from the callback to detach. Syscall IDs depend on the server architecture.

Syscall monitoring requires policy access to the server process's account. Non-root servers export only events from that account; a root server with a policy allowing the client to act as root can export system-wide events. Packet capture, disk, and generic tracepoint monitoring require a root server and **explicit `root` authorization** for the client identity in the policy, since they can expose other users' activity. The server also needs Linux eBPF privileges to load programs and attach tracepoints or a packet-socket filter, plus CAP_NET_RAW for packet capture. If unavailable, the stream returns the source error. Treat event data as sensitive and grant root access only to identities that should see it.

## Server-side aggregations

Append an aggregate followed by `over DURATION [every INTERVAL] [by FIELD, ...]` to a query. The server collects a **new** window of matching events or sampled snapshots, maintains aggregate state rather than storing raw records, and returns one JSON result after the window ends. Each query selects one aggregate:

| Function | Meaning |
| --- | --- |
| `count` | Number of matching events or observed snapshot records |
| `sum(FIELD)` | Sum of numeric values |
| `avg(FIELD)` | Arithmetic mean, rounded to at most 18 decimal places, without trailing zeros |
| `min(FIELD)` / `max(FIELD)` | Smallest / largest numeric value |
| `count_distinct(FIELD)` | Exact number of distinct scalar values, including strings |
| `percentile(FIELD, PERCENT)` | Exact nearest-rank percentile, with a finite percentage from 0 to 100 |
| `hist(FIELD)` | Log-scale histogram of numeric values in the field's native units |
| `rate(COUNTER)` | Sampled cumulative counter deltas per observed second |

Numeric results are JSON numbers, not formatted strings. Integers remain exact; fractional reductions round to at most 18 decimal places and omit trailing zeros (for example `1618242`, not `1618242.000000000000000000`).

`hist` returns `{count, zero_count, buckets: [{lower, upper, count}, ...]}` with only occupied buckets, sorted by lower bound. Bounds are exact, lower-inclusive and upper-exclusive, with four equal sub-buckets per power-of-two range; zero is counted separately. Signed and fractional fields work too. For `duration_ns`, 9.6ms and 14ms land in different buckets: [8388608, 10485760) and [12582912, 14680064) nanoseconds. An empty histogram has count zero and an empty bucket list. Each occupied bucket consumes one slot in the query-wide 65,536 retained-value budget. Sort/limit by a numeric sibling metric, not by the histogram object.

```sh
portal query --name node-a --query 'disk:completion where duration_ns > 5ms {
  @slow[device: device_name] = {ops: count(), latency: hist(duration_ns)}
} after 30s { emit @slow order by ops desc limit 10 }'

portal query --name node-a --query 'cgroups rate(io.write_ios), rate(io.write_bytes), max(memory_bytes) over 30s every 1s by path'
```

```sh
# Linux x86-64: count legacy open(2) syscall entries by process for 30 seconds.
portal query --name node-a --query 'syscalls where syscall = 2 count over 30s by pid'

# Named Linux tracepoint, when exposed by the server kernel:
portal query --name node-a --query 'tracepoint where event = syscalls:sys_enter_open and fields in (common_pid) count over 30s by field.common_pid'

# Modern libc often uses openat/openat2 instead of open. Linux x86-64 IDs:
portal query --name node-a --query 'syscalls where syscall in (2,257,437) count over 30s by pid'

portal query --name node-a --query 'process where action = start count over 1m by name'
portal query --name node-a --query 'packets where protocol = tcp and dst.port = 80 count over 30s by src.ip,dst.port'
portal query --name node-a --query 'disk where operation = write count over 30s by device'

portal query --name node-a --query 'packets where protocol = tcp sum(length) over 30s by dst.ip'
portal query --name node-a --query 'disk avg(sectors) over 30s by device'
portal query --name node-a --query 'disk min(sectors) over 30s by device'
portal query --name node-a --query 'disk max(sectors) over 30s by device'
portal query --name node-a --query 'process count_distinct(name) over 1m'
portal query --name node-a --query 'packets percentile(length, 95) over 30s by dst.port'
```

Syscall numbers depend on the **server architecture**. These count syscall **entries/attempts**, not successful opens or currently open files. Named `sys_enter_openat` and `sys_enter_openat2` tracepoints can be selected separately when present. Tracepoint `common_pid` is a task/thread ID; the `syscalls` source's `pid` is the process/thread-group ID. Tracepoint queries retain their root/policy requirements.

Results retain `source` and `time` (window end) and add `aggregation` with UTC `start`, `end`, `group_by`, and `counts`. For example, the counts might be `[{"group":{"pid":123},"count":7},{"group":{"pid":456},"count":2}]`. Group values retain their JSON scalar types and full-width integer precision. Omitting `by` returns one total count, including zero if nothing matches; an empty grouped window returns `counts: []`.

Other functions return `function`, `field`, and `values` instead of `counts`, with entries such as `{"group":{"device":2048},"value":1234}`; percentiles also carry `percentile` (omitted zero means the minimum). In Go, `AggregationResult.Values` contains `AggregateValue` entries whose `Value` is `json.RawMessage`, preserving numeric precision. For an empty ungrouped window, `sum` and `count_distinct` return zero; `avg`, `min`, `max`, and `percentile` return `null`. An empty grouped window returns `values: []`. Reductions use exact rational arithmetic: integer results do not wrap at 64 bits, and decimal results round to 18 places. Use a precision-preserving JSON decoder if consuming large values outside the Go API.

Use comma-separated functions for **multiple aggregates over the same window**:

```sh
portal query --name node-a --query 'disk count, sum(sectors), percentile(sectors,95) over 30s by pid, name, device'
portal query --name node-a --query 'tracepoint where event = block:block_rq_issue and fields in (nr_sector) and stacks = kernel count, sum(field.nr_sector) over 30s by kernel.stack'
portal query --name node-a --query 'syscalls where phase = completion and syscall in (:fsync,:fdatasync) and stacks = user count, sum(duration_ns), percentile(duration_ns,95) over 30s by pid, user.stack'
```

All functions receive the same matching events from **one subscription**, or the same snapshots from **one sampler**; they share filters, window, sampling interval and grouping. This is not multiple queries run consecutively, or a cross-source join. Multi-function output has `aggregation.metrics` in request order, with each entry using the existing `function`/`field`/`percentile` and `counts` or `values` format plus the same window/grouping. Single-function queries keep their existing result format. Collection-loss counters describe the entire shared capture and appear once at `aggregation.collection`. For example, `| .aggregation.metrics[] | select(.function == "sum") | .values` selects a sum's values (also filter by `.field` if selecting several sums).

Add `result.format = rows` for compact output: `aggregation.columns` describes the functions in request order, and `aggregation.rows` contains one `{group, values}` per group. Long stack strings appear only once per row. Missing group metrics are null, not fabricated zeros. MCP JSON aggregates without a jq suffix default to this shape; `format: "legacy"` opts out. CLI/API defaults and existing jq pipelines retain the legacy shape unless you explicitly request row controls.

`result.nonzero = true` omits rows only when **all** values are numeric zero (nulls remain). `result.limit = N` returns the top N rows sorted descending by `result.sort_metric` (zero-based, default first), with exact numeric comparisons, deterministic ties and nulls last. Limit is 0–4096; zero means unlimited. These controls imply row format and apply after collection, not before aggregation; they do not relax storage/group limits. `total_groups` reports groups before filtering/limiting and `omitted_zero_groups` reports all-zero rows removed. Folded output cannot be combined with row controls.

```sh
portal query --name node-a --query 'syscalls where phase = completion and paths = true and syscall in (:fsync,:fdatasync) and result.format = rows and result.limit = 10 and result.sort_metric = 1 count, sum(duration_ns), percentile(duration_ns,95) over 30s by process_name, file.path'
portal query --name node-a --query 'cgroups where result.nonzero = true and result.limit = 10 avg(io.write_bytes_per_second) over 30s every 1s by path'
portal query --name node-a --query 'disk where phase = completion and result.format = rows count, avg(duration_ns) over 30s by device_name, rwbs, name_group'
```

At most eight distinct metrics are allowed; duplicate function/field/percentile combinations are rejected. All metrics share the query-wide 65,536 retained-value budget; each supports up to 4,096 groups. For sampled snapshots, unavailable fields are skipped **independently per metric**: a rate can skip its baseline while `count` or a memory gauge still uses that observation. Thus metrics may legitimately have different numbers of usable samples. API callers set `AggregationRequest.Metrics: []AggregateMetric{{Function: "count"}, {Function: "sum", Field: "sectors"}}` alongside the common `Window`, `Every` and `GroupBy`, instead of setting the top-level `Function`, `Field` or `Percentile`. Both client and server must support the extension.

Percentiles sort numeric observations and select the nearest rank: for a nonempty group, rank is the ceiling of percentage × sample count / 100, clamped to at least one. Thus 0 returns the minimum, 100 the maximum, and 50 selects the lower middle sample for an even-sized group; there is no interpolation or approximate reduction. Percentile storage is capped at 65,536 samples **across the entire query**, and distinct counting at 65,536 retained `(group, value)` pairs. Duplicates within a distinct group consume no additional capacity. Exceeding a cap fails explicitly rather than returning a partial or approximate result. Sum, mean, and extrema do not retain individual samples.

Available event aggregate/grouping fields are `pid`, `tid`, `syscall` for syscalls; `pid`, `name`, `action` for process events; `protocol`, `direction`, `src.ip`, `dst.ip`, `src.port`, `dst.port`, `length` for packets; `device`, `operation`, `sector`, `sectors` for disk; and selected `field.NAME` values for tracepoints. Numeric functions on event sources accept integer fields: process `pid`, packet ports and `length` (full captured frame length in bytes), disk `device`, `sector` and `sectors` (512-byte sector units), and all syscall/tracepoint fields. Strings can be grouped or counted distinctly, not summed or averaged. These additions do not change the available `where` filters. Up to four grouping fields can be combined. Windows must be positive and at most one hour. More than 4,096 groups fails explicitly rather than returning truncated results.

For event sources, the window is half-open `[start, end)` using server ingestion time, beginning immediately before the source is attached; attachment time is included and events outside that interval are excluded. This does not query registered-monitor history. Collection is still best-effort according to each source's capture limits. Disconnecting or canceling stops collection; source failures and premature termination return errors, not a misleading complete result. Filters, function, field, percentile, grouping fields, window duration, and sampling interval are signed and checked server-side with the existing source authorization rules. `portal monitor` and registered monitors reject aggregation queries; use `portal query` or `Client.Query(ctx, request)`, where `request` comes from `ParseMonitorQuery` or specifies `Aggregation: &AggregationRequest{Window: 30*time.Second, Function: "sum", Field: "length", GroupBy: []string{"dst.ip"}}` with `Source: "packets"`. Omitted `Function` still means `count`. The result is in `Snapshot.Aggregation`.

### Selector/action queries

The original DSL remains supported. Alternatively, separate event selection from aggregation actions and reporting:

```sh
portal query --name node-a --query '
syscalls:completion where syscall in (:fsync, :fdatasync) {
  let caller = stack.user(from: ["os.(*File).Sync", glob("*Fdatasync")], offsets: false)
  let directory = path.prefix(file.path, 3)
  @syncs[process_name, directory, caller] = {
    calls: count(), elapsed: sum(duration_ns), p95: percentile(duration_ns, 95)
  }
} after 30s { emit @syncs order by elapsed desc limit 25 }'
```

`let` defines a field alias or supported projection, not a general expression. Stack and file projections automatically request capture. Stack functions are `stack.user(...)` and `stack.kernel(...)`, with named options `offsets`, `from`, `until`, `top`, `drop_top`, and `drop_bottom`. Stack patterns use double-quoted literal names (including Go pointer methods) or explicit `glob("prefix*")` / `glob("*suffix")`; literal names beginning or ending with `*` are not supported. `from` accepts a list of alternatives. `path.prefix(file.path, N)` groups by the parent directory truncated to N components. Aliases become output grouping keys.

The selector may be a bare source, `syscalls:entry` / `syscalls:completion`, `disk:entry` / `disk:completion`, `process:start` / `process:exit`, or `tracepoint:CATEGORY:NAME`. Selector/action tracepoints infer payload fields from `field.NAME` references in predicates, locals, grouping, and metrics. An explicit `where fields in (...)` is optional and is combined with inferred fields, deduplicating inferred references (maximum 16 selected fields). Count-only or identity/stack-only probes select no payload fields; task identity is still captured. Unsupported kernel fields still fail explicitly. The original DSL continues to require an explicit field list. Predicates reuse existing server filters, supporting `=` / `==`, `in (...)` or `in [...]`, and `and`. Existing predicate glob semantics are unchanged. This syntax is case-sensitive, uses double-quoted strings, and does not support comments.

Both syntaxes support numeric event comparisons `>`, `>=`, `<`, and `<=`. For example:

```sh
portal query --name node-a --query '
disk:completion where device_name = "nvme0n1" and duration_ns > 5000000 {
  @slow[name_group, rwbs] = {ops: count(), p99: percentile(duration_ns, 99)}
} after 30s { emit @slow order by ops desc limit 15 }'
```

`duration_ns > 5000000 and duration_ns <= 20000000` selects operations longer than 5ms and at most 20ms. Comparisons accept available numeric event fields, including selected `field.NAME`, signed `return_value`, packet `length`, and completion `duration_ns`. Completion-only fields require a completion selector (or `phase = completion` in the original DSL). Missing optional values do not match. Thresholds are exact decimal integers/fractions or hexadecimal integers, at most 128 bytes, with no float rounding for full-width counters; leading-zero integers remain decimal. At most 16 comparisons can be combined with `and`. They run server-side after capture, before streaming/storage/reduction, and do not reduce kernel capture traffic. They are not supported for snapshots or sampled snapshot aggregates. API callers use `MonitorRequest.Comparisons`, containing `{Field, Op, Value}` predicates; these are signed and validated just like other filters. Syntax errors show a plain-language message, line/column, and source caret rather than internal parser rules.

Both syntaxes also accept duration literals specifically for `duration_ns`, for example `duration_ns > 5ms and duration_ns <= 1s`, `1.5ms`, or `250us`. Units are `ns`, `us`/`µs`/`μs`, `ms`, `s`, `m`, and `h`, using Go duration semantics and nanosecond resolution. The client converts these to integer nanoseconds before signing; API comparison values remain numeric. Unit literals are rejected for unrelated fields, so `length > 5ms` cannot accidentally mean five million bytes.

Scripts support up to eight selector/action blocks, with one named table per block and shared reporting blocks at the end. Table names must be unique across the script; locals are scoped to their selector. Table groups use existing fields, local aliases, or inline `ALIAS: FIELD/PROJECTION` entries; `[]` means ungrouped. For example, `@j[proc: process_name, caller: stack.user(offsets: false)]` names the output group keys without separate `let` statements. Aliases must be unique identifiers; a field cannot be grouped twice. Values are named aggregate functions, or a lone function such as `@traffic[src.ip] = sum(length)` (column name `value`). Available functions are `count()`, `sum`, `avg`, `min`, `max`, `count_distinct`, `percentile`, `hist`, and `rate`. Results use compact `aggregation.table`, `columns` with metric names, and `rows` with separate `group` and named `values` objects. Optional `order by METRIC asc` or `desc` and `limit N` apply to output, not collection. Ascending limits select the lowest values; nulls stay last in both directions and ties are deterministic. Without an explicit order, existing descending behavior is unchanged. API callers can set `AggregationRequest.Ascending` (default false). CLI/MCP queries accept this syntax and the usual trailing jq stage. Both client and server must support this extension.

Named-table rows are shaped like:

```json
{"group":{"proc":"postgres"},"values":{"ops":724,"p99":3800000}}
```

Use `.aggregation.rows[] | {proc: .group.proc, ops: .values.ops, p99: .values.p99}` in a trailing jq stage, or `.windows[].rows[] | .values.ops` for periodic results. Names do not depend on declaration order; missing metrics remain explicit `null`, not zero. Group and metric names occupy separate objects, so a metric can have the same name as a group without collisions. Columns retain function/field/percentile metadata. A lone aggregate is addressed as `.values.value`.

Original-DSL compact queries keep positional `values` arrays. Named selector/action tables now emit objects instead: update existing named-table jq expressions from `.values[INDEX]` to `.values.NAME`, and update both client and server. The Go API retains `AggregateRow.Values` aligned with `Columns`; its JSON decoder accepts either format. No duplicate positional array is emitted for named tables.

```text
tracepoint:jbd2:jbd2_handle_start {
  @j[proc: process_name] = {
    handles: count(), blocks: sum(field.requested_blocks)
  }
} after 30s { emit @j order by blocks asc limit 15 }
```

This infers `requested_blocks` from the body; no repeated field list is necessary.

For finite periodic reports, keep one subscription open and clear the table between buckets:

```sh
portal query --name node-a --query '
disk:completion where operation = write {
  @writes[device_name, io.cgroup.path] = {
    requests: count(), sectors: sum(sectors), p95: percentile(duration_ns, 95)
  }
} every 30s { emit @writes order by sectors desc limit 10; clear @writes }
  after 5m { stop }'
```

These are **non-overlapping buckets, returned together when the query finishes**, not live streaming or rolling windows. Results are in `Snapshot.Windows` / JSON `windows`; the last bucket is shortened if necessary. Empty buckets are included. Assignment uses server receipt time, not event timestamps. The final bucket carries subscription-wide collection counters, not per-bucket loss estimates. Periodic reports require event sources, an interval of at least 100ms, at most 64 buckets, and a total duration of at most one hour. All buckets/metrics share 4,096 retained metric groups and 65,536 retained values; output is capped at 7 MiB. Limits fail explicitly rather than silently truncating capture.

Snapshot-only sources support one-shot action aggregates with their normal default sampling interval (for example `memory { @usage[] = avg(used) } after 5s { emit @usage }`), not periodic action reports. Process actions currently select lifecycle events. There is no arbitrary scripting, event-level correlation, shared-table accumulation across selectors, or persistent aggregate monitor. Completed tables can be joined as described below. Actions lower to the same signed and validated requests and policy checks as the original DSL. API equivalents add `Table`, metric `Name`, `GroupAliases`, and `ReportEvery` to `AggregationRequest`; `ReportEvery` is separate from the existing snapshot sampling `Every`.

#### Multiple sources in one script

Compare file flushes and disk completions over the same observation window:

```sh
portal query --name node-a --query '
syscalls:completion where syscall in (:fsync, :fdatasync) {
  @flushes[proc: process_name] = {ops: count(), total_ns: sum(duration_ns)}
}
disk:completion where device_name = "nvme0n1" {
  @io[io.cgroup.path, rwbs] = {ops: count(), sectors: sum(sectors), p99: percentile(duration_ns, 99)}
}
after 30s {
  emit @flushes order by total_ns desc limit 15;
  emit @io order by sectors desc limit 15
}'
```

Each selector has its own filters, capture settings, subscription/sampler, and table. Sources run concurrently with exactly matching start/end and bucket boundaries; their kernel attachment times are not atomic, and this does not link individual syscalls to disk requests. Repeating a source with different selectors is allowed, but uses separate subscriptions. All selectors must pass validation and authorization before any collection starts. A source failure cancels the others and fails the whole query rather than returning partial tables.

For periodic event buckets, replace the `after` block with:

```text
every 5s {
  emit @flushes order by total_ns desc limit 15; clear @flushes;
  emit @io order by sectors desc limit 15; clear @io
}
after 30s { stop }
```

Every table must be emitted once per report, and periodic reports must clear each emitted table. Tables share the same window and reporting interval; sorting and limits remain table-specific. One-shot scripts can mix events and sampled snapshot sources (for example, add `memory { @mem[] = avg(used) }` and `emit @mem`). Periodic scripts still require event sources only. Existing collection budgets apply independently to each selector; total script output is capped at 7 MiB, and the 4096-byte query limit remains.

Multi-selector results are in `Snapshot.Tables` / JSON `tables`, in selector order. Each entry has its source and either `aggregation` or `windows`, with the table name and named metric objects. Use `.tables[].aggregation` for one-shot results or `.tables[].windows[]` for periodic results; a trailing jq filter such as `.tables[] | {source, result: .aggregation}` works normally. Single-selector and original-DSL results retain their existing shapes. API callers use `MonitorRequest{Source: "script", Mode: "aggregate", Aggregation: sharedTiming, Probes: selections}`: root aggregation contains only `Window`/`ReportEvery`, and each selection is a non-nested named aggregate with matching timing. The entire script is signed; syscall names resolve independently against the server architecture. Update both client and server for multi-selector support.

#### Joining completed aggregate tables

Join two tables by explicitly named output grouping columns:

```sh
portal query --name node-a --query '
syscalls:completion where syscall in (:fsync, :fdatasync) {
  @flush[proc: process_name] = {flushes: count(), flush_ns: sum(duration_ns)}
}
tracepoint:jbd2:jbd2_handle_start {
  @journal[proc: process_name] = {handles: count(), blocks: sum(field.requested_blocks)}
}
after 30s {
  emit @flush left join @journal on proc order by flush_ns desc limit 20
}'
```

`inner join` retains matched keys only; `left join` also retains unmatched left rows; `full join` retains unmatched rows from both sides. `on proc, directory` joins on a composite key (1–4 keys). Each key must be a grouping column on both tables; inline aliases let different source fields share a column name. Numeric keys compare exactly, including full-width integers; strings and numbers remain distinct. Missing/null keys never match each other.

Joins are **one-to-one**: duplicate non-null keys on either side fail the query, even if an inner join or a limit would hide them. Include more join keys or aggregate to fewer grouping columns rather than multiplying rows and inflating totals. Null-key rows remain unmatched. Non-key group columns are preserved as qualified keys such as `flush.device` and `journal.device`.

Sorting and limits run **after** joining all captured aggregate rows. Use an unambiguous metric name (`flush_ns`) or a qualified name (`flush.flush_ns`); ambiguous names such as `ops` on both sides are rejected. Ascending and descending ordering keep null metrics last. Missing matches produce explicit null metrics, not zero. Metrics are namespaced by input table:

```json
{"group":{"proc":"postgres"},"values":{"flush":{"flushes":12,"flush_ns":60000000},"journal":{"handles":18,"blocks":144}}}
```

Join scripts return `tables` in **emit order**. Joined entries have `source: "join"`, an `aggregation.join` descriptor (left/right/kind/on and output controls), qualified column names, and rows with nested metric objects. For jq, use `.tables[].aggregation.rows[] | {proc: .group.proc, calls: .values.flush.flushes, handles: .values.journal.handles}`. Separate source diagnostics are retained in `aggregation.collections.TABLE`; they are never summed or represented as per-row loss. The `table` field retains the left table name. You can also emit an original table or reuse it in another pairwise join; joins do not mutate source rows. Chained joins and event-level correlation are not supported.

For periodic reports, join **corresponding buckets only**, then clear both input tables:

```text
every 5s {
  emit @flush full join @journal on proc order by flush.flush_ns desc limit 20;
  clear @flush; clear @journal
}
after 30s { stop }
```

Every input table must participate in an emit or join; periodic scripts must clear each input exactly once per reporting block. Buckets still arrive together at completion, not streamed live. Up to eight output reports are supported. Existing per-selector collection limits and the 7 MiB script output cap remain; a full join may retain up to the sum of both input row counts. This compares aggregate activity in the same observation window, **not causal links** between syscalls, journal handles or disk requests. Process names are coarse identifiers; PIDs can be reused and task versus charged I/O cgroups have different attribution semantics.

API callers set `MonitorRequest.Reports` to `[]AggregateReport{{Left: "flush", Right: "journal", Kind: "left", On: []string{"proc"}, Sort: "flush_ns", Limit: 20}}`. A report with only `Left` emits an original table. Input probes must have compact output and no pre-join row filtering/sorting/limits; source predicates remain supported. Joined JSON decodes to the existing column-aligned Go `AggregateRow.Values`. Reports are included in the signed request and validated on the server. Upgrade both client and server for join support; scripts without joins retain their existing syntax and output.

#### Rollups and computed columns

Use `rollup by` to keep a subset of a table's **output group names**, either when emitting it or on either side of a join. This avoids collecting the source twice just to get coarser groups. For example:

```sh
portal query --name node-a --query '
disk:completion where device_name = "nvme0n1" {
  @io[owner: io.cgroup.path, operation: operation] = {ops: count(), sectors: sum(sectors), p99: percentile(duration_ns, 99)}
}
cgroups {
  @kernel[owner: path] = {write_ops: rate(io.write_ios)}
}
after 30s {
  emit @io;
  emit @io rollup by owner full join @kernel on owner
    select ops_per_s = io.ops / window.seconds,
           kib_per_s = io.sectors * 512 / 1024 / window.seconds,
           ratio = ops_per_s / kernel.write_ops
    order by kib_per_s desc limit 20
}'
```

For a write-only comparison, add `and operation = write` to the disk selector; otherwise `ops` includes all selected operations while `write_ops` counts only writes. The example's first emit intentionally retains the detailed operation breakdown. Neither join nor arithmetic implies that disk requests and cgroup accounting count identical operations.

`emit @io rollup by owner` combines operations for each owner. `emit @a rollup by owner full join @b rollup by owner on owner` rolls up both inputs before matching. Rollup takes 1–4 unique existing group columns, in the requested order; it does not invent groups or turn null keys into joinable identities. Remaining duplicate join keys still fail. You can reuse an original table and multiple rollups without mutating them. Rollups operate on the **same observations**, not displayed summary numbers: averages retain weighting, percentiles retain samples, distinct counts retain set semantics, histograms combine observations, and rates preserve the union of valid observation intervals. Coarse reductions share the original subscription/sampler and retention budgets; requesting rollups consumes additional aggregate state, so percentile/distinct/histogram queries may reach the existing limits sooner. Periodic reports roll up each bucket independently; diagnostics remain source-wide or bucket-wide, not per rolled-up group.

`select NAME = EXPRESSION[, ...]` **appends** up to eight numeric columns before `order by` and `limit`. It supports decimal literals, `+`, `-`, `*`, `/`, unary minus and parentheses with conventional precedence. Refer to existing metrics, unambiguous `TABLE.METRIC` names in joins, or previously defined computed columns. `window.seconds` is the actual output bucket/window length, including shorter final buckets; it is not the observed-time denominator used internally by `rate`. Unknown/ambiguous metrics, histograms in arithmetic, and conflicting column names are rejected before collection. Missing/null operands or division by zero produce null, which sorts last; missing measurements are not silently replaced with zero.

Computed values use exact rational arithmetic over the completed metric values, with fractions rounded to at most 18 decimal places on output and full-width integers preserved. Expressions are limited to 64 nodes, depth 16, decimal literals of 128 bytes and 4096-bit numeric results. In a join, existing metrics remain nested under input table names while computed values are direct keys, such as `.tables[].aggregation.rows[].values.ratio`; `columns` includes descriptors with `function: "computed"`. API reports use `LeftRollup`, `RightRollup`, and `Select: []AggregateComputedColumn`; expressions are `AggregateExpression{Op, Value, Args}` trees with `number`, `field`, `neg`, `+`, `-`, `*`, `/` operators. These controls are signed and server-validated. Reports with rollups/select return `tables` in emit order, even with one selector. Both client and server must be updated. The old syntax is unchanged; buckets still arrive at completion rather than streaming.

**Choosing join keys:** use task `cgroup.path` for syscall/tracepoint activity from the same executing cgroup, or disk `io.cgroup.path` against the cgroups source's `path` for charged I/O comparisons. Task membership is best-effort procfs information at receipt; charged I/O ownership comes from the request and can differ during writeback. Kernel journal/metadata work may legitimately be charged to root, and a tracepoint task's cgroup is not a substitute for the request's charged owner. Avoid treating the 15-character task `name` as a unique identity; `process_name` is more readable, but executable basenames can also collide. Ensure paths use compatible namespaces, and avoid adding ancestor/descendant cgroup counters together. Unequal event/counter rates alone do not prove lost events or disabled accounting.

### Sampled snapshot aggregations

CPU, memory, network, kernel, sensors, GPU, containers, cgroups, and process snapshots use the same functions and grouping mechanism:

```sh
portal query --name node-a --query 'memory avg(used) over 30s every 1s'
portal query --name node-a --query 'cpu avg(utilization_percent) over 30s every 1s by name'
portal query --name node-a --query 'network where name = eth* avg(bytes_recv_per_second) over 30s every 1s by name'
portal query --name node-a --query 'kernel max(counters.processes_running) over 1m every 2s'
portal query --name node-a --query 'sensors percentile(temperature_celsius,95) over 1m every 2s by name'
portal query --name node-a --query 'gpu avg(memory_used_mib) over 30s every 1s by uuid'
portal query --name node-a --query 'process where name = worker* count_distinct(pid) over 30s every 1s by name'
```

Snapshot-only sources default to `every 1s`. **Process requires explicit `every` to sample current processes**; without it, aggregation still collects process start/exit events. `action` is not available in process snapshots. Event-only sources reject `every`. Intervals must be at least 100 ms and no longer than the window; windows are limited to one hour. Sampling begins immediately, then follows the interval grid within `[start,end)`. Slow reads skip ticks instead of overlapping or catching up in bursts. The result's `aggregation.every` reports the effective interval in nanoseconds. At most 4,096 records per snapshot are accepted, in addition to the normal aggregate limits.

`portal capabilities --name node-a` describes each source's `sampling.fields`, `numeric_fields`, `group_by_fields`, default interval, and minimum interval. Each output/sampling field includes `aggregatable`: true means it supports at least one field-taking aggregate, not that every aggregate is valid. Use `query_field` for its DSL name, `numeric_fields` for numeric gauges/derived values, and sampling `semantics: "counter"` for fields accepted by `rate`. Nested arrays and collection diagnostics are not scalar aggregate fields. Fields are record-relative paths such as `used`, `temperature_celsius`, or `counters.processes_running`. Gauges describe current values; CPU times, network traffic, and context switches are cumulative counters. Sum/avg/min/max/percentile/hist of raw counters are rejected: use `rate(COUNTER)` or derived `FIELD_per_second` rates, such as `bytes_recv_per_second` or `counters.context_switches_per_second`. CPU `utilization_percent` is 100 × (delta total − delta idle − delta iowait) / delta total per core, accounting for nice/IRQ/softIRQ time without double-counting guest time.

`rate(COUNTER)` divides the sum of valid deltas by the union of their observed time intervals within each group, without extrapolating to the window edges. Concurrent counters grouped together contribute a combined rate, not a mean of their rates. Disjoint valid intervals contribute their durations without counting intervening gaps. It skips initial baselines, resets, missing values, identity changes and cgroup I/O device-set changes or per-device resets; no valid interval yields null. Units are the counter's units per second. This differs from `avg(FIELD_per_second)`, which weights each available sample equally rather than by elapsed time. Avoid summing parent and child cgroups, whose counters include descendants.

Rates use actual elapsed collection time and consecutive observations of the same entity. The first observation establishes a baseline; counter resets, missing fields, and disappearing/reappearing entities restart it. Derived queries require a window longer than the interval. Missing optional metrics and unavailable derived values are skipped, **not treated as zero**. `avg` is an arithmetic mean of observed values, not a time-weighted mean; `sum` of a gauge sums observations, not elapsed-time usage. `count` counts observed records, not unique entities or average population. Source permissions and platform/hardware requirements are unchanged.

### Process resource usage

`process` snapshots include `pid`, `name`, `started`, and best-effort resource/display fields:

| Field | Meaning |
| --- | --- |
| `cpu_seconds` | Cumulative user + system CPU seconds, excluding child processes |
| `rss_bytes` | Resident memory in bytes |
| `vms_bytes` | Virtual memory in bytes; platform accounting differs |
| `user` | Owning account name |
| `state` | Platform-reported process states, joined with commas |
| `threads` | Current thread count |
| `command_line` | Command line; may contain secrets |

Unsupported, inaccessible, or unavailable values are omitted, not reported as zero. The existing process visibility and policy rules still apply. Lifecycle events remain lightweight start/exit notifications; they do not include these metrics.

With explicit `every`, process aggregates also expose `cpu_seconds_per_second` and **`cpu_percent`**. Process CPU follows `top`'s convention: 100% means one fully occupied core, so multithreaded processes can exceed 100%. It is 100 × delta `cpu_seconds` / actual elapsed seconds, not lifetime CPU divided by process age. It is available only after consecutive samples of the same PID and start time; PID reuse starts a new baseline. A one-shot snapshot returns the CPU counter, not a fabricated instantaneous percentage.

```sh
# Top ten processes by sampled CPU usage during a fresh five-second window.
portal query --name node-a --query 'process avg(cpu_percent) over 5s every 1s by pid,name | .aggregation.values | map(select(.value != null)) | sort_by(.value) | reverse | .[:10][] | {pid: .group.pid, name: .group.name, cpu_percent: .value}'

# Peak resident memory by process during the window, in bytes.
portal query --name node-a --query 'process max(rss_bytes) over 5s every 1s by pid,name'

# Current process details; no aggregation window.
portal query --name node-a --query 'process where name = worker*'
```

Sorting and limiting are client-side; the DSL does not implement `order by` or `limit`, and the CLI does not yet provide an interactive `top` screen. To keep separate results for different lifetimes of a reused PID, add `started` to `by pid,name,started`.

### Built-in jq processing

`portal query --query 'SERVER_QUERY | JQ_EXPRESSION'` evaluates the suffix locally using [gojq](https://github.com/itchyny/gojq), with no external `jq` executable required. Keep the pipe **inside the quoted `--query` argument**. The first unquoted pipe separates the server query from jq; subsequent pipes are jq operators. Pipes inside quoted server-filter values are preserved (quote values containing literal pipes).

```sh
portal query --name node-a --query 'memory | .memory.used'
portal query --name node-a --query 'process | .processes | sort_by(.rss_bytes) | reverse | .[:10]'
portal query --name node-a --query 'process max(rss_bytes) over 5s every 1s by pid,name | .aggregation.values | sort_by(.value) | reverse | .[:10]'
portal query --name node-a --query 'capabilities | .sources[] | {name, modes}'
```

The jq stage receives the full snapshot JSON, including `aggregation` when present. It runs only in the client: only the server selection is sent and signed, and collection/policy checks are unchanged. jq syntax and compilation errors are reported before connecting or collecting a window. Runtime errors fail the command; earlier emitted results may already have been written. Cancellation also stops jq evaluation.

Each jq result is emitted as a compact JSON line; multiple results produce multiple lines, `empty` produces none, and strings remain JSON-quoted (this is not jq's `-r` mode). Without a suffix, existing JSON output is unchanged. Integer inputs preserve full-width precision, including through integer arithmetic; decimal operations follow gojq's floating-point semantics. This CLI suffix is not part of the server DSL accepted by `ParseMonitorQuery`, `monitor`, or registered monitors.

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

Initialize the coordinator config (prints a secret registration URL), then start the coordinator in one terminal:

```sh
./portal coordinator init --url http://127.0.0.1:8080 --config ./coordinator.json
./portal coordinator --config ./coordinator.json --listen 127.0.0.1:8080
```

Initialize the server config, allowing `operator` (the CA-signed certificate key ID from `cert sign --id`) to run as the current server user:

```sh
./portal server init \
  --name node-a --coordinator 'http://127.0.0.1:8080/register/TOKEN' \
  --ca ca.pub --identity operator --user "$(id -un)"
```

Replace `TOKEN` with the generated token, or paste the full URL printed by `coordinator init`.

Start a server in another terminal; it loads the saved token, CA public key and policy before registering or accepting commands:

```sh
./portal server \
  --label role=worker --label region=us-west
```

Query the inventory and run a command from the client:

```sh
curl http://127.0.0.1:8080/servers/node-a
./portal client --name node-a --coordinator http://127.0.0.1:8080 \
  --key operator --ca ca.pub --cert operator-cert.pub --user "$(id -un)" -- /usr/bin/id
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

`ca serve` exposes the signing key's **public** counterpart at `GET /ca.pub`, in SSH authorized-key format, without authentication. For this example, use `--ca https://ca.example.com/ca.pub`. The endpoint never exposes the signing private key, passkey state, or enrollment token; `--ca-key` remains a local private-key file.

All public `--ca` options accept a local path or an HTTPS URL, including server initialization/startup, client commands/config, and certificate request/refresh/inspection. Fetching uses normal TLS verification, a ten-second timeout, a 64 KiB limit, and exactly one plain SSH public key. Plain HTTP, redirects to HTTP, private keys, certificates, and malformed responses are rejected. A URL trusts that HTTPS origin to supply the CA key; use an independently distributed local file for an out-of-band pin. Server initialization pins the fetched key in its config; clients configured with a URL fetch its current key when verifying certificates, so changing that endpoint changes their trusted CA.

After enrollment, remove `PORTAL_CA_ENROLL_TOKEN` from the CA environment and delete the token file; passkeys are persisted in the state file. This first version serves one configured identity per CA instance. An administrator must distribute the trusted CA public-key file or HTTPS endpoint to clients and servers, and add `operator` to each server's local policy with only the accounts it may use. Passkey enrollment does **not** grant access by itself.

On any machine, request a certificate without copying the old private key:

```sh
mkdir -p ~/.config/portal
portal cert request --ca-url https://ca.example.com --ca ca.pub \
  --key ~/.config/portal/operator --cert ~/.config/portal/operator-cert.pub
```

The command generates a local Ed25519 key if absent, shows its fingerprint, and prints an approval URL. Open that URL in a browser, compare the fingerprint, and approve with a passkey. On first enrollment, enter the one-time enrollment token. The client receives a **48-hour SSH user certificate** for the new public key, verifies it against its configured CA public key, and writes it to `--cert`. It also stores a refresh token in `<key>.refresh` with mode 0600. The CA never receives the client's private key.

Headless clients can renew without a browser using the **same private key** and their refresh token:

```sh
portal cert refresh --ca-url https://ca.example.com --ca ca.pub \
  --key ~/.config/portal/operator --cert ~/.config/portal/operator-cert.pub
```

The CA requires a signature from that key, rotates the refresh token on each successful use, and returns a new 48-hour certificate. The token is bound to that key and expires **30 days after the most recent passkey approval**, not 30 days after each refresh. Clients configured with `ca_url` and `ca` automatically refresh before connections when the certificate has at most five minutes left or has expired; a separate renewal schedule is unnecessary. Manual `cert refresh` remains available and uses the same credential lock. After 30 days, rerun `cert request` and approve in the browser to start another 30-day period. If the client loses the rotated token due to a crash or failed write, browser approval is required again. Renewal requests never follow redirects, so the token is not forwarded to another origin. Keep the token file and private key together and restrict them to the client account; neither should be logged or committed.

Approval requests expire after five minutes and are not durable across CA restarts. The CA keeps passkey credentials and hashed refresh tokens on disk, while challenges and pending certificates live in memory. This version does not include automatic scheduling, multiple users per CA instance, or revocation; a stolen private key and certificate can remain usable for up to 48 hours unless each server's policy is changed and reloaded or its trusted CA is rotated. Protect the enrollment token and avoid logging approval URLs. Do not mount the CA signing key into the public coordinator.

## Symbols and event stacks

Linux servers support symbol lookup against the running kernel, an ELF binary on the server, or a live process. All symbol lookups and stack-enabled monitors require a root server and root query authorization: certificate root policy, root account keys, or query-only delegation via `--query-authorized-keys`. Only the first two also permit root commands.

```sh
portal query --name node-a --query 'symbols where target = kernel and name = vfs_*'
portal query --name node-a --query 'symbols where target = binary and path = /usr/bin/app and name = handle*'
portal query --name node-a --query 'symbols where target = process and pid = 1234 and addresses in (0x7f1234567890, 0x401234)'
portal query --name node-a --query 'symbols where target = process and pid = 1234 and name = handle* and limit = 1000'
```

Kernel/process addresses are absolute runtime addresses; binary addresses are link-time virtual addresses. Results preserve addresses as exact hexadecimal strings, with function name, module, offset, and per-address unresolved diagnostics. Name matching accepts exact names or a single edge glob, mutually exclusive with addresses. Process name searches cover functions in the executable and shared libraries' executable file mappings and return ASLR-adjusted runtime addresses, module names, sizes, and available ELF file offsets. Batches are limited to 256 addresses; name results default to 256 across all objects, with `and limit = N` up to 4096. ELF symbol tables and stripped Go runtime function metadata are supported. There is no DWARF/source-line, C++/Rust demangling, JIT, or BTF inspection in this increment. Process lookup accounts for ASLR and mapped objects, checks backing inode/device identity, and rejects a PID or mapping snapshot that changes during inspection. Unavailable/deleted mappings return explicit unresolved results for address lookup; name searches fail on unreadable mapped objects rather than silently returning incomplete results. Stripped objects without function metadata can contribute no names.

Add `stacks = user`, `kernel`, or `both` to syscall or generic tracepoint queries:

```sh
portal monitor-register --name node-a --query 'syscalls where pid = 1234 and stacks = both'
portal query --name node-a --query 'syscalls where pid = 1234 and stacks = both count over 10s by user.stack, kernel.stack'
portal query --name node-a --query 'tracepoint where event = block:block_rq_issue and fields in (common_pid, dev) and stacks = kernel count over 30s by field.dev, kernel.stack'
```

Events gain `user_stack`/`kernel_stack`, each with frames containing raw addresses and best-effort names/modules/offsets. Capture or symbolization failures remain explicit without discarding the ordinary event. Aggregation groups by semicolon-separated full call paths (`module:function+offset`, with unresolved addresses and capture errors retained), not just the first function. Stack capture defaults to 32 frames; the Go API can request up to 64 or disable symbolization. Stack maps hold 16,384 entries; collisions/full maps report capture errors and collection counters rather than reusing IDs and silently misattributing buffered events. Larger maps reduce collisions but cannot eliminate them. Ring-buffer loss, missing frame pointers/unwind support, stripped non-Go objects, process exit/exec/PID reuse before resolution, namespaces, and kallsyms restrictions can limit results. Kernel symbols are cached for the monitor lifetime; restart a monitor after module changes. Stacks are resolved after capture, not an atomic historical mapping snapshot. A block-event kernel stack describes the issuing path, not the originating application's stack after asynchronous writeback.

### Stack capture diagnostics

Stack-enabled aggregate results include `aggregation.stack_coverage.user` and/or `.kernel`. Each enabled side reports matching received `events`, stacks `captured` (at least one raw frame), `missing`, `empty`, and `capture_failures`. `helper_errors` breaks failures down by signed `bpf_get_stackid` code, e.g. `{"-14": 12, "-17": 1}`; `lookup_failures` counts failures reading a captured stack from its map. Raw events also expose `capture_error_code` alongside the existing error text.

Capture and symbolization are separate: `frames`, `named_frames`, `unresolved_frames`, `fully_symbolized`, `partially_symbolized`, `unsymbolized`, and `symbolization_failures` distinguish captured addresses from resolved function names. File/offset-only frames are unresolved, not named functions. Disabling symbolization increments `symbolization_disabled`, not unresolved/failure counts. `depth_limit_reached` counts stacks that filled the configured capture depth; they **may** be truncated, but an exactly-full complete stack is indistinguishable.

Coverage is measured **before stack shaping and output limits**, once per event, not per metric. Periodic results have independent coverage in each `windows[]` bucket; joins retain separate input coverage under `stack_coverage_by_table.TABLE`. These counts describe only matching events received by the server. Existing `collection.stack_capture_failures`, collisions and ring-buffer loss remain subscription-wide kernel diagnostics, including events that may never arrive; they are not comparable per-bucket or per-group loss estimates.

### Stack shaping and folded output

Stack grouping can be shaped on the server before any aggregate is reduced. User and kernel shapes are independent; raw event frames/addresses are unchanged and capture-error markers are always retained. Shaping applies to aggregate queries, not event monitors:

| Filter | Meaning |
| --- | --- |
| `stack.depth = 64` | Capture up to 64 frames (0 defaults to 32); usable with event monitors too |
| `user.stack.offsets = false` | Merge symbolized frames differing only by instruction offset; unresolved addresses stay distinct |
| `user.stack.drop_bottom = 3` | Remove three root-side **captured** frames |
| `user.stack.drop_top = 5` | Remove five leaf-side **captured** frames, e.g. runtime wrappers |
| `user.stack.from = logstorage.*` | Skip leaf-side frames before the first matching function; keep the match and its callers |
| `user.stack.until = logstorage.*` | Keep leaf-side frames through the first matching function, inclusive; no match leaves the stack unchanged |
| `user.stack.top = 8` | Keep at most eight leaf-side frames; zero keeps all remaining frames |

Use the same options with `kernel.stack`. Processing order is `drop_bottom`, `drop_top`, `from`, `until`, `top`, then optional offset removal. `from` and `until` match the full symbol function name (not module or address), case-sensitively, with an exact name or a single prefix/suffix glob. No match leaves the remaining frames unchanged. Use the full package prefix for fully qualified Go symbols. Top/drop counts range from 0 to 64. Trimming only affects captured frames, so increasing depth may be necessary to reach a common caller. API callers set `StackCapture.UserShape`/`KernelShape` to `StackShape{DropOffsets: true, DropTop: 5, From: "logstorage.*", Top: 8}`; `from`/`until` require symbolization. Controls are signed and checked server-side.

When user addresses cannot resolve to symbols but belong to file-backed mappings (such as a stripped QEMU executable), frames retain the mapped file path and `file_offset`, calculated from the mapping's offset and PC. Stack keys render `path@file+0xOFFSET`; this offset remains even with `offsets = false` because it is the only identity of the unresolved frame. Anonymous mappings still retain raw addresses and explicit errors. This does not fabricate function names or claim symbols were resolved.

Stack name matching treats **only a leading or trailing `*` as a wildcard**; interior stars are literal, including Go pointer receivers. Quote names containing parentheses: `user.stack.from = "os.(*File).Sync"` matches that method exactly. This rule applies equally to `until` and API patterns; quotes do not disable edge wildcards. `from in (...)` accepts 1–16 alternative patterns. It retains the first leaf-first frame matching **any** pattern and its callers, regardless of list order; if none match, the stack remains untrimmed. API callers use `StackShape.FromPatterns` instead of `From`.

```sh
portal query --name node-a --query 'syscalls where phase = completion and syscall in (:fsync,:fdatasync) and stacks = user and user.stack.offsets = false and user.stack.from in ("os.(*File).Sync", "*Fdatasync") count, sum(duration_ns) over 30s by process_name, user.stack'
```

```sh
portal query --name node-a --query 'syscalls where phase = completion and syscall in (:fsync,:fdatasync) and stacks = user and user.stack.offsets = false and user.stack.until = logstorage.* count, sum(duration_ns) over 30s by pid, user.stack'
```

JSON remains the default. Export a selected aggregate as flame-graph folded stacks with `--format folded`; `--folded-stack` defaults to `user.stack` (or select `kernel.stack`), and `--folded-metric` defaults to zero (the first function):

```sh
# Metric 1 is sum(duration_ns), so each path is weighted by elapsed nanoseconds.
portal query --name node-a --format folded --folded-metric 1 --query 'syscalls where phase = completion and syscall in (:fsync,:fdatasync) and stacks = user and user.stack.offsets = false and user.stack.top = 8 count, sum(duration_ns) over 30s by pid, user.stack' > fsync.folded
```

Folded output is `root;caller;leaf WEIGHT`, one line per path. Other group fields become prefix frames, e.g. `pid=123;root;caller;leaf 7000000`, so different processes/devices do not accidentally merge. Duplicate rendered paths sum their weights exactly; decimal weights use 18 places. Stack keys escape `;`, `%`, newline, carriage return and tab to prevent ambiguous frames or forged rows. Empty stacks appear as `[empty stack]`; empty grouped results produce no lines. Nonzero collection-loss counters are printed to stderr, not mixed into the folded file. Negative/null/non-numeric weights are rejected before output; folded format cannot be combined with `| jq`. This exports captured syscall/event cost or frequency—not a time-sampling CPU profile or exact device latency.

These queries work through the existing MCP `query` and persistent-monitor tools (shaping uses aggregate `query` only). `capabilities` advertises the symbols source, stack filters, and requirements. Upgrade client and server together for shaping controls.

## MCP tool

Run `portal mcp-server` as a stdio MCP server to expose `client`, `capabilities`, `query`, `monitor-register`, `monitor-read`, and `monitor-delete` as MCP tools. Server, coordinator, and credential-management commands are not exposed. For an MCP host that launches stdio servers:

```json
{"mcpServers":{"portal":{"command":"/absolute/path/to/portal","args":["mcp-server"]}}}
```

Start with `capabilities` using `{"name":"node-a"}` to discover the server's sources, fields, query syntax, aggregates, and caller authorization. Then call `query`, for example `{"name":"node-a","query":"memory avg(used) over 5s every 1s"}`. Queries also support the native `| JQ_EXPRESSION` suffix. All tools load the usual client config and accept connection overrides or an explicit `config` path.

For events, use `monitor-register` with `name` and `query`, then pass the returned `id` to `monitor-read`. MCP reads default to `duration: "5s"`; override with a positive duration up to `"1m"`. They return buffered records as JSON lines, and report a timeout if no records arrive. Resume subsequent reads with the last record's `after` sequence (a decimal string) or `after-timestamp` TAI64N timestamp, not both. The monitor remains active between calls until deleted with `monitor-delete` or its idle TTL expires. The unbounded live `monitor` command is CLI-only. CLI `monitor-read` still follows indefinitely by default, with optional `--duration` to bound it.

The MCP `client` tool takes `name`, `coordinator`, `key`, `cert`, optional `user`, and an `arguments` array for the remote command. For example, `{"name":"node-a","coordinator":"https://coordinator.example.com","key":"/path/operator","cert":"/path/operator-cert.pub","user":"deploy","arguments":["--","/usr/bin/id","-u"]}` runs `id -u` on `node-a`. Begin the array with `"--"` to protect remote flags from mflags' CLI parsing; it is a separator, not sent to the server. The MCP host must be able to read the client key and certificate files. Remote commands still require the server's certificate authentication and authorization policy. This CLI serves an MCP tool to MCP clients; it does not itself connect to external MCP servers.

The command protocol remains `adminhelper/2` for wire compatibility; upgrade clients and servers together if changing the protocol separately. Existing SSH user certificates with a nonempty key ID may continue to work if that identity is listed in the policy; certificates without a key ID cannot be authorized.

By default the server selects a number0 production relay. To use a relay you operate, pass `-relay https://relay.example.com/` to the server; the client learns that relay through inventory. The relay must accept both endpoints. For a directly reachable interface, the server can use `-listen SERVER_IP:PORT` to offer that address to iroh's in-band path discovery (not to coordinator inventory). The default bind uses an OS-assigned dual-stack port; direct upgrades depend on iroh discovering routable candidates and network/firewall reachability. A short command may finish before the upgrade and remain relayed. The coordinator is still reached via HTTP(S) for check-in and lookup; only the command channel uses iroh. Registrations expire after 90 seconds without a refresh and disappear on coordinator restart; servers re-register at their next check-in. The lookup endpoint is read-only and public to anyone who can access the coordinator; registration requires the shared token.

With a wildcard UDP bind, both endpoints advertise addresses from active local
interfaces, including private IPv4 and IPv6 ULA addresses, so peers on the same
LAN or VPN can connect directly. Loopback, link-local, down interfaces and
addresses incompatible with the bind's family are excluded. A concrete `-listen`
address does not advertise other interfaces. Candidates use the actual bound
UDP port and are exchanged with the peer by iroh, never stored in coordinator
inventory. Server candidates refresh on check-in; cached client candidates
refresh on each request. Public address discovery uses iroh's QAD service on
UDP port 7842 (not STUN); a custom HTTP relay alone does not supply QAD. Allow
outbound relay HTTPS, QAD UDP and peer UDP traffic for direct upgrades.

Use `--network-debug` on the server or a client command to log the selected
relay/direct path, validation status, RTT when known, and the current network
report. Diagnostics go to stderr, leaving JSON/MCP stdout untouched. Being
online with a relay does not prove direct UDP connectivity.

The MCP server reuses endpoints and connections across calls (up to 16 cached
peers), giving path discovery time to establish a direct route. Every request
still reloads credentials and inventory and authenticates a fresh stream;
canceling one request does not close sibling streams. Closed connections are
replaced on the next call; failed operations are not automatically replayed.
Upgrade both client and server for multi-request connection reuse. Go library
users can share a `NewClientTransport(ctx)` through `Client.Transport` and must
close it when done. Ordinary CLI invocations release their transport on exit.

**Security:** Serve the coordinator over HTTPS (or behind a trusted TLS reverse proxy) outside a local test; otherwise inventory and the registration token can be intercepted or changed. Protect the token, policy file, and CA signing key. The client trusts inventory returned by that coordinator for the server endpoint identity, while iroh verifies the connected endpoint matches that identity. The server verifies the CA signature, expiry, explicit principal, and proof of possession of the certificate's private key before applying its policy. Limit the server process's OS privileges appropriately: an authorized certificate can run arbitrary executables as an allowed user. This is a bounded-output (1 MiB), 60-second command facility, not an interactive shell or job supervisor.

Run tests with `go test ./... -count=1`.

# rPerf3

A small iPerf3-compatible network throughput tool in Rust.

## Why this exists

I started this project because I ran into an implementation problem in
the Windows build of iPerf3 and wanted a drop-in replacement I could
understand, debug, and extend. Learning Rust along the way was the
bonus.

The goal is protocol-level compatibility with iPerf3 (same wire format,
same control messages, same cookie-multiplexed streams) — not feature
parity. If `rPerf3` client can talk to an iPerf3 server, and an iPerf3
client can talk to `rPerf3` server, the MVP is working.

## What works today

- Client mode (`-c <host>`): control-channel handshake, configurable
  duration / parallel streams / write size, TCP data streams, results
  exchange.
- Server mode (`-s`): accepts one test at a time on a configured port,
  handles the full iPerf3 state machine end to end (ParamExchange →
  CreateStreams → TestStart/Running → TestEnd → ExchangeResults →
  DisplayResults → IperfDone), prints a summary line with observed
  bytes and Mbits/sec.
- CLI: `-s` and `-c` are mutually exclusive, one is required.
- Self-test: `cargo test --test self_test` spins up an in-process
  server and runs a client against it over loopback.
- **UDP data path (`-u`).** Full iPerf3-compatible UDP: 16-byte
  datagram header, RFC 1889 jitter EWMA, lost-packet and out-of-order
  accounting, sender-side bandwidth pacing (`-b`, default 1 Mbps for
  UDP), and an end-of-test sentinel packet. Works bidirectionally
  against real iPerf3.
- **Reverse + bidirectional tests (`-R`, `--bidir`).** In reverse, the
  server is the sender and the client is the receiver. In bidirectional,
  both sides send and receive on the same data streams concurrently.
  Works on TCP and UDP; interoperates with real iPerf3 in the
  rperf3-client → iperf3-server direction.
- **Server loops by default + concurrent tests** (`-1`, `--max-concurrent N`).
  The server now serves tests until killed (iperf3 default), `-1` restores
  the old one-shot behavior, and `--max-concurrent N > 1` enables up to N
  simultaneous tests multiplexed by cookie (TCP only — UDP concurrent
  sessions are rejected with AccessDenied).
- **JSON output (`-J`).**  After the test the client emits a
  pretty-printed JSON object shaped like iperf3's `-J` output:
  `start.connecting_to`, `start.test_start`, `end.sum_sent`, and
  `end.sum_received` are all populated.  Pipe to `jq` or parse
  in scripts.  Text output is suppressed when `-J` is active.
- **Logfile (`--logfile <PATH>`).**  Redirects all stdout output (text or
  JSON) to the specified file (append mode).  Works on any Unix platform.
- **Format flag (`-f <unit>`).**  Accepted for iperf3 CLI compatibility
  (`k`, `K`, `m`, `M`, `g`, `G`).  _Parsed but not yet applied to
  output — text output still auto-scales.  See roadmap._
- **Verbose / timestamps stubs (`-V`, `--timestamps`).**  Accepted for
  iperf3 CLI compatibility; no-op for now.  See roadmap.
- **Title prefix (`-T / --title <LABEL>`).** Fully implemented. Every
  interval row and summary row is prefixed with `LABEL:  ` so you can
  distinguish runs when piping output from multiple simultaneous tests.
- **Socket-option knobs (`-w`, `-M`, `-C`, `-S`).** Fully wired: window
  size sets `SO_SNDBUF`/`SO_RCVBUF`; TOS sets `IP_TOS` (all platforms);
  MSS sets `TCP_MAXSEG` and congestion sets `TCP_CONGESTION` (Linux-only
  with a runtime warning on other platforms). Applied on both the client
  data streams and the server side after negotiation.
- **Byte / block termination (`-n`, `-k`).** Send loops (TCP and UDP,
  client and reverse-server) now break when the requested byte count or
  block count is reached, whichever comes first.
- **CPU affinity (`-A`).** Pins the main thread to the given CPU index
  (e.g. `0`) via `sched_setaffinity` on Linux; emits a warning and
  continues on other platforms. Single-integer form only — range/list
  syntax is a follow-up.
- **Phase-5 wire propagation.** All negotiated knobs (`-w`, `-M`, `-C`,
  `-S`, `-n`, `-k`) are now included in the `ClientOptions` JSON sent
  during ParamExchange, so the server honors them even when both sides
  are rPerf3. `-Z` (zero-copy) remains a documented stub.

### Accuracy features

Built in because this is meant to be a trustworthy view of bandwidth,
not just "a number":

- **Measured elapsed on both sides.** Every stream records the
  timestamps of its first and last bytes. Throughput is computed
  from (last − first), not from the client-advertised integer
  seconds. Sub-second precision end to end.
- **`-O/--omit N`.** Skip the first N seconds of each stream so TCP
  slow-start doesn't pull the reported steady-state number down.
  Bytes from the omit window are tracked separately and excluded from
  the Mbits/sec line.
- **Per-second interval rows** on both client and server, so you can
  see whether a flat 1 Gbps is actually flat or oscillating:
  ```
  [CLI 1] 0.00-1.00 sec  128 MBytes  1.07 Gbits/sec
  [SRV 1] 0.00-1.00 sec  128 MBytes  1.07 Gbits/sec
  ```
- **TCP retransmits** (Linux, via `getsockopt(TCP_INFO)`). A clean
  throughput number on a lossy link isn't clean — retransmits would
  have been silent. Now they aren't.
- **CPU utilization** (Linux, via `/proc/self/stat`): helps tell
  "the network is slow" from "I'm CPU-bound."
- **Control-channel read timeouts.** A vanished peer no longer hangs
  the server forever; default handshake timeout is 30 seconds and
  the live-test window gets `handshake_timeout + test_duration`.

## Usage

```
Usage: rperf3 [OPTIONS] <--server|--client <HOST>>

Options:
  -s, --server               Run as a server (listen for incoming connections)
  -c, --client <HOST>        Run as a client and connect to this server host
  -p, --port <PORT>          Server port [default: 5201]
  -t, --time <TIME>          Test duration in seconds [default: 10]
  -P, --parallel <PARALLEL>  Number of parallel streams [default: 1]
  -l, --len <LEN>            Bytes per write (TCP buffer length) [default: 131072]
  -u, --udp                  Use UDP instead of TCP for data streams
  -b, --bandwidth <RATE>     Target bandwidth for UDP sender (e.g. 100M, 1G, 0 = unlimited)
  -R, --reverse              Reverse direction — server sends, client receives
      --bidir                Bidirectional — both sides send and receive
  -O, --omit <OMIT>          Seconds to omit at the start of the test [default: 0]
  -1, --one-off              Exit the server after one test (iperf3 -1 equivalent)
      --max-concurrent <N>   Max concurrent sessions [default: 1]
  -J, --json                 Emit iperf3-compatible end-of-test JSON (suppresses text output)
  -f, --format <UNIT>        Force format unit for text output: k K m M g G
                             (parsed for iperf3 compat; auto-scale still used — see roadmap)
      --logfile <PATH>       Redirect all output to this file (append; unix only)
  -V, --verbose              Verbose output (no-op stub — accepted for iperf3 compat)
      --timestamps           Prefix lines with timestamps (no-op stub — accepted for iperf3 compat)

Knob flags:
  -T, --title <LABEL>        Prefix every output line with LABEL (fully implemented)
  -w, --window <SIZE>        Socket send/receive buffer size, e.g. 256K (applied via setsockopt)
  -M, --set-mss <BYTES>      TCP maximum segment size (Linux-only; warning on other platforms)
  -C, --congestion <ALG>     TCP congestion algorithm, e.g. bbr (Linux-only; warning elsewhere)
  -S, --tos <VALUE>          IP type-of-service byte: decimal, 0x-hex, or 0-octal (applied)
  -Z, --zerocopy             Zero-copy mode (stub — sendfile not yet implemented)
  -n, --bytes <SIZE>         Stop after sending/receiving this many bytes (applied)
  -k, --blockcount <COUNT>   Stop after this many writes/blocks (applied)
  -A, --affinity <SPEC>      Pin main thread to CPU index (Linux-only; single integer form)

  -h, --help                 Print help
```

### Test against itself

```
# Terminal A
cargo run --release -- -s -p 5202

# Terminal B
cargo run --release -- -c 127.0.0.1 -p 5202 -t 3 -P 2
```

# Run the server indefinitely, handle up to 4 simultaneous tests
cargo run --release -- -s -p 5202 --max-concurrent 4

Or run the in-process self-test:

```
cargo test --test self_test -- --nocapture
```

```
# Reverse TCP: server sends, client receives
cargo run --release -- -c 127.0.0.1 -p 5202 -R -t 3
```

UDP at 100 Mbps for 3 seconds:

```
# Terminal A
cargo run --release -- -s -p 5202 -u

# Terminal B
cargo run --release -- -c 127.0.0.1 -p 5202 -u -b 100M -t 3
```

### Test against real iPerf3

rPerf3 client ↔ iperf3 server:

```
iperf3 -s -p 5202
cargo run --release -- -c 127.0.0.1 -p 5202 -t 3
```

rPerf3 client ↔ iperf3 server (UDP):

```
iperf3 -s -p 5202
cargo run --release -- -c 127.0.0.1 -p 5202 -u -b 50M -t 3
```

iperf3 client ↔ rPerf3 server (UDP):

```
cargo run --release -- -s -p 5202
iperf3 -c 127.0.0.1 -p 5202 -u -b 50M -t 3
```

rperf3 client in reverse ↔ iperf3 server:

```
iperf3 -s -p 5202
cargo run --release -- -c 127.0.0.1 -p 5202 -R -t 3
```

## Building

```
cargo build --release
cargo test            # unit + integration tests
cargo clippy --all-targets -- -D warnings
```

## Project layout

```
src/
  main.rs              CLI entry point
  lib.rs               crate::run_client / run_server / run_server_on
  cli.rs               clap-derive argument parsing and Mode enum
  client.rs            client state machine
  server.rs            server state machine
  common/
    mod.rs             Message enum + connect()
    affinity.rs        CPU affinity via sched_setaffinity (-A, Linux-only)
    cookie.rs          session cookie generation and wire reading
    cpu.rs             /proc/self/stat CPU sampling (Linux)
    interval.rs        per-second rolling interval reporter
    json_output.rs     iperf3-compatible JSON output structs + render()
    protocol.rs        Socket trait + TuningOpts, TCP/UDP wrappers, test MockSocket
    stream.rs          data-stream worker thread
    test.rs            Test + Config + per-stream receipts
    timer.rs           std::time::Instant wrapper
    wire.rs            framed JSON helpers + ClientOptions/Results
tests/
  self_test.rs         end-to-end loopback tests (data flow, omit, timeout)
```

### JSON output example

```bash
./target/release/rperf3 -s -p 5212 &
./target/release/rperf3 -c 127.0.0.1 -p 5212 -t 1 -J | jq .end.sum_sent
```

```json
{
  "bytes": 16777216,
  "seconds": 0.98,
  "bits_per_second": 137005034.5
}
```

## Roadmap / known stubs

| Flag | Status | Notes |
|------|--------|-------|
| `--rsa-public-key`, `--username`, `--password`, `--rsa-private-key`, `--authorized-users` | **Ships in phase 6** ✅ | RSA-OAEP-SHA256 authentication. See Authentication section above. |
| `-J` / `--json` | **Ships in phase 4** | Client-side end-of-test JSON. Server still prints text. |
| `--logfile` | **Ships in phase 4** | Works on Unix via `dup2`. Non-unix stub. |
| `-f` / `--format` | Parsed, no-op | Flag accepted; output still auto-scales. Follow-up work to wire unit through `format_interval_row`. |
| `-V` / `--verbose` | Parsed, no-op | Accepted for iperf3 CLI compat. |
| `--timestamps` | Parsed, no-op | Requires `chrono` dep; deferred. |
| `--json-stream` | Not started | Per-interval JSON streaming. |
| Server JSON | Not started | `-J` affects client only; server always prints text. |
| **Phase 5 — knob parity** | **Partially shipped** | See below. |

### Phase 5 / follow-up 1 detail

| Flag | Status |
|------|--------|
| `-T` / `--title` | **Fully implemented.** `OnceLock<String>` in `stream.rs`; every interval and summary row is prefixed. |
| `-w` / `--window` | **Applied.** Sets `SO_SNDBUF`/`SO_RCVBUF` on data sockets via `setsockopt` on both client and server. |
| `-n` / `--bytes` | **Applied.** TCP and UDP send loops break when `bytes_sent >= total_bytes`. Propagated in `ClientOptions`. |
| `-k` / `--blockcount` | **Applied.** Send loops break when `bytes_sent / block_size >= total_blocks`. Propagated in `ClientOptions`. |
| `-M` / `--set-mss` | **Applied (Linux).** Sets `TCP_MAXSEG` via `setsockopt`; logs a warning and skips on non-Linux. |
| `-C` / `--congestion` | **Applied (Linux).** Sets `TCP_CONGESTION` via `setsockopt`; logs a warning and skips on non-Linux. |
| `-S` / `--tos` | **Applied.** Sets `IP_TOS` via `setsockopt` on data sockets (all platforms). |
| `-A` / `--affinity` | **Applied (Linux).** Pins main thread to the given CPU index via `sched_setaffinity`; logs a warning on non-Linux. Single-integer only — range/list syntax is a future follow-up. |
| `-Z` / `--zerocopy` | **Stub.** Parsed and stored; `sendfile`-based implementation is a future follow-up. |

## Authentication (Phase 6)

rPerf3 implements iPerf3-compatible RSA-OAEP-SHA256 authentication. The
client encrypts a `"{unix_ts}\n{username}\n{sha256hex(password)}"` payload
with the server's RSA public key, base64-encodes it as `authtoken`, and
includes it in the ParamExchange JSON. The server decrypts with its private
key, validates the timestamp skew (≤ 10 s), and looks up the user in an
authorized-users CSV file.

### Server flags

| Flag | Description |
|------|-------------|
| `--rsa-private-key <PEM>` | Path to the server's RSA private key (PKCS#8 or PKCS#1 PEM). When set, every client **must** supply a valid authtoken. |
| `--authorized-users <CSV>` | Path to the authorized users file. Format: one `username,sha256hex_of_password` per line. Lines starting with `#` and blank lines are ignored. |

Both flags must be set together; if only one is set auth is not enforced.

### Client flags

| Flag | Description |
|------|-------------|
| `--rsa-public-key <PEM>` | Path to the server's RSA public key (PKCS#8 SubjectPublicKeyInfo or PKCS#1 PEM). |
| `--username <U>` | Username to authenticate as. |
| `--password <P>` | Plaintext password. If omitted and `--rsa-public-key` is set, the password is prompted interactively (no echo). |

### Quick start

```bash
# 1. Generate a 2048-bit RSA keypair
openssl genpkey -algorithm RSA -out /tmp/server-priv.pem -pkeyopt rsa_keygen_bits:2048
openssl rsa -in /tmp/server-priv.pem -pubout -out /tmp/server-pub.pem

# 2. Create an authorized_users file with sha256 of "secret"
echo "alice,$(printf secret | shasum -a 256 | awk '{print $1}')" > /tmp/authorized_users

# 3. Start the server with auth
./target/release/rperf3 -s -p 5201 \
    --rsa-private-key /tmp/server-priv.pem \
    --authorized-users /tmp/authorized_users

# 4. Good password — succeeds
./target/release/rperf3 -c 127.0.0.1 -p 5201 -t 1 \
    --rsa-public-key /tmp/server-pub.pem \
    --username alice \
    --password secret

# 5. Wrong password — server rejects with "access denied"
./target/release/rperf3 -c 127.0.0.1 -p 5201 -t 1 \
    --rsa-public-key /tmp/server-pub.pem \
    --username alice \
    --password wrong
```

## Out of scope

- Async/tokio runtime
- TLS

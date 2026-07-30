# webdiag

A fast, lightweight CLI tool for diagnosing websites. Given a URL, `webdiag` walks the full request lifecycle — DNS resolution, TCP connection, TLS handshake, certificate validation, HTTP response, and HTTP/3 support — and reports timing metrics for each phase.

<!-- Replace the placeholder below with a screenshot or demo GIF of your terminal output -->
<!-- ![webdiag demo](docs/demo.gif) -->

---

## Features

- **DNS** — resolves the hostname and traces the full CNAME chain to the final IP address
- **TCP** — measures connection time and reports the port used
- **TLS** — shows protocol version, cipher suite, ALPN, and SNI; warns on weak configurations
- **Certificate** — validates the certificate chain, reports issuer/subject/SANs, expiry date, and days remaining
- **HTTP** — reports status code, HTTP version, and redirect target
- **HTTP/3** — detects HTTP/3 support via the `Alt-Svc` response header
- **Redirect following** — automatically follows up to 10 redirects and aggregates results
- **Timing breakdown** — DNS lookup, TCP connect, TLS handshake, pre-transfer, TTFB, and total, each rated good / ok / warn / bad
- **Three output modes** — concise summary, per-hop verbose detail, and structured JSON
- **Color-aware output** — syntax-highlighted when writing to a terminal; plain text otherwise; auto-paged with `less`

---

## Requirements

- Go 1.22 or later

---

## Installation

### Homebrew (macOS / Linux)

```sh
brew install mqry/tap/webdiag
```

### Using `go install`

```sh
go install github.com/mqry/webdiag@latest
```

Make sure `$(go env GOPATH)/bin` is on your `PATH`.

### Build from source

```sh
git clone https://github.com/mqry/webdiag.git
cd webdiag
go build -o webdiag .
```

Move the binary somewhere on your `PATH`, for example:

```sh
mv webdiag /usr/local/bin/
```

---

## Usage

```
webdiag [flags] <url>
```

The `<url>` argument may include or omit the scheme. When the scheme is omitted, `https://` is assumed.

### Examples

```sh
# Default summary view
webdiag example.com

# Detailed per-redirect breakdown
webdiag --verbose https://example.com

# Structured JSON output
webdiag --json example.com

# Disable color (useful for CI or log files)
webdiag --no-color example.com

# Pipe JSON output to jq
webdiag --json example.com | jq '.overall.certificate'
```

---

## Flags

| Flag | Description |
|------|-------------|
| `--verbose` | Show detailed diagnostics for every hop in the redirect chain |
| `--json` | Output the full diagnostic result as indented JSON |
| `--no-color` | Disable ANSI color codes regardless of terminal detection |

---

## Output Modes

### Default (summary)

Displays a compact, color-coded overview of the final destination after all redirects, including overall timing scores.

```
URL            https://example.com
DNS            OK
 Lookup#1      example.com -> 104.20.23.154
TCP            OK (443 port)
TLS            OK
 Version       1.3
 Cipher        TLS_AES_128_GCM_SHA256
 Certificate   OK (89 days)
HTTP           OK (200)
 Version       HTTP/2.0
 Redirect      None
Timings
 DNS           23 ms (OK)
 TCP           10 ms (GOOD)
 TLS         1220 ms (BAD)
 TTFB          15 ms (GOOD)
 Total       1270 ms
```

### Verbose (`--verbose`)

Prints every redirect hop as a separate section, each with its own DNS, TCP, TLS, certificate, HTTP, and timing data. Useful for debugging redirect loops or per-hop latency spikes.

### JSON (`--json`)

Outputs the complete `DiagnosticResult` structure as pretty-printed, syntax-highlighted JSON. The top-level shape is:

```jsonc
{
  "overall": { /* aggregated result across all redirects */ },
  "redirects": [ /* per-hop details */ ]
}
```

---

## Timing Ratings

Each timing phase is rated against empirical thresholds:

| Phase | GOOD | OK | WARN | BAD |
|-------|------|----|------|-----|
| DNS Lookup | ≤ 20 ms | ≤ 50 ms | ≤ 100 ms | > 100 ms |
| TCP Connect | ≤ 10 ms | ≤ 50 ms | ≤ 100 ms | > 100 ms |
| TLS Handshake | ≤ 50 ms | ≤ 100 ms | ≤ 200 ms | > 200 ms |
| TTFB | ≤ 200 ms | ≤ 500 ms | ≤ 1000 ms | > 1000 ms |
| Total | ≤ 500 ms | ≤ 1000 ms | ≤ 2000 ms | > 2000 ms |

---

## License

MIT


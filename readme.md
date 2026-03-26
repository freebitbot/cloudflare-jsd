# Cloudflare JSD Solver

Go-based solver for Cloudflare's JavaScript Deobfuscation (JSD) challenge.

> ⚠️ **Note**: This is NOT a Cloudflare Turnstile solver. It's a completely different challenge.

## Installation

```bash
go build -o cloudflare-jsd .
```

## Usage

### Online Mode (solve challenge from URL)

```bash
# Basic usage - fetch and solve
./cloudflare-jsd -url https://target-site.com

# With custom host header
./cloudflare-jsd -url https://target-site.com -host custom.host.com
```

### Download Challenge Script

```bash
# Download the obfuscated main.js for analysis
./cloudflare-jsd -url https://target-site.com -download challenge.js

# Then process it offline
./cloudflare-jsd -file challenge.js -output deobfuscated.js
```

### Offline Mode (process local file)

```bash
# Deobfuscate a previously downloaded script
./cloudflare-jsd -file challenge.js -output deobfuscated.js
```

## CLI Flags

| Flag | Default | Description |
|------|---------|-------------|
| `-url` | - | Target URL with Cloudflare challenge |
| `-file` | - | Local JS file to process (offline mode) |
| `-output` | `out.js` | Output file for offline mode |
| `-host` | auto | Host header (auto-extracted from URL) |
| `-download` | - | Download challenge script to file |

## How It Works

```
1. Fetch target URL → extract r/t params from HTML
2. Fetch /cdn-cgi/challenge-platform/scripts/jsd/main.js
3. Deobfuscate the script (see pipeline below)
4. Extract Ve, Path, Alphabet from deobfuscated AST
5. Generate browser fingerprint
6. Compress with LZ-String and submit to Cloudflare
```

## Deobfuscation Pipeline

| Pass | Description |
|------|-------------|
| `UnrollMaps` | Inline object literal property lookups |
| `SequenceUnroller` | Convert sequence expressions to statements |
| `ReplaceReassignments` | Inline proxy variable reassignments |
| `ReplaceStrings` | Replace string function calls with literals |
| `ConcatStrings` | Concatenate adjacent string literals |
| `Simplify` | Final cleanup pass |

## Project Structure

```
├── main.go                 # CLI entry point
├── jsd/
│   ├── solver.go           # JsdSolver: fetch, deobfuscate, submit
│   ├── fp.go               # Browser fingerprint generation
│   ├── lz.go               # LZ-String compression
│   └── utils.go            # Extract r/t params from HTML
├── visitors/deobf/         # AST deobfuscation passes
│   ├── deobf.go            # Pipeline orchestration
│   ├── maps.go             # UnrollMaps
│   ├── sequence_unrolling.go
│   ├── concat_strings.go
│   ├── replace_strings.go
│   ├── replace_reassignments.go
│   └── proxy_functions.go
└── visitors/extract/       # Parameter extraction
    └── extract.go          # Parse Ve, Path, Alphabet from AST
```

## Dependencies

- [go-fast](https://github.com/t14raptor/go-fast) - JavaScript parser with AST visitor
- [tls-client](https://github.com/bogdanfinn/tls-client) - TLS fingerprint simulation
- [orderedmap](https://github.com/iancoleman/orderedmap) - Ordered JSON serialization

## Development

```bash
# Run
go run main.go -url https://example.com

# Build
go build -o cloudflare-jsd .

# Format
go fmt ./...

# Tidy
go mod tidy
```

---

## Disclaimer

This package is unofficial and not affiliated with Cloudflare. Use it responsibly and in accordance with Cloudflare's terms of service.

## License

MIT

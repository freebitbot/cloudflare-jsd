# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Cloudflare JSD challenge solver written in Go. The project reverse-engineers Cloudflare's JavaScript challenge, deobfuscates it, extracts key parameters, and submits a solution with a generated browser fingerprint.

**Status:** Currently being updated/migrated to Go (legacy JavaScript files remain).

## Commands

```bash
# Run the solver
go run main.go

# Build binary
go build

# Format code
go fmt ./...

# Tidy dependencies
go mod tidy
```

## Architecture

### Package Structure

```
├── main.go              # Entry point, HTTP client setup, solver orchestration
├── jsd/                 # Core solver logic
│   ├── solver.go        # JsdSolver: fetches script, submits solution
│   ├── fp.go            # Browser fingerprint generation (ordered map of browser props)
│   ├── lz.go            # LZ-String compression for payload
│   └── utils.go         # ExtractRT: regex extraction of r/t params from HTML
├── visitors/deobf/      # JavaScript AST deobfuscation (uses go-fast)
│   ├── deobf.go         # DeobfuscateAndExtract: orchestrates all passes
│   ├── maps.go          # UnrollMaps: inline object literal maps
│   ├── sequence_unrolling.go  # Unroll sequence expressions
│   ├── concat_strings.go      # Concatenate string literals
│   ├── replace_strings.go     # Replace string function calls
│   ├── replace_reassignments.go # Inline proxy variable reassignments
│   └── proxy_functions.go     # Inline proxy function calls
└── visitors/extract/    # Extract parameters from deobfuscated AST
    └── extract.go       # ParseScript: extracts Ve, Path, Alphabet from AST
```

### Data Flow

1. `main.go` fetches HTML from target URL
2. `jsd/utils.go` ExtractRT extracts `r` and `t` parameters from HTML
3. `jsd.NewSolver` creates solver with target host/URI
4. `solver.Run()` orchestrates:
   - Fetches Cloudflare's main.js challenge script
   - `deobf.DeobfuscateAndExtract` parses JS, runs deobfuscation passes
   - `extract.ParseScript` extracts Ve (b/g), Path (/jsd/oneshot/...), and alphabet string
5. `solver.Submit()` generates fingerprint, compresses with LZ-String, POSTs to endpoint

### Key Dependencies

- **go-fast** (`github.com/t14raptor/go-fast`) - JavaScript parser with AST visitor pattern
- **tls-client** (`github.com/bogdanfinn/tls-client`) - TLS fingerprint simulation for Chrome
- **orderedmap** (`github.com/iancoleman/orderedmap`) - JSON-serializable ordered map for fingerprint

### AST Deobfuscation Pipeline

The deobfuscation in `visitors/deobf/deobf.go` runs these passes in order:

1. `UnrollMaps` - Replace object literal property lookups with literal values
2. `SequenceUnroller` - Convert sequence expressions `(a, b, c)` into separate statements
3. `ReplaceReassignments` - Track and inline proxy variable reassignments
4. `ReplaceStrings` - Replace string decoding function calls with literal strings
5. `ConcatStrings` - Concatenate adjacent string literals
6. `simplifier.Simplify` - Final cleanup pass from go-fast

## Working with the Code

### Modifying Deobfuscation

All AST transformations use the visitor pattern from go-fast. Create a struct embedding `ast.NoopVisitor` and implement the relevant `Visit*` methods. See existing files in `visitors/deobf/` for patterns.

### Fingerprint Format

The fingerprint in `jsd/fp.go` is an ordered map where keys are expected values and values are arrays of browser property paths that should return that value. The map is serialized to JSON, compressed with LZ-String, and sent as the payload.

### HTTP Client

Uses `tls-client` with Chrome profile for TLS fingerprint simulation. Headers must include `http.HeaderOrderKey` to preserve header order (required by Cloudflare).

# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

```bash
# Build
go build ./...

# Run all tests
go test ./redactor/...

# Run a single test by name
go test ./redactor/ -run TestWindowsRules/WIN-NET-USE
go test ./redactor/ -run TestLinuxRules/<test-id>

# Run benchmarks
go benchmark ./redactor/ -bench=. -benchmem

# Health check (verify rules load correctly)
go run . -health

# Run the binary (reads from stdin, writes to stdout)
echo 'psexec -u admin -p SuperSecret! cmd.exe' | go run .
echo '{"cmd": "net use Z: \\server P@ssword domain"}' | go run . -json
```

## Architecture

SecretScaple is a log sanitization engine. Input flows through `ProcessStream` (orchestrator) → worker pool → per-line redaction.

**Redaction pipeline (per line/chunk):**
1. **Phase 0** (`engine.go:RedactBytes`) — Regex rules run when trigger chars (`@`, `=`, `:`, `/`, `-`) are present. These handle patterns like URL basic auth and DB connection strings.
2. **Phase 1** — Tokenize the line via `LogSplitter` (splits on whitespace/quotes), then slide a window of tokens through the trie. Matches emit `pendingRedaction` structs.
3. **Phase 2** — Sort by priority, resolve overlaps, reconstruct the output string with redactions applied.

**Processing modes:**
- **Raw mode** (`RedactBytes`) — processes the byte slice as a flat log string.
- **JSON mode** (`RedactAllJSONStrings` in `scanner.go`) — walks JSON string values only, preserving structure. JSON keys listed in `JSONSensitiveKeys` have their values fully redacted regardless of content.

**Key data structures:**
- `Trie` (`trie.go`) — holds the root `TrieNode`, global mask string, regex rules (`[]*RegexRule`), and `JSONSensitiveKeys` map.
- `TrieNode` — has literal `Children map[string]*TrieNode` and `RegexChildren []RegexEdge` for pattern-matching token edges. `"*"` key in Children is the wildcard for `<any>`/`<REDACT>`.
- `RuleMeta` — attached to terminal nodes; stores which token indices to redact (`RedactIndices`), `redact_after` string (semantic delimiter), `redact_offset`, and priority.
- `EngineWorkspace` — pooled (`workspacePool`) scratch space for one redaction pass; recycled across calls to avoid allocations.

**Concurrency:** `ProcessStream` (`orchestrator.go`) fans input into 256KB chunks dispatched to a worker pool via channels. An order-preserving writer goroutine uses an index-keyed buffer map to emit output in original order.

## Rule Files

Rules live in `rules/*.json` and are loaded at startup by `LoadRulesFromDir`. Three rule types:

1. **Trie rules** (default) — `phrase` is a token sequence. Tokens can be literals, `<any>`, `<REDACT>`, `<any:pattern>`, `<redact:pattern>`.
2. **Regex rules** — `"isRegex": true`, `phrase[0]` is the pattern. Use capture groups to redact only part of the match.
3. **JSON key rules** — `"type": "json_key"`, `phrase` is a list of key names. Values under those keys are always fully star-redacted.

Rule fields: `id`, `phrase`, `priority` (lower = wins on overlap), `enabled`, `mask` (per-rule mask, overrides global), `redact_offset` (byte skip before redacting), `redact_after` (case-insensitive string; redaction starts after this delimiter), `min_length`/`max_length` (skip redaction if captured secret is outside this length range).

## Tests

Test cases live in `tests/*.json` (one file per platform). Each case has `id`, `input`, `expected`. Test functions in `redactor/engine_test.go` auto-detect JSON vs raw input by checking for a leading `{`. New rules must have a corresponding test case.

Adding a rule:
1. Add JSON entry to the appropriate `rules/*.json` file.
2. Add a test case with `id`, `input`, `expected` to the matching `tests/*.json` file.
3. Run `go test ./redactor/ -run TestWindowsRules/<your-id>` to verify.

# SecretScalpel

A semantic log sanitization engine for security teams. Built to strip credentials from alert data before it reaches your SOAR, your case comments, and your customers.

## The Problem

Windows alerts are full of credentials. `psexec` commands, `net use` strings, database connection strings with passwords inline. They flow from your SIEM into your SOAR, into case comments, into ticket descriptions, onto email distribution lists that your customers can read.

Most teams handle this with regex. Regex doesn't understand context. It doesn't know that `-p` means password in `psexec` but not in `grep`. It fires on things it shouldn't and misses things it should catch.

SecretScalpel uses a token-aware rule engine that understands command structure. It knows that in `net use Z: \\server P@ssw0rd domain` the fourth token is a credential — not because it matched a pattern on the word "password", but because it understands the structure of a Windows `net use` command.

## How It Works

SecretScalpel tokenizes each log line and walks a rule trie. Rules match on sequences of tokens, not raw strings. A rule like:

```json
{ "id": "WIN-PSEXEC", "phrase": ["psexec", "-u", "<any>", "-p", "<REDACT>"] }
```

matches `psexec -u admin -p SuperSecret!` and redacts only the password token, leaving the rest of the line intact and parseable.

For patterns that genuinely require regex — URL basic auth, database connection strings, attached flag syntax — a small set of regex rules runs as a fallback. Everything else goes through the trie.

## Performance

Benchmarked on an i9-13900K (24 cores):

| Scenario | Throughput |
|---|---|
| Realistic JSON log data (1 secret per 20 lines) | **~1000 MB/s** |
| Worst case (raw logs, secrets on ~80% of lines) | 67 MB/s |

Realistic throughput on a single machine translates to over **80 TB/day**. The clean-path for both raw and JSON logs is highly optimized to minimize memory allocations. Key optimizations include per-rule `required_byte` guards that skip regex evaluation when a trigger character is absent, cache-line-padded metrics to eliminate false sharing across workers, and a pooled workspace to avoid per-line allocations.

Honest caveat: the "worst-case" benchmark uses data where almost every line contains a credential. Real production log data does not look like this. The ~1000 MB/s figure reflects actual MSSP workloads with structured JSON logs.

## Rule Format

Rules are plain JSON. They live in the `rules/` directory and are loaded at startup. No recompilation required.

```json
[
  {
    "id": "WIN-NET-USE",
    "phrase": ["net", "use", "<any:^[\\\\/]+.*>", "<REDACT>"],
    "priority": 4,
    "enabled": true
  },
  {
    "id": "WIN-PSEXEC-SEPARATED",
    "phrase": ["psexec", "-u", "<any>", "-p", "<REDACT>"],
    "priority": 1,
    "enabled": true
  }
]
```

**Phrase tokens:**
- Literal string — must match exactly (case-insensitive)
- `<REDACT>` — matches any token and redacts it
- `<any>` — matches any token without redacting
- `<any:pattern>` — matches tokens whose text matches the regex pattern
- `<redact:pattern>` — matches and redacts tokens matching the pattern

**Regex rules** (for patterns that can't be expressed as token sequences):
```json
{
  "id": "PHASE0-URI-BASIC-AUTH",
  "phrase": ["(?i)https?://[^\\s:]+:([^\\s@:]+)@[^\\s/]+"],
  "isRegex": true,
  "required_byte": "@",
  "priority": 4,
  "enabled": true
}
```

The optional `required_byte` field skips regex evaluation entirely when the specified byte is absent from the input line — a cheap early-exit guard.

Rules are auditable, git-diffable, and reviewable by anyone on your team without touching Go code. Duplicate rule IDs across files are logged as warnings at startup.

## Included Rules

SecretScalpel ships with rules covering common credential exposure patterns:

**Windows:**
- `net use` — UNC path authentication
- `psexec` — both attached (`-pPassword`) and separated (`-p Password`) forms
- `cmdkey` — credential manager
- `runas` — user impersonation
- `schtasks` — scheduled task credentials
- `sqlcmd`, `wmic`, `appcmd` — database and management tooling
- `az login`, `dsmod`, `netdom` — Azure CLI and AD tooling
- `mstsc`, `rasdial` — remote access
- PowerShell `ConvertTo-SecureString`, `Set-LocalUser`, `$env:PASSWORD = ...`
- URL basic auth (`https://user:pass@host`)
- Database connection strings (`Password=value;`)
- Generic flag patterns (`--password=value`, `/p:value`)

**Linux & Cloud:**
- `curl` basic auth, `mysql`/`psql` command-line credentials
- `openssl`, `gpg`, `ssh-keygen` passphrase flags
- `git clone` HTTPS with embedded credentials
- AWS, GCP (`gcloud`), and Azure CLI credential flags

**Third-party:**
- Impacket credential syntax (`user:pass@host`)
- JSON sensitive key redaction (API keys, tokens, secrets in structured logs)

## Usage

### CLI

```bash
# Redact raw log lines from stdin
echo 'psexec -u admin -p SuperSecret! cmd.exe' | secretscalpel

# Redact JSON log data, preserving structure
echo '{"log": "net use Z: \\server P@ssword domain"}' | secretscalpel -json

# Validate rule files (useful in CI before deploy)
secretscalpel -validate-rules

# Print version
secretscalpel -version

# Health check (load rules, print OK, exit 0)
secretscalpel -health
```

**Flags:**

| Flag | Env var | Default | Description |
|------|---------|---------|-------------|
| `-rules` | `SECRETSCALPEL_RULES_DIR` | `./rules` | Path to rules directory |
| `-json` | `SECRETSCALPEL_JSON_MODE` | `false` | JSON mode — walks string values only |
| `-workers` | `SECRETSCALPEL_WORKERS` | NumCPU | Worker goroutine count |
| `-mask` | `SECRETSCALPEL_MASK` | `*` | Redaction mask character(s) |
| `-fail-open` | `SECRETSCALPEL_FAIL_OPEN` | `false` | Pass input through unredacted on error |
| `-admin-addr` | `SECRETSCALPEL_ADMIN_ADDR` | `""` | HTTP admin server address (e.g. `:9090`) |
| `-validate-rules` | — | — | Validate rule files and exit (0=ok, 1=error) |
| `-health` | — | — | Verify rules load, print OK, exit 0 |
| `-version` | — | — | Print version and exit |

### Admin HTTP server

When `-admin-addr` is set, an HTTP server exposes:

- `GET /health` — returns `{"status":"ok","version":"..."}` always
- `GET /ready` — returns `{"status":"ready","rules":N}` or 503 if no rules are loaded
- `GET /metrics` — Prometheus text exposition with counters:
  - `secretscalpel_chunks_processed_total`
  - `secretscalpel_bytes_in_total`
  - `secretscalpel_lines_dropped_total`
  - `secretscalpel_worker_panics_total`
  - `secretscalpel_write_errors_total`
  - `secretscalpel_redactions_applied_total`

### Hot reload

Send `SIGHUP` to reload rules from disk without restarting the process. In-flight chunks continue with the old trie; new chunks pick up the updated rules atomically.

```bash
kill -HUP $(pidof secretscalpel)
```

### Docker

```bash
docker build -t secretscalpel .

# Pipe logs through the container
cat app.log | docker run -i --rm secretscalpel

# With custom rules directory
cat app.log | docker run -i --rm -v /my/rules:/rules secretscalpel -rules /rules
```

### As a library

```go
import "secretscalpel/redactor"

trie := redactor.NewTrie("*", 0, 0)
redactor.LoadRulesFromDir("./rules", trie)

// Redact a raw log line
redacted := redactor.RedactBytes([]byte(line), trie)

// Redact JSON log data while preserving structure
redacted := redactor.RedactAllJSONStrings([]byte(jsonLine), trie)

// Stream processing with parallel workers and context cancellation
var triePtr atomic.Pointer[redactor.Trie]
triePtr.Store(trie)
err := redactor.ProcessStream(ctx, reader, writer, &triePtr, isJSON, 0) // 0 = NumCPU
```

### JSON vs Raw mode

SecretScalpel has two processing modes:

- **Raw mode** (`RedactBytes`) — processes the entire input as a flat byte stream. Use for plaintext logs, syslog, CEF format.
- **JSON mode** (`RedactAllJSONStrings`) — walks JSON string values only, leaving keys and structure intact. Use for structured JSON logs (Elastic, Splunk JSON, etc.). Output remains valid, parseable JSON.

JSON keys listed in `json_keys.json` have their values fully star-redacted regardless of content.

## Limitations

**SecretScalpel is a sanitization tool, not a DLP system.** It does not:
- Detect all possible credential formats — only patterns covered by loaded rules
- Guarantee zero false negatives — novel credential formats without rules will pass through
- Replace network-level DLP or CASB tooling
- Handle binary log formats

If a credential format isn't covered by a rule, it won't be redacted. Test your rules against your actual alert data before deploying in a production pipeline.

## Architecture

```
Input stream
     │
     ▼
ProcessStream (orchestrator)
     │ chunks input into 256KB batches, fans out to worker pool
     ▼
RedactAllJSONStrings / RedactBytes
     │
     ├── Phase 0: Regex rules (URL auth, connection strings)
     │   each rule has an optional required_byte guard;
     │   the rule is skipped entirely if its byte is absent
     │
     └── Phase 1: Trie engine
         tokenizes line → sliding window → matches rule phrases
         redacts matched tokens in-place
```

The worker pool dispatches `*atomic.Pointer[Trie]` so rules can be hot-reloaded via SIGHUP with zero downtime. The trie uses a recycled `EngineWorkspace` pool to minimize per-line allocations. On clean lines (no secrets) the input slice is returned without copying.

Lines exceeding 1MB are dropped with a warning to prevent unbounded memory growth and pathological regex backtracking.

## Contributing

Rule contributions are the highest-value contribution. If you have credential patterns from your own environment that aren't covered, open a PR with:
- The rule JSON
- An example input line
- The expected redacted output

New rules must have a corresponding test case in `tests/`.

## License

MIT

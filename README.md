# RedactBox

A semantic log sanitization engine for security teams. Built to strip credentials from Windows alert data before it reaches your SOAR, your case comments, and your customers.

## The Problem

Windows alerts are full of credentials. `psexec` commands, `net use` strings, database connection strings with passwords inline. They flow from your SIEM into your SOAR, into case comments, into ticket descriptions, onto email distribution lists that your customers can read.

Most teams handle this with regex. Regex doesn't understand context. It doesn't know that `-p` means password in `psexec` but not in `grep`. It fires on things it shouldn't and misses things it should catch.

RedactBox uses a token-aware rule engine that understands command structure. It knows that in `net use Z: \\server P@ssw0rd domain` the fourth token is a credential — not because it matched a pattern on the word "password", but because it understands the structure of a Windows `net use` command.

## How It Works

RedactBox tokenizes each log line and walks a rule trie. Rules match on sequences of tokens, not raw strings. A rule like:

```json
{ "id": "WIN-PSEXEC", "phrase": ["psexec", "-u", "<any>", "-p", "<REDACT>"] }
```

matches `psexec -u admin -p SuperSecret!` and redacts only the password token, leaving the rest of the line intact and parseable.

For patterns that genuinely require regex — URL basic auth, database connection strings, attached flag syntax — a small set of regex rules runs as a fallback. Everything else goes through the trie.

## Performance

Benchmarked on an i9-13900K (24 cores):

| Scenario | Throughput |
|---|---|
| Realistic log data (1 secret per 20 lines) | **985 MB/s** |
| Worst case (secrets on 80% of lines) | 67 MB/s |

Realistic throughput translates to roughly 1.8 TB/day on a single machine. The clean-path is nearly allocation-free — lines with no secrets are returned without copying.

Honest caveat: the worst-case benchmark uses data where almost every line contains a credential. Real production log data does not look like this. The 985 MB/s number reflects actual MSSP workloads.

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
- `<any:pattern>` — matches tokens that match the regex pattern
- `<redact:pattern>` — matches and redacts tokens matching the pattern
- `redact_offset` — skip N bytes at the start of the matched token before redacting (for attached flags like `-pMyPassword`)

**Regex rules** (for patterns that can't be expressed as token sequences):
```json
{
  "id": "PHASE0-URI-BASIC-AUTH",
  "phrase": ["(?i)https?://[^\\s:]+:([^\\s@:]+)@[^\\s/]+"],
  "isRegex": true,
  "priority": 4,
  "enabled": true
}
```

Rules are auditable, git-diffable, and reviewable by anyone on your team without touching Go code.

## Included Rules

RedactBox ships with rules for common Windows credential exposure patterns:

- `net use` — UNC path authentication
- `psexec` — both attached (`-pPassword`) and separated (`-p Password`) forms
- `cmdkey` — credential manager
- `runas` — user impersonation
- `schtasks` — scheduled task credentials
- `sqlcmd`, `wmic`, `appcmd` — database and management tooling
- `az login`, `dsmod`, `netdom` — Azure CLI and AD tooling
- `mstsc`, `rasdial` — remote access
- PowerShell `ConvertTo-SecureString`, `Set-LocalUser`
- URL basic auth (`https://user:pass@host`)
- Database connection strings (`Password=value;`)
- Generic flag patterns (`--password=value`, `/p:value`)

## Usage

### As a library

```go
import "redactbox/redactor"

trie := redactor.NewTrie("*", 0, 0)
redactor.LoadRulesFromDir("./rules", trie)

// Redact a raw log line
redacted := redactor.RedactBytes([]byte(line), trie)

// Redact JSON log data while preserving structure
redacted := redactor.RedactAllJSONStrings([]byte(jsonLine), trie)

// Stream processing with parallel workers
err := redactor.ProcessStream(reader, writer, trie, isJSON, 0) // 0 = NumCPU
```

### JSON vs Raw mode

RedactBox has two processing modes:

- **Raw mode** (`RedactBytes`) — processes the entire input as a flat byte stream. Use for plaintext logs, syslog, CEF format.
- **JSON mode** (`RedactAllJSONStrings`) — walks JSON string values only, leaving keys and structure intact. Use for structured JSON logs (Elastic, Splunk JSON, etc.). Output remains valid, parseable JSON.

## Limitations

**RedactBox is a sanitization tool, not a DLP system.** It does not:
- Detect all possible credential formats — only patterns covered by loaded rules
- Guarantee zero false negatives — novel credential formats without rules will pass through
- Replace network-level DLP or CASB tooling
- Handle binary log formats

The rule set covers common Windows CLI credential patterns observed in MSSP alert pipelines. Coverage for Linux, cloud CLI tools, and application-specific formats is limited and will improve over time.

If a credential format isn't covered by a rule, it won't be redacted. Test your rules against your actual alert data before deploying in a production pipeline.

## Architecture

```
Input stream
     │
     ▼
ProcessStream (orchestrator)
     │ chunks input, fans out to worker pool
     ▼
RedactAllJSONStrings / RedactBytes
     │
     ├── Phase 0: Regex rules (URL auth, connection strings)
     │   runs only when trigger chars (@, =, /) are present
     │
     └── Phase 1: Trie engine
         tokenizes line → sliding window → matches rule phrases
         redacts matched tokens in-place
```

The trie uses a recycled workspace pool to minimize allocations. On clean lines (no secrets) the input slice is returned without copying.

## Contributing

Rule contributions are the highest-value contribution. If you have credential patterns from your own environment that aren't covered, open a PR with:
- The rule JSON
- An example input line
- The expected redacted output

New rules should have a corresponding test case in `tests/`.

## License

MIT
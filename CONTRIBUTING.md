# Contributing to SecretScalpel

We welcome contributions, especially new rules to cover credential patterns we missed!

## 1. How to Add a Rule

Rules are defined in JSON files located in the `rules/` directory. You can add a new rule to an existing file (e.g., `linux.json`) or create a new file (e.g., `my_custom_rules.json`).

### Rule Types

#### A. Token Sequence Rules (Preferred)
These are fast ($O(k)$) and should be used whenever the secret appears in a predictable command structure.

```json
{
  "id": "MY-RULE-ID",
  "phrase": ["command", "-flag", "<any>", "--secret", "<REDACT>"],
  "priority": 1,
  "enabled": true
}
```

**Tokens:**
- `"string"`: Literal match (case-insensitive).
- `"<REDACT>"`: Matches any token and redacts it.
- `"<any>"`: Matches any token (wildcard) without redacting.
- `"<any:regex>"`: Matches a token only if it satisfies the regex (e.g., `<any:^--.*>`).
- `"<redact:regex>"`: Matches and redacts a token only if it satisfies the regex.

#### B. Regex Rules (Fallback)
Use these only when tokenization fails (e.g., secrets inside a URL or connection string).

```json
{
  "id": "MY-REGEX-RULE",
  "phrase": ["(?i)password=([^;]+)"],
  "isRegex": true,
  "required_byte": "=",
  "priority": 2,
  "enabled": true
}
```

**Fields:**
- `phrase`: Array containing a single regex string. Use capture groups `()` to define what to redact.
- `required_byte`: (Optional but recommended) A single character that *must* be present in the line for this regex to run. This is a massive performance optimization.

### Common Fields

| Field | Type | Description |
|-------|------|-------------|
| `id` | string | Unique identifier for the rule. |
| `priority` | int | Lower numbers run first. Use `0-9`. Default is `0`. |
| `min_length` | int | (Optional) Ignore secrets shorter than this. |
| `max_length` | int | (Optional) Ignore secrets longer than this. |
| `redact_after` | string | (Optional) Start redaction only after this substring (e.g., `":"` in `user:pass`). |
| `mask` | string | (Optional) Override the global mask (e.g., `"***"`). |

---

## 2. How to Test Your Rule

Every rule **must** have a corresponding test case to ensure it works and to prevent regressions.

1.  Open the corresponding test file in `tests/` (e.g., `tests/linux_tests.json`).
2.  Add a test case entry:

```json
{
  "id": "MY-RULE-ID",
  "input": "command -flag value --secret SuperSecret123",
  "expected": "command -flag value --secret *************"
}
```

3.  Run the tests:

```bash
make test
```

If you want to run only your specific test (faster):

```bash
go test -v ./redactor/ -run MY-RULE-ID
```

---

## 3. Performance Guidelines

SecretScalpel is designed for high-throughput logging pipelines.

1.  **Avoid Regex if possible:** Token rules are significantly faster.
2.  **Use `required_byte`:** If you must use regex, always set a `required_byte` (e.g., `@` for emails, `=` for connection strings).
3.  **Be specific:** `["psexec", "-p", "<REDACT>"]` is better than `["<any>", "-p", "<REDACT>"]`.

## 4. Running Benchmarks

If you modify the core engine code, please run benchmarks to ensure no performance regressions.

```bash
make bench
```

We aim for **>900 MB/s** on the "Realistic" benchmark.
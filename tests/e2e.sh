#!/bin/bash
set -euo pipefail

# Run from the project root.
if [ ! -f "go.mod" ]; then
    echo "Error: run this script from the project root." >&2
    exit 1
fi

PASS=0
FAIL=0

pass() { echo "  PASS: $1"; PASS=$((PASS+1)); }
fail() { echo "  FAIL: $1"; echo "        expected: $2"; echo "        got:      $3"; FAIL=$((FAIL+1)); }

check() {
    local desc="$1" expected="$2" got="$3"
    if [ "$got" = "$expected" ]; then
        pass "$desc"
    else
        fail "$desc" "$expected" "$got"
    fi
}

echo "Building secretscalpel..."
go build -o secretscalpel .
trap 'rm -f secretscalpel' EXIT

echo ""
echo "--- Flags ---"

check "--version prints version" \
    "secretscalpel v0.1.0" \
    "$(./secretscalpel --version 2>/dev/null)"

check "--health exits 0" \
    "OK" \
    "$(./secretscalpel --health 2>/dev/null)"

check "--validate-rules exits 0 on valid rules" \
    "OK" \
    "$(./secretscalpel --validate-rules 2>/dev/null)"

echo ""
echo "--- Raw log redaction ---"

check "psexec -p flag" \
    "psexec -u admin -p ********* cmd.exe" \
    "$(echo 'psexec -u admin -p Secret123 cmd.exe' | ./secretscalpel 2>/dev/null)"

check "net use password" \
    "net use Z: \\\\fileserver\\share alice ******** domain" \
    "$(echo 'net use Z: \\fileserver\share alice P@ssword domain' | ./secretscalpel 2>/dev/null)"

check "URL basic auth" \
    "https://user:********@host/path" \
    "$(echo 'https://user:password@host/path' | ./secretscalpel 2>/dev/null)"

check "clean line passes through unchanged" \
    "this is a normal log line" \
    "$(echo 'this is a normal log line' | ./secretscalpel 2>/dev/null)"

echo ""
echo "--- JSON log redaction ---"

check "JSON wrapped psexec" \
    '{"log": "psexec -u admin -p ********* cmd.exe"}' \
    "$(echo '{"log": "psexec -u admin -p Secret123 cmd.exe"}' | ./secretscalpel 2>/dev/null)"

check "JSON key rule redacts by key name" \
    '{"password": "***********"}' \
    "$(echo '{"password": "mysecret123"}' | ./secretscalpel 2>/dev/null)"

check "JSON non-string values untouched" \
    '{"retries": 3, "enabled": true}' \
    "$(echo '{"retries": 3, "enabled": true}' | ./secretscalpel 2>/dev/null)"

check "clean JSON line passes through unchanged" \
    '{"level": "INFO", "msg": "hello world"}' \
    "$(echo '{"level": "INFO", "msg": "hello world"}' | ./secretscalpel 2>/dev/null)"

echo ""
echo "--- Auto-detect mixed stream ---"

MIXED_IN=$'psexec -u admin -p Secret123 cmd.exe\n{"log": "net use Z: \\\\\\\\fileserver\\\\share alice P@ssword domain"}\nnormal log line'
MIXED_OUT=$'psexec -u admin -p ********* cmd.exe\n{"log": "net use Z: \\\\\\\\fileserver\\\\share alice ******** domain"}\nnormal log line'

check "mixed raw+JSON stream" \
    "$MIXED_OUT" \
    "$(echo "$MIXED_IN" | ./secretscalpel 2>/dev/null)"

echo ""
echo "--- --debug-rules flag ---"

DEBUG_OUT="$(echo 'psexec -u admin -p Secret123 cmd.exe' | ./secretscalpel --debug-rules 2>/dev/null)"
if echo "$DEBUG_OUT" | grep -qE '\[3P-PSEXEC|WIN-PSEXEC|[A-Z0-9-]+\]'; then
    pass "--debug-rules injects rule ID tags"
else
    fail "--debug-rules injects rule ID tags" "[RULE-ID] tag in output" "$DEBUG_OUT"
fi

echo ""
echo "--- Empty and edge-case input ---"

check "empty input produces empty output" \
    "" \
    "$(echo -n '' | ./secretscalpel 2>/dev/null)"

check "whitespace-only line passes through" \
    "   " \
    "$(echo '   ' | ./secretscalpel 2>/dev/null)"

echo ""
echo "--- Generic pattern rules ---"

check "JWT bearer token" \
    "Authorization: Bearer **************************************************************" \
    "$(echo 'Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyIn0.abc123def456ghi789jkl' | ./secretscalpel 2>/dev/null)"

check "AWS access key ID" \
    "AWS_ACCESS_KEY_ID=********************" \
    "$(echo 'AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE' | ./secretscalpel 2>/dev/null)"

check "PEM private key body" \
    "key: -----BEGIN RSA PRIVATE KEY-----******************-----END RSA PRIVATE KEY-----" \
    "$(echo 'key: -----BEGIN RSA PRIVATE KEY----- MIIEowIBAAKCAQEA -----END RSA PRIVATE KEY-----' | ./secretscalpel 2>/dev/null)"

echo ""
echo "--- --mask flag ---"

check "--mask changes redaction string" \
    "psexec -u admin -p [REDACTED] cmd.exe" \
    "$(echo 'psexec -u admin -p Secret123 cmd.exe' | ./secretscalpel --mask '[REDACTED]' 2>/dev/null)"

echo ""
if [ "$FAIL" -eq 0 ]; then
    echo "All $PASS tests passed."
    exit 0
else
    echo "$FAIL/$((PASS+FAIL)) tests FAILED."
    exit 1
fi

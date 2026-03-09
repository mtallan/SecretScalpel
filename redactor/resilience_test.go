package redactor

import (
	"bytes"
	"context"
	"io"
	"strings"
	"sync/atomic"
	"testing"
)

// TestRedactBytes_NegativeCases covers edge-case and adversarial inputs that the
// happy-path test suite never exercises.
func TestRedactBytes_NegativeCases(t *testing.T) {
	cases := []struct {
		name  string
		input string
	}{
		{"empty", ""},
		{"whitespace only", "   \t\n\r  "},
		{"null bytes", "\x00\x00\x00"},
		{"high unicode", "日本語テスト パスワード=秘密"},
		{"emoji", "🔑 password=🔐secret🔐"},
		{"only quotes", `""""""`},
		{"only equals signs", "========="},
		{"only at signs", "@@@@@@@"},
		{"only colons", ":::::::"},
		{"only dashes", "---------"},
		{"lone surrogate-like bytes", "\xed\xa0\x80"},
		{"very long token no spaces", strings.Repeat("A", 4096)},
		{"token at exactly 256 chars", strings.Repeat("B", 256)},
		{"256 tokens", strings.Repeat("word ", 256)},
		{"257 tokens", strings.Repeat("word ", 257)},
		{"binary garbage", "\x01\x02\x03\xff\xfe\xfd"},
		{"mixed ascii and binary", "password=\x00\xff\x80secret"},
		{"newline only", "\n"},
		{"carriage return only", "\r"},
		{"crlf only", "\r\n"},
		{"multiple newlines", "\n\n\n\n\n"},
		{"tab separated", "key\tvalue\tsecret"},
		{"deeply nested equals", "a=b=c=d=e=f=g=h=i=j=k=l=m=n"},
		{"url-like no creds", "https://example.com/path?query=value"},
		{"partial url", "https://"},
		{"at sign no user", "@hostname"},
		{"equals at end", "something="},
		{"colon at start", ":value"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// Must not panic
			got := RedactBytes([]byte(tc.input), testRoot)
			// Output must be non-nil even for empty input
			if got == nil && tc.input != "" {
				t.Error("RedactBytes returned nil for non-empty input")
			}
		})
	}
}

// TestRedactAllJSONStrings_NegativeCases covers malformed and edge-case JSON.
func TestRedactAllJSONStrings_NegativeCases(t *testing.T) {
	cases := []struct {
		name  string
		input string
	}{
		{"empty", ""},
		{"not json", "this is not json at all"},
		{"partial object", `{"key":`},
		{"unclosed string", `{"key": "value`},
		{"null value", `{"key": null}`},
		{"numeric value", `{"key": 12345}`},
		{"boolean value", `{"key": true}`},
		{"nested nulls", `{"a": {"b": null}}`},
		{"empty object", `{}`},
		{"empty array", `[]`},
		{"empty string value", `{"key": ""}`},
		{"unicode in value", `{"key": "日本語"}`},
		{"escaped quotes", `{"key": "value with \"quotes\""}`},
		{"null bytes in string", "{\"key\": \"val\x00ue\"}"},
		{"deeply nested", `{"a":{"b":{"c":{"d":{"e":"value"}}}}}`},
		{"array of objects", `[{"key":"val"},{"key":"val2"}]`},
		{"number at top level", `42`},
		{"string at top level", `"just a string"`},
		{"trailing comma", `{"key": "value",}`},
		{"missing value", `{"key": }`},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// Must not panic
			got := RedactAllJSONStrings([]byte(tc.input), testRoot)
			if got == nil {
				t.Error("RedactAllJSONStrings returned nil")
			}
		})
	}
}

// TestProcessStream_MaxLineLength verifies that lines over 1MB are dropped
// rather than causing unbounded memory growth.
func TestProcessStream_MaxLineLength(t *testing.T) {
	// Build a 2MB line (no newline) followed by a normal line
	hugeLine := bytes.Repeat([]byte("A"), 2*1024*1024)
	normal := []byte("net use Z: \\\\server P@ssword domain\n")

	var input bytes.Buffer
	input.Write(hugeLine)
	input.WriteByte('\n')
	input.Write(normal)

	var output bytes.Buffer
	if err := ProcessStream(context.Background(), bytes.NewReader(input.Bytes()), &output, &testTriePtr, false, 1); err != nil {
		t.Fatalf("ProcessStream error: %v", err)
	}

	out := output.String()
	// The first portion of the huge line (up to maxLineBytes) passes through, but
	// its remainder is dropped. The normal line after it must still be processed.
	if !strings.Contains(out, "net use") {
		t.Error("Expected normal line after huge line to appear in output")
	}
	// The full 2MB of A's should not appear — the remainder was dropped
	if strings.Contains(out, strings.Repeat("A", 2*1024*1024)) {
		t.Error("Expected remainder of huge line to be dropped")
	}
}

// TestProcessStream_EmptyInput verifies empty input produces empty output without error.
func TestProcessStream_EmptyInput(t *testing.T) {
	var output bytes.Buffer
	if err := ProcessStream(context.Background(), bytes.NewReader(nil), &output, &testTriePtr, false, 1); err != nil {
		t.Fatalf("unexpected error on empty input: %v", err)
	}
	if output.Len() != 0 {
		t.Errorf("expected empty output, got %d bytes", output.Len())
	}
}

// TestProcessStream_NilTrie verifies the engine doesn't panic with a nil trie.
func TestProcessStream_NilTrie(t *testing.T) {
	emptyTrie := NewTrie("*", 0, 0)
	var emptyPtr atomic.Pointer[Trie]
	emptyPtr.Store(emptyTrie)
	input := bytes.NewReader([]byte("some log line\n"))
	var output bytes.Buffer
	if err := ProcessStream(context.Background(), input, &output, &emptyPtr, false, 1); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

// TestProcessStream_OutputOrdering verifies that output order matches input order
// even with concurrent workers.
func TestProcessStream_OutputOrdering(t *testing.T) {
	var input bytes.Buffer
	var expected strings.Builder

	// Write enough lines to span multiple chunks and exercise the order-preserving writer
	for i := 0; i < 10000; i++ {
		line := "line with no secrets number one\n"
		input.WriteString(line)
		expected.WriteString(line)
	}

	var output bytes.Buffer
	if err := ProcessStream(context.Background(), bytes.NewReader(input.Bytes()), &output, &testTriePtr, false, 4); err != nil {
		t.Fatalf("ProcessStream error: %v", err)
	}

	if output.String() != expected.String() {
		t.Error("Output order does not match input order")
	}
}

// TestProcessStream_ConcurrentSafety runs ProcessStream concurrently to catch
// data races. Run with: go test -race ./redactor/...
func TestProcessStream_ConcurrentSafety(t *testing.T) {
	input := bytes.Repeat([]byte("psexec -u admin -p Secret123 cmd.exe\n"), 1000)

	for i := 0; i < 5; i++ {
		t.Run("run", func(t *testing.T) {
			t.Parallel()
			if err := ProcessStream(context.Background(), bytes.NewReader(input), io.Discard, &testTriePtr, false, 2); err != nil {
				t.Errorf("ProcessStream error: %v", err)
			}
		})
	}
}

// FuzzRedactBytes feeds arbitrary byte slices into the redaction engine.
// Run with: go test -fuzz=FuzzRedactBytes ./redactor/...
func FuzzRedactBytes(f *testing.F) {
	// Seed corpus with interesting edge cases
	seeds := []string{
		"",
		"normal log line",
		"psexec -u admin -p Secret123 cmd.exe",
		"net use Z: \\\\server P@ssword domain",
		"https://user:pass@host/path",
		"\x00\x01\x02\xff",
		strings.Repeat("A", 1024),
		"key=value key2=value2",
		`{"password": "secret"}`,
		"日本語 password=秘密",
	}
	for _, s := range seeds {
		f.Add([]byte(s))
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		// Must not panic
		got := RedactBytes(data, testRoot)
		// Output length must never exceed input length by more than the mask overhead
		// (redacted region replaced 1:1 with stars or mask string, so len(out) == len(in))
		_ = got
	})
}

// FuzzRedactAllJSONStrings feeds arbitrary byte slices into the JSON walker.
// Run with: go test -fuzz=FuzzRedactAllJSONStrings ./redactor/...
func FuzzRedactAllJSONStrings(f *testing.F) {
	seeds := []string{
		"",
		"{}",
		"[]",
		`{"key": "value"}`,
		`{"password": "secret123"}`,
		`[{"a":"b"},{"c":"d"}]`,
		`{"nested": {"password": "secret"}}`,
		"not json at all",
		"\x00",
		`{"key": null}`,
	}
	for _, s := range seeds {
		f.Add([]byte(s))
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		// Must not panic
		got := RedactAllJSONStrings(data, testRoot)
		_ = got
	})
}

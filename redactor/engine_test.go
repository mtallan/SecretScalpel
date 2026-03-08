package redactor

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"testing"
)

type TestCase struct {
	ID       string `json:"id"`
	Input    string `json:"input"`
	Expected string `json:"expected"`
}

func TestLinuxRules(t *testing.T) {
	root := NewTrie("*", 2, 0)
	err := LoadRulesFromDir("../rules", root)
	if err != nil {
		t.Fatalf("Failed to load rules: %v", err)
	}

	testFileData, err := os.ReadFile("../tests/linux_tests.json")
	if err != nil {
		t.Fatalf("Failed to read test file: %v", err)
	}

	var tests []TestCase
	if err := json.Unmarshal(testFileData, &tests); err != nil {
		t.Fatalf("Failed to unmarshal test cases: %v", err)
	}

	for _, tc := range tests {
		t.Run(tc.ID, func(t *testing.T) {
			inputBytes := []byte(tc.Input)
			var resultBytes []byte

			if bytes.HasPrefix(bytes.TrimSpace(inputBytes), []byte("{")) {
				resultBytes = RedactAllJSONStrings(inputBytes, root)
			} else {
				resultBytes = RedactBytes(inputBytes, root)
			}

			if string(resultBytes) != tc.Expected {
				t.Errorf("\nInput:    %s\nExpected: %s\nGot:      %s", tc.Input, tc.Expected, string(resultBytes))
			}
		})
	}
}
func TestWindowsRules(t *testing.T) {
	// 1. Initialize the Trie
	root := NewTrie("*", 2, 0)

	// Step up one directory to reach the rules folder
	err := LoadRulesFromDir("../rules", root)
	if err != nil {
		t.Fatalf("Failed to load rules: %v", err)
	}

	// 2. Load the test cases (stepping up one directory to reach the tests folder)
	testFileData, err := os.ReadFile("../tests/windows_tests.json")
	if err != nil {
		t.Fatalf("Failed to read test file: %v", err)
	}

	var tests []TestCase
	if err := json.Unmarshal(testFileData, &tests); err != nil {
		t.Fatalf("Failed to unmarshal test cases: %v", err)
	}

	// 3. Execute Table-Driven Tests
	for _, tc := range tests {
		t.Run(tc.ID, func(t *testing.T) {
			inputBytes := []byte(tc.Input)
			var resultBytes []byte

			// Auto-detect JSON payload vs Raw CLI string
			if bytes.HasPrefix(bytes.TrimSpace(inputBytes), []byte("{")) {
				resultBytes = RedactAllJSONStrings(inputBytes, root)
			} else {
				resultBytes = RedactBytes(inputBytes, root)
			}

			result := string(resultBytes)

			// Assert equality
			if result != tc.Expected {
				t.Errorf("\nInput:    %s\nExpected: %s\nGot:      %s", tc.Input, tc.Expected, result)
			}
		})
	}
}
func TestMacRules(t *testing.T) {
	root := NewTrie("*", 2, 0)
	err := LoadRulesFromDir("../rules", root)
	if err != nil {
		t.Fatalf("Failed to load rules: %v", err)
	}

	testFileData, err := os.ReadFile("../tests/mac_tests.json")
	if err != nil {
		t.Fatalf("Failed to read test file: %v", err)
	}

	var tests []TestCase
	if err := json.Unmarshal(testFileData, &tests); err != nil {
		t.Fatalf("Failed to unmarshal test cases: %v", err)
	}

	for _, tc := range tests {
		t.Run(tc.ID, func(t *testing.T) {
			resultBytes := RedactBytes([]byte(tc.Input), root)
			if string(resultBytes) != tc.Expected {
				t.Errorf("\nInput:    %s\nExpected: %s\nGot:      %s", tc.Input, tc.Expected, string(resultBytes))
			}
		})
	}
}

func TestJSONKeyRules(t *testing.T) {
	root := NewTrie("*", 2, 0)
	err := LoadRulesFromDir("../rules", root)
	if err != nil {
		t.Fatalf("Failed to load rules: %v", err)
	}

	testFileData, err := os.ReadFile("../tests/json_key_tests.json")
	if err != nil {
		t.Fatalf("Failed to read test file: %v", err)
	}

	var tests []TestCase
	if err := json.Unmarshal(testFileData, &tests); err != nil {
		t.Fatalf("Failed to unmarshal test cases: %v", err)
	}

	for _, tc := range tests {
		t.Run(tc.ID, func(t *testing.T) {
			// JSON key sentinel tests always go through RedactAllJSONStrings
			resultBytes := RedactAllJSONStrings([]byte(tc.Input), root)
			if string(resultBytes) != tc.Expected {
				t.Errorf("\nInput:    %s\nExpected: %s\nGot:      %s", tc.Input, tc.Expected, string(resultBytes))
			}
		})
	}
}

func BenchmarkEngine_1MB_Raw(b *testing.B) {
	root := NewTrie("********", 2, 0)

	// Load your actual rules. Since the test runs inside the /redactor
	// directory, we step up one level to hit the /rules folder.
	err := LoadRulesFromDir("../rules", root)
	if err != nil {
		b.Fatalf("Failed to load rules for benchmark: %v", err)
	}

	// Build a chunky dummy log chunk
	chunk := []byte(`{"timestamp": "2026-03-01T12:00:00Z", "cmd": "net use Z: \\server\share P@ssw0rd123! domain"}
2026-03-01 12:00:01 INFO Executing: psexec -u admin -p SuperSecret! cmd.exe
{"url": "https://admin:MySecretPass@api.corp.local/data"}
2026-03-01 12:00:03 DEBUG Server=tcp:prod.db,1433;User ID=sa;Password=DbPassword123!;
This is a normal log entry with no secrets. It should be parsed very quickly.
Another boring line.
custom-cli.exe /p:MyP@ssword! /silent
`)

	// Repeat the chunk until we have a 1MB payload
	var payload bytes.Buffer
	for payload.Len() < 1024*1024 {
		payload.Write(chunk)
	}
	rawBytes := payload.Bytes()

	b.ResetTimer()                   // Don't count the setup time
	b.ReportAllocs()                 // Tell us how much memory we are allocating
	b.SetBytes(int64(len(rawBytes))) // Allows Go to calculate MB/s

	for i := 0; i < b.N; i++ {
		_ = RedactBytes(rawBytes, root)
	}
}

func BenchmarkEngine_1MB_JSONWalker(b *testing.B) {
	root := NewTrie("********", 2, 0)
	err := LoadRulesFromDir("../rules", root)
	if err != nil {
		b.Fatalf("Failed to load rules for benchmark: %v", err)
	}

	// Same chunk, but wrapped entirely in a JSON array structure
	chunk := []byte(`{"log": "net use Z: \\server\share P@ssw0rd123! domain", "level": "INFO"},
{"log": "psexec -u admin -p SuperSecret! cmd.exe", "level": "WARN"},
{"log": "https://admin:MySecretPass@api.corp.local/data", "level": "DEBUG"},
{"log": "Server=tcp:prod.db,1433;User ID=sa;Password=DbPassword123!;", "level": "ERROR"},
{"log": "This is a normal log entry with no secrets.", "level": "INFO"},
`)

	var payload bytes.Buffer
	payload.WriteString("[\n")
	for payload.Len() < 1024*1024 {
		payload.Write(chunk)
	}
	payload.WriteString("]\n")
	rawBytes := payload.Bytes()

	b.ResetTimer()
	b.ReportAllocs()
	b.SetBytes(int64(len(rawBytes)))

	for i := 0; i < b.N; i++ {
		_ = RedactAllJSONStrings(rawBytes, root)
	}
}
func BenchmarkOrchestrator_1MB_JSONWalker(b *testing.B) {
	root := NewTrie("********", 2, 0)
	err := LoadRulesFromDir("../rules", root)
	if err != nil {
		b.Fatalf("Failed to load rules: %v", err)
	}

	chunk := []byte(`{"log": "net use Z: \\server\share P@ssw0rd123! domain", "level": "INFO"}` + "\n" +
		`{"log": "psexec -u admin -p SuperSecret! cmd.exe", "level": "WARN"}` + "\n" +
		`{"log": "https://admin:MySecretPass@api.corp.local/data", "level": "DEBUG"}` + "\n" +
		`{"log": "Server=tcp:prod.db,1433;User ID=sa;Password=DbPassword123!;", "level": "ERROR"}` + "\n" +
		`{"log": "This is a normal log entry with no secrets.", "level": "INFO"}` + "\n")

	var input bytes.Buffer
	for input.Len() < 1024*1024 {
		input.Write(chunk)
	}
	rawBytes := input.Bytes()

	b.ResetTimer()
	b.ReportAllocs()
	b.SetBytes(int64(len(rawBytes)))

	for i := 0; i < b.N; i++ {
		// Use io.Discard because we don't care about the final output during the speed test
		_ = ProcessStream(bytes.NewReader(rawBytes), io.Discard, root, true, 0)
	}
}
func BenchmarkOrchestrator_1MB_Realistic(b *testing.B) {
	root := NewTrie("********", 2, 0)
	err := LoadRulesFromDir("../rules", root)
	if err != nil {
		b.Fatalf("Failed to load rules: %v", err)
	}

	// 1 secret per ~20 normal lines — closer to real MSSP data
	chunk := []byte(
		`{"log": "User alice logged in from 10.0.0.1", "level": "INFO"}` + "\n" +
			`{"log": "File /etc/config read successfully", "level": "DEBUG"}` + "\n" +
			`{"log": "Service restarted on port 8080", "level": "INFO"}` + "\n" +
			`{"log": "Health check passed", "level": "INFO"}` + "\n" +
			`{"log": "Request completed in 42ms", "level": "DEBUG"}` + "\n" +
			`{"log": "User bob logged out", "level": "INFO"}` + "\n" +
			`{"log": "Disk usage at 42%", "level": "INFO"}` + "\n" +
			`{"log": "Connection from 192.168.1.5 established", "level": "DEBUG"}` + "\n" +
			`{"log": "Cache miss for key user:1234", "level": "DEBUG"}` + "\n" +
			`{"log": "Scheduled job completed", "level": "INFO"}` + "\n" +
			`{"log": "Memory usage normal", "level": "INFO"}` + "\n" +
			`{"log": "API request to /health returned 200", "level": "DEBUG"}` + "\n" +
			`{"log": "User session expired", "level": "INFO"}` + "\n" +
			`{"log": "Config reload triggered", "level": "INFO"}` + "\n" +
			`{"log": "Thread pool size adjusted to 8", "level": "DEBUG"}` + "\n" +
			`{"log": "Backup completed successfully", "level": "INFO"}` + "\n" +
			`{"log": "Network latency 2ms", "level": "DEBUG"}` + "\n" +
			`{"log": "Queue depth 0", "level": "INFO"}` + "\n" +
			`{"log": "TLS handshake completed", "level": "DEBUG"}` + "\n" +
			`{"log": "psexec -u admin -p SuperSecret! cmd.exe", "level": "WARN"}` + "\n")

	var input bytes.Buffer
	for input.Len() < 1024*1024 {
		input.Write(chunk)
	}
	rawBytes := input.Bytes()

	b.ResetTimer()
	b.ReportAllocs()
	b.SetBytes(int64(len(rawBytes)))

	for i := 0; i < b.N; i++ {
		_ = ProcessStream(bytes.NewReader(rawBytes), io.Discard, root, true, 0)
	}
}
func BenchmarkOrchestrator_100MB_Realistic(b *testing.B) {
	root := NewTrie("********", 2, 0)
	err := LoadRulesFromDir("../rules", root)
	if err != nil {
		b.Fatalf("Failed to load rules: %v", err)
	}

	chunk := []byte(
		`{"log": "User alice logged in from 10.0.0.1", "level": "INFO"}` + "\n" +
			`{"log": "File /etc/config read successfully", "level": "DEBUG"}` + "\n" +
			`{"log": "Service restarted on port 8080", "level": "INFO"}` + "\n" +
			`{"log": "Health check passed", "level": "INFO"}` + "\n" +
			`{"log": "Request completed in 42ms", "level": "DEBUG"}` + "\n" +
			`{"log": "User bob logged out", "level": "INFO"}` + "\n" +
			`{"log": "Disk usage at 42%", "level": "INFO"}` + "\n" +
			`{"log": "Connection from 192.168.1.5 established", "level": "DEBUG"}` + "\n" +
			`{"log": "Cache miss for key user:1234", "level": "DEBUG"}` + "\n" +
			`{"log": "Scheduled job completed", "level": "INFO"}` + "\n" +
			`{"log": "Memory usage normal", "level": "INFO"}` + "\n" +
			`{"log": "API request to /health returned 200", "level": "DEBUG"}` + "\n" +
			`{"log": "User session expired", "level": "INFO"}` + "\n" +
			`{"log": "Config reload triggered", "level": "INFO"}` + "\n" +
			`{"log": "Thread pool size adjusted to 8", "level": "DEBUG"}` + "\n" +
			`{"log": "Backup completed successfully", "level": "INFO"}` + "\n" +
			`{"log": "Network latency 2ms", "level": "DEBUG"}` + "\n" +
			`{"log": "Queue depth 0", "level": "INFO"}` + "\n" +
			`{"log": "TLS handshake completed", "level": "DEBUG"}` + "\n" +
			`{"log": "psexec -u admin -p SuperSecret! cmd.exe", "level": "WARN"}` + "\n")

	var input bytes.Buffer
	for input.Len() < 100*1024*1024 {
		input.Write(chunk)
	}
	rawBytes := input.Bytes()

	b.ResetTimer()
	b.ReportAllocs()
	b.SetBytes(int64(len(rawBytes)))

	for i := 0; i < b.N; i++ {
		_ = ProcessStream(bytes.NewReader(rawBytes), io.Discard, root, true, 0)
	}
}

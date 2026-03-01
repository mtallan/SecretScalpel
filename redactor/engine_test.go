package redactor

import (
	"bytes"
	"encoding/json"
	"os"
	"testing"
)

type TestCase struct {
	ID       string `json:"id"`
	Input    string `json:"input"`
	Expected string `json:"expected"`
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

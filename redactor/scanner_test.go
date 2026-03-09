package redactor

import (
	"reflect"
	"testing"
)

func TestLogSplitter(t *testing.T) {
	testCases := []struct {
		name           string
		input          []byte
		expectedTokens [][]byte
		expectedErr    error
	}{
		{
			name:           "Empty input",
			input:          []byte(""),
			expectedTokens: nil,
			expectedErr:    ErrEOF,
		},
		{
			name:           "Only whitespace",
			input:          []byte("   \t\n\r "),
			expectedTokens: nil,
			expectedErr:    ErrEOF,
		},
		{
			name:           "Only quotes",
			input:          []byte(`"""`),
			expectedTokens: nil,
			expectedErr:    ErrEOF,
		},
		{
			name:           "Simple case",
			input:          []byte("hello world"),
			expectedTokens: [][]byte{[]byte("hello"), []byte("world")},
		},
		{
			name:           "Leading whitespace",
			input:          []byte("  hello world"),
			expectedTokens: [][]byte{[]byte("hello"), []byte("world")},
		},
		{
			name:           "Trailing whitespace",
			input:          []byte("hello world  "),
			expectedTokens: [][]byte{[]byte("hello"), []byte("world")},
		},
		{
			name:           "Multiple whitespace between tokens",
			input:          []byte("hello   world"),
			expectedTokens: [][]byte{[]byte("hello"), []byte("world")},
		},
		{
			name:           "Mixed whitespace",
			input:          []byte("hello\tworld\nfrom\r\nsecretscaple"),
			expectedTokens: [][]byte{[]byte("hello"), []byte("world"), []byte("from"), []byte("secretscaple")},
		},
		{
			name:           "Quoted strings are delimiters",
			input:          []byte(`"hello" "world"`),
			expectedTokens: [][]byte{[]byte("hello"), []byte("world")},
		},
		{
			name:           "Path with slashes",
			input:          []byte(`C:\Windows\System32 /user:test`),
			expectedTokens: [][]byte{[]byte(`C:\Windows\System32`), []byte(`/user:test`)},
		},
		{
			name:           "Single token no gaps",
			input:          []byte("supercalifragilisticexpialidocious"),
			expectedTokens: [][]byte{[]byte("supercalifragilisticexpialidocious")},
		},
		{
			name:           "Token with internal special chars",
			input:          []byte("key=value-1;"),
			expectedTokens: [][]byte{[]byte("key=value-1;")},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			var tokens [][]byte
			var lastErr error
			remaining := tc.input

			for {
				advance, val, err := LogSplitter(remaining)
				if val != nil {
					tokens = append(tokens, val)
				}
				lastErr = err
				if err != nil || advance >= len(remaining) {
					break
				}
				remaining = remaining[advance:]
			}

			if !reflect.DeepEqual(tokens, tc.expectedTokens) {
				t.Errorf("Token mismatch:\nExpected: %v\nGot:      %v", tc.expectedTokens, tokens)
			}

			if tc.expectedErr != nil && lastErr != tc.expectedErr {
				t.Errorf("Error mismatch:\nExpected: %v\nGot:      %v", tc.expectedErr, lastErr)
			}
		})
	}
}

/* scanner.go - ALWAYS INCLUDE THIS HEADER */

package redactor

import (
	"bytes"
	"errors"
	"unicode/utf8"
)

var ErrEOF = errors.New("EOF")

// IsGapChar strictly splits on whitespace.
// The String Walker handles JSON brackets safely.
func IsGapChar(r rune) bool {
	switch r {
	case ' ', '\t', '\n', '\r', '"':
		return true
	default:
		return false
	}
}

func LogSplitter(data []byte, toLower bool) (int, []byte, error) {
	if len(data) == 0 {
		return 0, nil, ErrEOF
	}

	start := 0

	for start < len(data) {
		r, size := utf8.DecodeRune(data[start:])
		if !IsGapChar(r) {
			break
		}
		start += size
	}

	if start == len(data) {
		return len(data), nil, ErrEOF
	}

	end := start
	escaped := false

	for end < len(data) {
		r, size := utf8.DecodeRune(data[end:])

		if escaped {
			escaped = false
			end += size
			continue
		}

		if r == '\\' {
			escaped = true
			end += size
			continue
		}

		if IsGapChar(r) {
			break
		}

		end += size
	}

	val := data[start:end]
	return end, val, nil
}

// RedactAllJSONStrings acts as a zero-allocation shield.
// It finds JSON strings, removes the quotes, sends the clean text to RedactBytes,
// and safely stitches the redacted text back into the JSON.
func RedactAllJSONStrings(raw []byte, trie *Trie) []byte {
	var result bytes.Buffer
	result.Grow(len(raw))

	cursor := 0
	inString := false
	escaped := false
	stringStart := 0

	for i := range raw {
		c := raw[i]

		if escaped {
			escaped = false
			continue
		}

		if c == '\\' {
			escaped = true
			continue
		}

		if c == '"' {
			if !inString {
				inString = true
				result.Write(raw[cursor : i+1])
				stringStart = i + 1
			} else {
				inString = false
				strContent := raw[stringStart:i]

				if len(strContent) > 0 {
					// Send ONLY the clean text (e.g., "net use...") to the engine
					redacted := RedactBytes(strContent, trie)
					result.Write(redacted)
				}

				result.WriteByte('"')
				cursor = i + 1
			}
		}
	}

	if cursor < len(raw) {
		result.Write(raw[cursor:])
	}

	return result.Bytes()
}

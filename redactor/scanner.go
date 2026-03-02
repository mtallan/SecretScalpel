/* scanner.go */
package redactor

import (
	"bytes"
	"errors"
)

var ErrEOF = errors.New("EOF")

// IsGapChar strictly splits on whitespace and quotes using raw bytes.
func IsGapChar(c byte) bool {
	switch c {
	case ' ', '\t', '\n', '\r', '"':
		return true
	default:
		return false
	}
}

// LogSplitter now runs entirely on raw bytes. No rune decoding.
func LogSplitter(data []byte, toLower bool) (int, []byte, error) {
	if len(data) == 0 {
		return 0, nil, ErrEOF
	}

	start := 0
	for start < len(data) {
		if !IsGapChar(data[start]) {
			break
		}
		start++
	}

	if start == len(data) {
		return len(data), nil, ErrEOF
	}

	end := start
	escaped := false

	for end < len(data) {
		c := data[end]

		if escaped {
			escaped = false
			end++
			continue
		}

		if c == '\\' {
			escaped = true
			end++
			continue
		}

		if IsGapChar(c) {
			break
		}

		end++
	}

	val := data[start:end]
	return end, val, nil
}

func RedactAllJSONStrings(raw []byte, trie *Trie) []byte {
	var result bytes.Buffer
	result.Grow(len(raw))

	cursor := 0
	inString := false
	escaped := false
	stringStart := 0

	for i := 0; i < len(raw); i++ {
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

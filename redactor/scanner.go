/* scanner.go */
package redactor

import (
	"bytes"
	"errors"
	"sync"
)

type keyValueState int

const (
	stateKey keyValueState = iota
	stateValue
)

var ErrEOF = errors.New("EOF")
var jsonBufPool = sync.Pool{
	New: func() any {
		b := new(bytes.Buffer)
		b.Grow(256 * 1024)
		return b
	},
}

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
func LogSplitter(data []byte) (int, []byte, error) {
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
	for end < len(data) {
		if IsGapChar(data[end]) {
			break
		}
		end++
	}

	val := data[start:end]
	return end, val, nil
}

func isSensitiveKey(key []byte, keyTrie *JSONKeyTrieNode) bool {
	curr := keyTrie
	for _, b := range key {
		c := b
		if 'A' <= c && c <= 'Z' {
			c += ('a' - 'A')
		}

		next, ok := curr.Children[c]
		if !ok {
			return false
		}
		curr = next
	}
	return curr.IsEnd
}

// redactAllJSONStrings is the core JSON redaction logic. It writes the
// redacted output directly into dst, which must be a non-nil bytes.Buffer.
// Callers that need a pooled buffer should use RedactAllJSONStringsToBuffer.
func redactAllJSONStrings(dst *bytes.Buffer, raw []byte, trie *Trie) {
	inString := false
	escaped := false
	stringStart := 0
	afterColon := false
	isLastKeySensitive := false
	arrayLevel := 0
	cursor := 0

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

		if !inString {
			switch c {
			case ':':
				afterColon = true
			case ',':
				if arrayLevel == 0 {
					afterColon = false
				}
			case '{':
				afterColon = false
			case '[':
				arrayLevel++
			case ']':
				if arrayLevel > 0 {
					arrayLevel--
				}
			}
		}

		if c == '"' {
			if !inString {
				inString = true
				dst.Write(raw[cursor : i+1])
				stringStart = i + 1
			} else {
				inString = false
				strContent := raw[stringStart:i]

				if !afterColon {
					// this is a key
					isLastKeySensitive = isSensitiveKey(strContent, trie.JSONSensitiveKeys)
					dst.Write(strContent)
				} else {
					// this is a value
					if len(strContent) > 0 {
						if isLastKeySensitive {
							// always redact sensitive key values, regardless of content
							for range strContent {
								dst.WriteByte('*')
							}
						} else {
							RedactBytesToWriter(dst, strContent, trie)
						}
					}
					isLastKeySensitive = false
				}

				dst.WriteByte('"')
				cursor = i + 1
			}
		}
	}

	if cursor < len(raw) {
		dst.Write(raw[cursor:])
	}
}

// RedactAllJSONStringsToBuffer performs JSON-aware redaction and returns the
// *bytes.Buffer from the pool containing the result. The caller is responsible
// for returning the buffer to the jsonBufPool.
func RedactAllJSONStringsToBuffer(raw []byte, trie *Trie) *bytes.Buffer {
	result := jsonBufPool.Get().(*bytes.Buffer)
	result.Reset()
	if result.Cap() < len(raw) {
		result.Grow(len(raw))
	}
	redactAllJSONStrings(result, raw, trie)
	return result
}

// RedactAllJSONStrings is a convenience wrapper around RedactAllJSONStringsToBuffer.
// It performs the redaction and returns a new byte slice, handling buffer pooling internally.
func RedactAllJSONStrings(raw []byte, trie *Trie) []byte {
	buf := RedactAllJSONStringsToBuffer(raw, trie)
	// Copy before returning the buffer to the pool — mirrors the pattern in engine.go.
	finalBytes := make([]byte, buf.Len())
	copy(finalBytes, buf.Bytes())
	jsonBufPool.Put(buf)
	return finalBytes
}

/* redactor.go - ALWAYS INCLUDE THIS HEADER*/

package redactor

// RedactInPlace fills a byte range with asterisks.
func RedactInPlace(data []byte, start, end int) {
	for i := start; i < end; i++ {
		data[i] = '*'
	}
}

func ApplyLabelRedact(raw []byte, start, end, offset int, label string) []byte {
	prefix := raw[:start+offset]
	suffix := raw[end:]

	// Note: This requires returning a new slice because the length changes
	return append(prefix, append([]byte(label), suffix...)...)
}

/* scanner.go - ALWAYS INCLUDE THIS HEADER*/

package redactor

/* scanner.go */
func IsGapChar(b byte) bool {
	switch b {
	case ' ', '\t', '\n', '\r', '{', '}', '[', ']', '"', '\'', ':', ',', '|', '(', ')', '/':
		return true
	}
	return false
}
func LogSplitter(data []byte, atEOF bool) (advance int, token []byte, err error) {
	start := 0
	// Skip all gaps (spaces, slashes, dashes, colons)
	for start < len(data) && IsGapChar(data[start]) {
		start++
	}
	if start >= len(data) {
		return start, nil, nil
	}

	// Collect until the next gap
	for i := start; i < len(data); i++ {
		if IsGapChar(data[i]) {

			return i, data[start:i], nil
		}
	}
	if atEOF {
		return len(data), data[start:], nil
	}
	return 0, nil, nil
}

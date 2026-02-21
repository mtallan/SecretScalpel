/* engine.go - REFINED FOR PRODUCTION & DEBUGGING */

package redactor

import (
	"bytes"
	"fmt"
)

func RedactBytes(raw []byte, root *TrieNode) {
	// 1. Setup Window and History
	// We add buffer room to ensure the sliding window covers MaxDepth
	windowSize := root.MaxDepth + 2
	history := make([][]byte, windowSize)
	posHistory := make([]TokenPos, windowSize)

	cursor := 0
	count := 0
	currentPos := 0
	lastRedactedByte := -1

	// 2. Manual Scanner Loop
	remaining := raw
	for {
		advance, val, err := LogSplitter(remaining, true)
		if advance == 0 || err != nil {
			break
		}

		// Calculate precise start/end in the original raw slice
		tokenStart := currentPos + (advance - len(val))
		tokenEnd := currentPos + advance

		// --- SYSTEM DEBUG: View exact tokenization ---
		//fmt.Printf("DEBUG: Tokenized [%s] at Range[%d:%d]\n", string(val), tokenStart, tokenEnd)

		// 3. Update History Ring Buffer
		idx := cursor % windowSize
		history[idx] = bytes.ToLower(val)
		posHistory[idx] = TokenPos{Start: tokenStart, End: tokenEnd}

		currentPos += advance
		remaining = remaining[advance:]
		cursor++
		if count < windowSize {
			count++
		}

		// 4. Trie Matching Logic (Sliding Window)
		// We look back through our history to see if the current sequence matches a rule
		for i := 0; i < count; i++ {
			curr := root
			for j := i; j < count; j++ {
				ringIdx := (cursor - count + j) % windowSize
				word := string(history[ringIdx])

				// Match literal word or wildcard
				next, ok := curr.Children[word]
				if !ok {
					// Check for prefix wildcard (e.g., "-p*" matches "-pPassword")
					// This is crucial for Linux/Windows attached flags
					foundPrefix := false
					for pattern, node := range curr.Children {
						if len(pattern) > 1 && pattern[len(pattern)-1] == '*' {
							prefix := pattern[:len(pattern)-1]
							if bytes.HasPrefix(history[ringIdx], []byte(prefix)) {
								next = node
								foundPrefix = true
								break
							}
						}
					}

					// Fallback to pure wildcard if no prefix match
					if !foundPrefix {
						next, ok = curr.Children["*"]
					} else {
						ok = true
					}
				}

				if ok {
					curr = next
					if curr.IsTerminal {
						// 5. Match Found! Calculate redaction target
						// ONLY trigger if this is the end of the window we just added
						if curr.IsTerminal && j == count-1 {
							fmt.Printf("  [!] TRIE HIT: Rule [%s] identified sequence ending at [%s]\n", curr.ID, word)
							// ... redaction logic ...
						}

						targetIdx := j + curr.Skip
						if targetIdx >= 0 && targetIdx < count {
							tRingIdx := (cursor - count + targetIdx) % windowSize
							p := posHistory[tRingIdx]

							// Apply RedactOffset (handles cases like -pPassword -> -p********)
							startPos := p.Start + curr.RedactOffset

							if startPos < p.End && startPos > lastRedactedByte {
								fmt.Printf("      -> REDACTING: Bytes %d to %d\n", startPos, p.End)
								for k := startPos; k < p.End; k++ {
									raw[k] = '*'
								}
								lastRedactedByte = p.End
							}
						}
					}
				} else {
					// Path broken, move to next history starting point
					break
				}
			}
		}
	}
}

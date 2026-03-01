package redactor

import (
	"bytes"
	"sort"
	"strings"
)

type Token struct {
	Word  string
	Start int
	End   int
}

type RedactionTarget struct {
	start  int
	end    int
	mask   string
	offset int
}

type pendingRedaction struct {
	matchStart int
	matchEnd   int
	priority   int
	targets    []RedactionTarget
}

func RedactBytes(raw []byte, trie *Trie) []byte {
	if trie == nil || trie.Root == nil || len(raw) == 0 {
		return raw
	}

	var toRedact []pendingRedaction

	// =========================================================
	// PHASE 0: Global Regex Scanning (Capture Group Aware)
	// =========================================================
	for _, rr := range trie.RegexRules {
		matches := rr.Re.FindAllSubmatchIndex(raw, -1)
		for _, match := range matches {
			start, end := match[0], match[1]
			// If capture group 1 exists, redact ONLY that group
			if len(match) >= 4 && match[2] != -1 {
				start = match[2]
				end = match[3]
			}

			toRedact = append(toRedact, pendingRedaction{
				matchStart: start,
				matchEnd:   end,
				priority:   rr.Priority,
				targets: []RedactionTarget{{
					start: start, end: end, mask: rr.Mask, offset: rr.Offset,
				}},
			})
		}
	}

	// =========================================================
	// PHASE 1: Sliding Window Trie Matching
	// =========================================================
	var window []Token
	windowSize := trie.MaxDepth + 1
	currentPos, remaining := 0, raw

	for {
		advance, val, err := LogSplitter(remaining, true)
		if advance == 0 || err != nil {
			break
		}

		sPos := currentPos + (advance - len(val))
		ePos := currentPos + advance
		window = append(window, Token{Word: strings.ToLower(string(val)), Start: sPos, End: ePos})
		if len(window) > windowSize {
			window = window[1:]
		}

		for i := 0; i < len(window); i++ {
			curr := trie.Root
			for j := i; j < len(window); j++ {
				word := window[j].Word

				// Priority: Literal -> Regex Edge -> Wildcard (*)
				next, ok := curr.Children[word]
				if !ok {
					for _, edge := range curr.RegexChildren {
						if edge.Re.MatchString(word) {
							next = edge.Node
							ok = true
							break
						}
					}
				}
				if !ok {
					next, ok = curr.Children["*"]
				}

				if ok {
					curr = next
					if curr.Meta != nil {
						var targets []RedactionTarget
						for _, relIdx := range curr.Meta.RedactIndices {
							tIdx := i + relIdx
							if tIdx < len(window) {
								targets = append(targets, RedactionTarget{
									start:  window[tIdx].Start,
									end:    window[tIdx].End,
									mask:   curr.Meta.CustomMask,
									offset: curr.Meta.Offset,
								})
							}
						}
						if len(targets) > 0 {
							toRedact = append(toRedact, pendingRedaction{
								matchStart: window[i].Start,
								matchEnd:   window[j].End,
								priority:   curr.Meta.Priority,
								targets:    targets,
							})
						}
					}
				} else {
					break
				}
			}
		}
		currentPos += advance
		remaining = remaining[advance:]
	}

	if len(toRedact) == 0 {
		return raw
	}

	// =========================================================
	// PHASE 2: Reconstruction (Priority Pre-emption)
	// =========================================================

	// Sort to process highest priority (lowest number) first.
	// This ensures Priority 1 rules get "first dibs" on claiming bytes.
	sort.Slice(toRedact, func(i, j int) bool {
		if toRedact[i].priority != toRedact[j].priority {
			return toRedact[i].priority < toRedact[j].priority
		}
		lenI := toRedact[i].matchEnd - toRedact[i].matchStart
		lenJ := toRedact[j].matchEnd - toRedact[j].matchStart
		return lenI > lenJ
	})

	claimed := make([]bool, len(raw))
	type finalInt struct {
		start int
		end   int
		mask  string
	}
	var resolved []finalInt

	// 2. Claim Bytes
	for _, r := range toRedact {
		overlap := false
		// If ANY byte is already claimed by a better rule, abort.
		for k := r.matchStart; k < r.matchEnd; k++ {
			if claimed[k] {
				overlap = true
				break
			}
		}
		if overlap {
			continue
		}

		// Lock down these bytes for this winning rule
		for k := r.matchStart; k < r.matchEnd; k++ {
			claimed[k] = true
		}

		for _, t := range r.targets {
			actualStart := t.start + t.offset
			if actualStart < 0 || actualStart >= t.end {
				continue
			}

			maskStr := t.mask
			if maskStr == "" || maskStr == "*" {
				maskStr = string(bytes.Repeat([]byte("*"), t.end-actualStart))
			}
			resolved = append(resolved, finalInt{start: actualStart, end: t.end, mask: maskStr})
		}
	}

	// 3. Sequential Write
	sort.Slice(resolved, func(i, j int) bool {
		return resolved[i].start < resolved[j].start
	})

	var filtered []finalInt
	if len(resolved) > 0 {
		filtered = append(filtered, resolved[0])
		for i := 1; i < len(resolved); i++ {
			last := &filtered[len(filtered)-1]
			if resolved[i].start < last.end {
				continue
			}
			filtered = append(filtered, resolved[i])
		}
	}

	var result bytes.Buffer
	result.Grow(len(raw))
	writePos := 0
	for _, interval := range filtered {
		if writePos < interval.start {
			result.Write(raw[writePos:interval.start])
		}
		result.WriteString(interval.mask)
		writePos = interval.end
	}
	if writePos < len(raw) {
		result.Write(raw[writePos:])
	}

	return result.Bytes()
}

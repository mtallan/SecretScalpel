package redactor

import (
	"bytes"
	"sort"
	"strings"
	"sync"
)

var globalStars = bytes.Repeat([]byte("*"), 2048)

type Token struct {
	Start int
	End   int
}

type RedactionTarget struct {
	start       int
	end         int
	mask        string
	offset      int
	redactAfter string
}

type pendingRedaction struct {
	matchStart int
	matchEnd   int
	priority   int
	targets    []RedactionTarget
}

type interval struct{ start, end int }

type finalInt struct {
	start int
	end   int
	maskB []byte
	maskS string
}

// EngineWorkspace holds all the reusable slices and buffers for a single redaction pass.
type EngineWorkspace struct {
	toRedact []pendingRedaction
	claimed  []interval
	resolved []finalInt
	outBuf   bytes.Buffer
}

// workspacePool allows 24 concurrent workers to recycle memory instead of allocating.
var workspacePool = sync.Pool{
	New: func() any {
		return &EngineWorkspace{
			toRedact: make([]pendingRedaction, 0, 64),
			claimed:  make([]interval, 0, 64),
			resolved: make([]finalInt, 0, 64),
		}
	},
}

type byPriority []pendingRedaction

func (b byPriority) Len() int      { return len(b) }
func (b byPriority) Swap(i, j int) { b[i], b[j] = b[j], b[i] }
func (b byPriority) Less(i, j int) bool {
	if b[i].priority != b[j].priority {
		return b[i].priority < b[j].priority
	}
	return (b[i].matchEnd - b[i].matchStart) > (b[j].matchEnd - b[j].matchStart)
}

type byStart []finalInt

func (b byStart) Len() int           { return len(b) }
func (b byStart) Swap(i, j int)      { b[i], b[j] = b[j], b[i] }
func (b byStart) Less(i, j int) bool { return b[i].start < b[j].start }

func RedactBytes(raw []byte, trie *Trie) []byte {
	if trie == nil || trie.Root == nil || len(raw) == 0 {
		return raw
	}

	// =========================================================
	// PHASE 0: Global Regex Scanning (Fast-Path Guarded)
	// =========================================================
	hasRegexTrigger := false
	for i := 0; i < len(raw); i++ {
		c := raw[i]
		if c == '@' || c == '=' || c == ':' || c == '/' || c == '-' {
			hasRegexTrigger = true
			break
		}
	}

	// Check out a recycled workspace
	ws := workspacePool.Get().(*EngineWorkspace)

	// Reset the slices without shrinking their capacity
	ws.toRedact = ws.toRedact[:0]
	ws.claimed = ws.claimed[:0]
	ws.resolved = ws.resolved[:0]
	ws.outBuf.Reset()

	if hasRegexTrigger {
		for _, rr := range trie.RegexRules {
			if !rr.Re.Match(raw) {
				continue
			}
			matches := rr.Re.FindAllSubmatchIndex(raw, -1)
			for _, match := range matches {
				start, end := match[0], match[1]
				for i := 2; i < len(match); i += 2 {
					if match[i] != -1 {
						start = match[i]
						end = match[i+1]
					}
				}
				ws.toRedact = append(ws.toRedact, pendingRedaction{
					matchStart: start,
					matchEnd:   end,
					priority:   rr.Priority,
					targets: []RedactionTarget{{
						start: start, end: end, mask: rr.Mask, offset: rr.Offset, redactAfter: rr.RedactAfter,
					}},
				})
			}
		}
	}

	// =========================================================
	// PHASE 1: Tokenization & Sliding Window (Stack Allocated)
	// =========================================================
	var stackTokens [256]Token
	tokens := stackTokens[:0]
	currentPos := 0
	remaining := raw

	for {
		advance, val, err := LogSplitter(remaining, true)
		if advance == 0 || err != nil {
			break
		}
		sPos := currentPos + (advance - len(val))
		ePos := currentPos + advance
		tokens = append(tokens, Token{Start: sPos, End: ePos})
		currentPos += advance
		remaining = remaining[advance:]
	}

	windowSize := trie.MaxDepth + 1
	var scratch [256]byte

	for i := 0; i < len(tokens); i++ {
		curr := trie.Root
		for j := i; j < len(tokens) && j < i+windowSize; j++ {
			tok := tokens[j]
			wordRaw := raw[tok.Start:tok.End]

			n := len(wordRaw)
			if n > 256 {
				n = 256
			}
			for k := 0; k < n; k++ {
				c := wordRaw[k]
				if c >= 'A' && c <= 'Z' {
					scratch[k] = c + 32
				} else {
					scratch[k] = c
				}
			}

			next, ok := curr.Children[string(scratch[:n])]
			if !ok {
				for _, edge := range curr.RegexChildren {
					if edge.Re.Match(wordRaw) {
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
						if tIdx < len(tokens) {
							targets = append(targets, RedactionTarget{
								start:       tokens[tIdx].Start,
								end:         tokens[tIdx].End,
								mask:        curr.Meta.CustomMask,
								offset:      curr.Meta.Offset,
								redactAfter: curr.Meta.RedactAfter,
							})
						}
					}
					if len(targets) > 0 {
						ws.toRedact = append(ws.toRedact, pendingRedaction{
							matchStart: tokens[i].Start,
							matchEnd:   tokens[j].End,
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

	if len(ws.toRedact) == 0 {
		workspacePool.Put(ws)
		return raw
	}

	// =========================================================
	// PHASE 2: Reconstruction & Overlap Protection
	// =========================================================
	sort.Sort(byPriority(ws.toRedact))

	for _, r := range ws.toRedact {
		overlap := false
		for _, c := range ws.claimed {
			if r.matchStart < c.end && r.matchEnd > c.start {
				overlap = true
				break
			}
		}
		if overlap {
			continue
		}

		ws.claimed = append(ws.claimed, interval{r.matchStart, r.matchEnd})

		for _, t := range r.targets {
			// Compute actualStart: prefer redactAfter (dynamic) over offset (legacy).
			// redactAfter searches for the literal prefix inside the token and skips past it,
			// so the offset is always correct regardless of the prefix length.
			actualStart := t.start
			if t.redactAfter != "" {
				tokenStr := string(raw[t.start:t.end])
				idx := strings.Index(strings.ToLower(tokenStr), strings.ToLower(t.redactAfter))
				if idx == -1 {
					// Delimiter not found in token — skip this target rather than redacting wrong bytes
					continue
				}
				actualStart = t.start + idx + len(t.redactAfter)
			} else {
				actualStart = t.start + t.offset
			}

			if actualStart < 0 || actualStart >= t.end {
				continue
			}

			maskStr := t.mask
			if maskStr == "" {
				maskStr = trie.GlobalMask
			}

			if maskStr == "*" {
				maskLen := t.end - actualStart
				if maskLen < 0 {
					maskLen = 0
				}
				if maskLen > len(globalStars) {
					maskLen = len(globalStars)
				}
				ws.resolved = append(ws.resolved, finalInt{start: actualStart, end: t.end, maskB: globalStars[:maskLen]})
			} else {
				ws.resolved = append(ws.resolved, finalInt{start: actualStart, end: t.end, maskS: maskStr})
			}
		}
	}

	sort.Sort(byStart(ws.resolved))

	var filtered []finalInt
	if len(ws.resolved) > 0 {
		filtered = append(filtered, ws.resolved[0])
		for i := 1; i < len(ws.resolved); i++ {
			last := &filtered[len(filtered)-1]
			if ws.resolved[i].start < last.end {
				continue
			}
			filtered = append(filtered, ws.resolved[i])
		}
	}

	ws.outBuf.Grow(len(raw))
	writePos := 0
	for _, inv := range filtered {
		if writePos < inv.start {
			ws.outBuf.Write(raw[writePos:inv.start])
		}
		if inv.maskB != nil {
			ws.outBuf.Write(inv.maskB)
		} else {
			ws.outBuf.WriteString(inv.maskS)
		}
		writePos = inv.end
	}
	if writePos < len(raw) {
		ws.outBuf.Write(raw[writePos:])
	}

	// We MUST copy the bytes before putting the workspace back in the pool
	// otherwise the next thread will overwrite our output!
	finalBytes := make([]byte, ws.outBuf.Len())
	copy(finalBytes, ws.outBuf.Bytes())

	workspacePool.Put(ws)
	return finalBytes
}

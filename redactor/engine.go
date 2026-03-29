package redactor

import (
	"bytes"
	"io"
	"sort"
	"sync"
)

var globalStars = bytes.Repeat([]byte("*"), 2048)

type Token struct {
	Start int
	End   int
}

type RedactionTarget struct {
	start            int
	end              int
	mask             string
	redactAfter      string
	redactAfterBytes []byte
}

type pendingRedaction struct {
	matchStart int
	matchEnd   int
	priority   int
	targets    []RedactionTarget
	minLength  int
	maxLength  int
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
	toRedact    []pendingRedaction
	claimed     []interval
	resolved    []finalInt
	filtered    []finalInt
	targets     []RedactionTarget
	tokens      []Token
	activeNodes []*TrieNode
	nextNodes   []*TrieNode
	outBuf      bytes.Buffer
}

// workspacePool allows 24 concurrent workers to recycle memory instead of allocating.
var workspacePool = sync.Pool{
	New: func() any {
		return &EngineWorkspace{
			toRedact:    make([]pendingRedaction, 0, 512),
			claimed:     make([]interval, 0, 128),
			resolved:    make([]finalInt, 0, 128),
			filtered:    make([]finalInt, 0, 128),
			targets:     make([]RedactionTarget, 0, 512),
			tokens:      make([]Token, 0, 8192),
			activeNodes: make([]*TrieNode, 0, 16),
			nextNodes:   make([]*TrieNode, 0, 16),
		}
	},
}

// bytesIndexCaseInsensitive performs a case-insensitive search for `sep` in `s`.
// It is a byte-slice equivalent of strings.Index(strings.ToLower(s), strings.ToLower(sep)).
func bytesIndexCaseInsensitive(s, sep []byte) int {
	n, m := len(s), len(sep)
	if m == 0 {
		return 0
	}
	if n < m {
		return -1
	}
	for i := 0; i <= n-m; i++ {
		if bytes.EqualFold(s[i:i+m], sep) {
			return i
		}
	}
	return -1
}

// RedactBytesToWriter runs the full redaction pipeline on raw and writes the result to w.
func RedactBytesToWriter(w io.Writer, raw []byte, trie *Trie) {
	if trie == nil || trie.Root == nil || len(raw) == 0 {
		w.Write(raw)
		return
	}

	// =========================================================
	// PHASE 0: Global Regex Scanning (Fast-Path Guarded)
	// =========================================================
	hasRegexTrigger := false
	for i := range raw {
		c := raw[i]
		if c == '@' || c == '=' || c == ':' || c == '/' || c == '-' {
			hasRegexTrigger = true
			break
		}
	}

	// Check out a recycled workspace
	ws := workspacePool.Get().(*EngineWorkspace)

	// Reset the slices without shrinking their capacity
	ws.toRedact    = ws.toRedact[:0]
	ws.claimed     = ws.claimed[:0]
	ws.resolved    = ws.resolved[:0]
	ws.filtered    = ws.filtered[:0]
	ws.targets     = ws.targets[:0]
	ws.tokens      = ws.tokens[:0]
	ws.activeNodes = ws.activeNodes[:0]
	ws.nextNodes   = ws.nextNodes[:0]
	// ws.outBuf is not used in this function.

	if hasRegexTrigger {
		for _, rr := range trie.RegexRules {
			if rr.RequiredByte != 0 && bytes.IndexByte(raw, rr.RequiredByte) < 0 {
				continue
			}
			for _, match := range rr.Re.FindAllSubmatchIndex(raw, -1) {
				start, end := match[0], match[1]
				for i := 2; i < len(match); i += 2 {
					if match[i] != -1 {
						start = match[i]
						end = match[i+1]
					}
				}
				targetsStart := len(ws.targets)
				regexMask := rr.Mask
				if trie.DebugRules {
					regexMask = "[" + rr.ID + "]"
				}
				ws.targets = append(ws.targets, RedactionTarget{
					start: start, end: end, mask: regexMask, redactAfter: rr.RedactAfter, redactAfterBytes: rr.RedactAfterBytes,
				})
				ws.toRedact = append(ws.toRedact, pendingRedaction{
					matchStart: start,
					matchEnd:   end,
					priority:   rr.Priority,
					targets:    ws.targets[targetsStart:],
					minLength:  rr.MinLength,
					maxLength:  rr.MaxLength,
				})
			}
		}
	}

	// =========================================================
	// PHASE 1: Tokenization & Sliding Window (Stack Allocated)
	// =========================================================
	currentPos := 0
	remaining := raw

	for {
		advance, val, err := LogSplitter(remaining)
		if advance == 0 || err != nil {
			break
		}
		sPos := currentPos + (advance - len(val))
		ePos := currentPos + advance
		ws.tokens = append(ws.tokens, Token{Start: sPos, End: ePos})
		currentPos += advance
		remaining = remaining[advance:]
	}

	windowSize := trie.MaxDepth + 1
	var scratch [256]byte

	for i := 0; i < len(ws.tokens); i++ {
		ws.activeNodes = append(ws.activeNodes[:0], trie.Root)

		for j := i; j < len(ws.tokens) && j < i+windowSize; j++ {
			tok := ws.tokens[j]
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

			// Fan out to every branch that matches this token: literal, all matching
			// regex edges, and wildcard. This prevents a regex edge from silently
			// shadowing a wildcard rule at the same trie position.
			ws.nextNodes = ws.nextNodes[:0]
			for _, curr := range ws.activeNodes {
				// The Go compiler optimizes `m[string(b)]` to avoid allocation when
				// looking up a byte slice key in a map[string]T.
				if next, ok := curr.Children[string(scratch[:n])]; ok {
					ws.nextNodes = append(ws.nextNodes, next)
				}
				for _, edge := range curr.RegexChildren {
					if edge.Re.Match(wordRaw) {
						ws.nextNodes = append(ws.nextNodes, edge.Node)
					}
				}
				if next, ok := curr.Children["*"]; ok {
					ws.nextNodes = append(ws.nextNodes, next)
				}
			}

			if len(ws.nextNodes) == 0 {
				break
			}
			ws.activeNodes, ws.nextNodes = ws.nextNodes, ws.activeNodes

			for _, node := range ws.activeNodes {
				if node.Meta != nil {
					targetsStart := len(ws.targets)
					for _, relIdx := range node.Meta.RedactIndices {
						tIdx := i + relIdx
						if tIdx < len(ws.tokens) {
							trieMask := node.Meta.CustomMask
							if trie.DebugRules {
								trieMask = "[" + node.Meta.ID + "]"
							}
							ws.targets = append(ws.targets, RedactionTarget{
								start:            ws.tokens[tIdx].Start,
								end:              ws.tokens[tIdx].End,
								mask:             trieMask,
								redactAfter:      node.Meta.RedactAfter,
								redactAfterBytes: node.Meta.RedactAfterBytes,
							})
						}
					}
					if len(ws.targets) > targetsStart {
						ws.toRedact = append(ws.toRedact, pendingRedaction{
							matchStart: ws.tokens[i].Start,
							matchEnd:   ws.tokens[j].End,
							priority:   node.Meta.Priority,
							targets:    ws.targets[targetsStart:],
							minLength:  node.Meta.MinLength,
							maxLength:  node.Meta.MaxLength,
						})
					}
				}
			}
		}
	}

	if len(ws.toRedact) == 0 {
		w.Write(raw)
		workspacePool.Put(ws)
		return
	}

	// =========================================================
	// PHASE 2: Reconstruction & Overlap Protection
	// =========================================================
	sort.Slice(ws.toRedact, func(i, j int) bool {
		a, b := ws.toRedact[i], ws.toRedact[j]
		if a.priority != b.priority {
			return a.priority < b.priority
		}
		// If priorities are equal, the longer match wins.
		return (a.matchEnd - a.matchStart) > (b.matchEnd - b.matchStart)
	})

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
			actualStart := t.start
			if len(t.redactAfterBytes) > 0 {
				tokenSlice := raw[t.start:t.end]
				idx := bytesIndexCaseInsensitive(tokenSlice, t.redactAfterBytes)
				if idx == -1 {
					continue
				}
				actualStart = t.start + idx + len(t.redactAfterBytes)
			}

			secretLen := t.end - actualStart
			if secretLen < 0 {
				secretLen = 0
			}
			if r.minLength > 0 && secretLen < r.minLength {
				continue
			}
			if r.maxLength > 0 && secretLen > r.maxLength {
				continue
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

	sort.Slice(ws.resolved, func(i, j int) bool {
		return ws.resolved[i].start < ws.resolved[j].start
	})

	if len(ws.resolved) > 0 {
		ws.filtered = append(ws.filtered, ws.resolved[0])
		for i := 1; i < len(ws.resolved); i++ {
			last := &ws.filtered[len(ws.filtered)-1]
			if ws.resolved[i].start < last.end {
				continue
			}
			ws.filtered = append(ws.filtered, ws.resolved[i])
		}
	}

	writePos := 0
	for _, inv := range ws.filtered {
		if writePos < inv.start {
			w.Write(raw[writePos:inv.start])
		}
		if inv.maskB != nil {
			w.Write(inv.maskB)
		} else {
			io.WriteString(w, inv.maskS)
		}
		writePos = inv.end
	}
	if writePos < len(raw) {
		w.Write(raw[writePos:])
	}

	workspacePool.Put(ws)
}

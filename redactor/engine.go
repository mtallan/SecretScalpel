package redactor

import (
	"bytes"
	"cmp"
	"io"
	"slices"
	"sync"
	"sync/atomic"
)

var globalStars = bytes.Repeat([]byte("*"), 2048)

type Token struct {
	Start          int
	End            int
	LowercaseStart int // byte offset into EngineWorkspace.lcBuf
}

type RedactionTarget struct {
	start            int
	end              int
	mask             string
	redactAfter      string
	redactAfterBytes []byte
}

type pendingRedaction struct {
	matchStart  int
	matchEnd    int
	priority    int
	targetStart int // index into ws.targets
	targetEnd   int // index into ws.targets
	minLength   int
	maxLength   int
	hits        *atomic.Int64 // nil-safe; points to the originating rule's counter
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
	lcBuf       []byte // flat buffer of lowercased token bytes, indexed by Token.LowercaseStart
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
			lcBuf:       make([]byte, 0, 64*1024),
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
	trie.bytesIn.Add(int64(len(raw)))

	// =========================================================
	// PHASE 0: Global Regex Scanning (Fast-Path Guarded)
	// =========================================================
	hasRegexTrigger := bytes.ContainsAny(raw, "@=:/-")

	// Check out a recycled workspace
	ws := workspacePool.Get().(*EngineWorkspace)

	// Reset the slices without shrinking their capacity
	ws.toRedact = ws.toRedact[:0]
	ws.claimed = ws.claimed[:0]
	ws.resolved = ws.resolved[:0]
	ws.filtered = ws.filtered[:0]
	ws.targets = ws.targets[:0]
	ws.tokens = ws.tokens[:0]
	ws.activeNodes = ws.activeNodes[:0]
	ws.nextNodes = ws.nextNodes[:0]
	ws.lcBuf = ws.lcBuf[:0]
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
					matchStart:  start,
					matchEnd:    end,
					priority:    rr.Priority,
					targetStart: targetsStart,
					targetEnd:   len(ws.targets),
					minLength:   rr.MinLength,
					maxLength:   rr.MaxLength,
					hits:        rr.Hits,
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
		n := min(len(val), 256)
		lcStart := len(ws.lcBuf)
		for k := range n {
			c := val[k]
			if c >= 'A' && c <= 'Z' {
				ws.lcBuf = append(ws.lcBuf, c+32)
			} else {
				ws.lcBuf = append(ws.lcBuf, c)
			}
		}
		ws.tokens = append(ws.tokens, Token{Start: sPos, End: ePos, LowercaseStart: lcStart})
		currentPos += advance
		remaining = remaining[advance:]
	}

	windowSize := trie.MaxDepth + 1

	for i := 0; i < len(ws.tokens); i++ {
		tok0 := ws.tokens[i]
		// First-byte fast reject: skip if no trie path can start with this token.
		if trie.Root.WildcardChild == nil && !trie.Root.HasRegexChildren {
			lcLen0 := min(tok0.End-tok0.Start, 256)
			if lcLen0 == 0 || !trie.Root.FirstByteSet[ws.lcBuf[tok0.LowercaseStart]] {
				continue
			}
		}

		ws.activeNodes = append(ws.activeNodes[:0], trie.Root)

		for j := i; j < len(ws.tokens) && j < i+windowSize; j++ {
			tok := ws.tokens[j]
			wordRaw := raw[tok.Start:tok.End]
			lcLen := min(tok.End-tok.Start, 256)
			lcWord := ws.lcBuf[tok.LowercaseStart : tok.LowercaseStart+lcLen]

			// Fan out to every branch that matches this token: literal, all matching
			// regex edges, and wildcard. This prevents a regex edge from silently
			// shadowing a wildcard rule at the same trie position.
			ws.nextNodes = ws.nextNodes[:0]
			for _, curr := range ws.activeNodes {
				// The Go compiler optimizes `m[string(b)]` to avoid allocation when
				// looking up a byte slice key in a map[string]T.
				if next, ok := curr.Children[string(lcWord)]; ok {
					ws.nextNodes = append(ws.nextNodes, next)
				}
				if curr.HasRegexChildren {
					for _, edge := range curr.RegexChildren {
						if edge.Re.Match(wordRaw) {
							ws.nextNodes = append(ws.nextNodes, edge.Node)
						}
					}
				}
				if curr.WildcardChild != nil {
					ws.nextNodes = append(ws.nextNodes, curr.WildcardChild)
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
						if tIdx >= 0 && tIdx < len(ws.tokens) {
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
							matchStart:  ws.tokens[i].Start,
							matchEnd:    ws.tokens[j].End,
							priority:    node.Meta.Priority,
							targetStart: targetsStart,
							targetEnd:   len(ws.targets),
							minLength:   node.Meta.MinLength,
							maxLength:   node.Meta.MaxLength,
							hits:        node.Meta.Hits,
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
	slices.SortFunc(ws.toRedact, func(a, b pendingRedaction) int {
		if a.priority != b.priority {
			return cmp.Compare(a.priority, b.priority)
		}
		// If priorities are equal, the longer match wins.
		return cmp.Compare(b.matchEnd-b.matchStart, a.matchEnd-a.matchStart)
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

		resolvedBefore := len(ws.resolved)
		for _, t := range ws.targets[r.targetStart:r.targetEnd] {
			actualStart := t.start
			if len(t.redactAfterBytes) > 0 {
				tokenSlice := raw[t.start:t.end]
				idx := bytesIndexCaseInsensitive(tokenSlice, t.redactAfterBytes)
				if idx == -1 {
					continue
				}
				actualStart = t.start + idx + len(t.redactAfterBytes)
			}

			secretLen := max(t.end-actualStart, 0)
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
				maskLen := min(max(t.end-actualStart, 0), len(globalStars))
				ws.resolved = append(ws.resolved, finalInt{start: actualStart, end: t.end, maskB: globalStars[:maskLen]})
			} else {
				ws.resolved = append(ws.resolved, finalInt{start: actualStart, end: t.end, maskS: maskStr})
			}
		}
		// Count the rule hit only when at least one target was actually redacted.
		if len(ws.resolved) > resolvedBefore && r.hits != nil {
			r.hits.Add(1)
			trie.totalMatches.Add(1)
		}
	}

	slices.SortFunc(ws.resolved, func(a, b finalInt) int {
		return cmp.Compare(a.start, b.start)
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

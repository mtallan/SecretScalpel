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
	toRedact []pendingRedaction
	claimed  []interval
	resolved []finalInt
	filtered []finalInt
	targets  []RedactionTarget
	tokens   []Token
	outBuf   bytes.Buffer
}

// workspacePool allows 24 concurrent workers to recycle memory instead of allocating.
var workspacePool = sync.Pool{
	New: func() any {
		return &EngineWorkspace{
			toRedact: make([]pendingRedaction, 0, 512),
			claimed:  make([]interval, 0, 128),
			resolved: make([]finalInt, 0, 128),
			filtered: make([]finalInt, 0, 128),
			targets:  make([]RedactionTarget, 0, 512),
			tokens:   make([]Token, 0, 8192),
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
	ws.filtered = ws.filtered[:0]
	ws.targets = ws.targets[:0]
	ws.tokens = ws.tokens[:0]
	ws.outBuf.Reset()

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
				ws.targets = append(ws.targets, RedactionTarget{
					start: start, end: end, mask: rr.Mask, redactAfter: rr.RedactAfter, redactAfterBytes: rr.RedactAfterBytes,
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
		curr := trie.Root
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

			// The Go compiler optimizes `m[string(b)]` to avoid allocation when looking up
			// a byte slice key in a map[string]T.
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
					targetsStart := len(ws.targets)
					for _, relIdx := range curr.Meta.RedactIndices {
						tIdx := i + relIdx
						if tIdx < len(ws.tokens) {
							ws.targets = append(ws.targets, RedactionTarget{
								start:            ws.tokens[tIdx].Start,
								end:              ws.tokens[tIdx].End,
								mask:             curr.Meta.CustomMask,
								redactAfter:      curr.Meta.RedactAfter,
								redactAfterBytes: curr.Meta.RedactAfterBytes,
							})
						}
					}
					if len(ws.targets) > targetsStart {
						ws.toRedact = append(ws.toRedact, pendingRedaction{
							matchStart: ws.tokens[i].Start,
							matchEnd:   ws.tokens[j].End,
							priority:   curr.Meta.Priority,
							targets:    ws.targets[targetsStart:],
							minLength:  curr.Meta.MinLength,
							maxLength:  curr.Meta.MaxLength,
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
			// Compute actualStart: prefer redactAfter (dynamic) over offset (legacy).
			// redactAfter searches for the literal prefix inside the token and skips past it,
			// so the offset is always correct regardless of the prefix length.
			actualStart := t.start
			if len(t.redactAfterBytes) > 0 {
				tokenSlice := raw[t.start:t.end]
				idx := bytesIndexCaseInsensitive(tokenSlice, t.redactAfterBytes)
				if idx == -1 {
					continue
				}
				actualStart = t.start + idx + len(t.redactAfterBytes)
			}

			// Enforce min/max length constraints from the rule
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

	if n := int64(len(ws.filtered)); n > 0 {
		Default.RedactionsApplied.Add(n)
	}

	ws.outBuf.Grow(len(raw))
	writePos := 0
	for _, inv := range ws.filtered {
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

// RedactBytesToWriter performs the same redaction as RedactBytes but writes the
// result directly to an io.Writer, avoiding the final allocation for the
// returned byte slice. This is more efficient when the output is being
// accumulated in a buffer, such as during JSON string redaction.
func RedactBytesToWriter(w io.Writer, raw []byte, trie *Trie) {
	if trie == nil || trie.Root == nil || len(raw) == 0 {
		w.Write(raw)
		return
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
	ws.filtered = ws.filtered[:0]
	ws.targets = ws.targets[:0]
	ws.tokens = ws.tokens[:0]
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
				ws.targets = append(ws.targets, RedactionTarget{
					start: start, end: end, mask: rr.Mask, redactAfter: rr.RedactAfter, redactAfterBytes: rr.RedactAfterBytes,
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
		curr := trie.Root
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

			// The Go compiler optimizes `m[string(b)]` to avoid allocation when looking up
			// a byte slice key in a map[string]T.
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
					targetsStart := len(ws.targets)
					for _, relIdx := range curr.Meta.RedactIndices {
						tIdx := i + relIdx
						if tIdx < len(ws.tokens) {
							ws.targets = append(ws.targets, RedactionTarget{
								start:            ws.tokens[tIdx].Start,
								end:              ws.tokens[tIdx].End,
								mask:             curr.Meta.CustomMask,
								redactAfter:      curr.Meta.RedactAfter,
								redactAfterBytes: curr.Meta.RedactAfterBytes,
							})
						}
					}
					if len(ws.targets) > targetsStart {
						ws.toRedact = append(ws.toRedact, pendingRedaction{
							matchStart: ws.tokens[i].Start,
							matchEnd:   ws.tokens[j].End,
							priority:   curr.Meta.Priority,
							targets:    ws.targets[targetsStart:],
							minLength:  curr.Meta.MinLength,
							maxLength:  curr.Meta.MaxLength,
						})
					}
				}
			} else {
				break
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

	if n := int64(len(ws.filtered)); n > 0 {
		Default.RedactionsApplied.Add(n)
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

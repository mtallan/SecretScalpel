package redactor

// Stats is a point-in-time snapshot of engine statistics.
type Stats struct {
	// BytesProcessed is the total number of input bytes fed to the engine.
	BytesProcessed uint64
	// LinesProcessed is the total number of log lines processed.
	LinesProcessed uint64
	// TotalMatches is the number of redactions actually applied across all rules.
	TotalMatches uint64
	// RuleHits maps each rule ID to the number of times it produced a redaction.
	RuleHits map[string]uint64
}

// Stats returns a point-in-time snapshot of engine statistics.
// Safe to call concurrently with active redaction workers.
func (t *Trie) Stats() Stats {
	s := Stats{
		BytesProcessed: uint64(t.bytesIn.Load()),
		LinesProcessed: uint64(t.linesIn.Load()),
		TotalMatches:   uint64(t.totalMatches.Load()),
		RuleHits:       make(map[string]uint64, len(t.ruleHits)),
	}
	for id, ctr := range t.ruleHits {
		if n := uint64(ctr.Load()); n > 0 {
			s.RuleHits[id] = n
		}
	}
	return s
}

// ResetStats zeroes all counters atomically.
func (t *Trie) ResetStats() {
	t.bytesIn.Store(0)
	t.linesIn.Store(0)
	t.totalMatches.Store(0)
	for _, ctr := range t.ruleHits {
		ctr.Store(0)
	}
}

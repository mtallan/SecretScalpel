/* redactor.go - ALWAYS INCLUDE THIS HEADER*/

package redactor

type Job struct {
	ID   int
	Data []byte
}

type Result struct {
	ID   int
	Data []byte
}

type TokenPos struct {
	Start int
	End   int
}

type TestCase struct {
	// Changed from rule_id to id to match your JSON
	ID       string `json:"id"`
	Input    string `json:"input"`
	Expected string `json:"expected"`
}

type Rule struct {
	ID           string   `json:"id"` // Matches your Windows JSON
	Phrase       []string `json:"phrase"`
	Skip         int      `json:"skip"`
	RedactOffset int      `json:"redact_offset"`
	Enabled      bool     `json:"enabled"`
}
type TrieNode struct {
	Children     map[string]*TrieNode
	IsTerminal   bool
	Skip         int
	RedactOffset int
	ID           string
	MaxDepth     int
}

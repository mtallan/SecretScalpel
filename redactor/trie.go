package redactor

import (
	"log/slog"
	"regexp"
	"strings"
)

type RegexRule struct {
	ID               string
	Re               *regexp.Regexp
	Mask             string
	RedactAfter      string
	RedactAfterBytes []byte
	Priority         int
	MinLength        int
	MaxLength        int
	RequiredByte     byte // if non-zero, skip this rule unless this byte is present in the input
}

type RegexEdge struct {
	Re   *regexp.Regexp
	Node *TrieNode
}

type RuleMeta struct {
	ID               string
	RedactIndices    []int
	CustomMask       string
	RedactAfter      string
	RedactAfterBytes []byte
	Priority         int
	MinLength        int
	MaxLength        int
}

type TrieNode struct {
	Children      map[string]*TrieNode
	RegexChildren []RegexEdge
	Meta          *RuleMeta
}

type JSONKeyTrieNode struct {
	Children map[byte]*JSONKeyTrieNode
	IsEnd    bool
}

var placeholderRegex = regexp.MustCompile(`(?i)^<(redact|any):(.+)>$`)

type Trie struct {
	Root              *TrieNode
	MaxDepth          int
	GlobalMask        string
	RegexRules        []*RegexRule
	JSONSensitiveKeys *JSONKeyTrieNode
	RuleCount         int // total rules loaded (trie + regex + json_key)
}

func NewTrie(mask string, min int, max int) *Trie {
	return &Trie{
		Root:              &TrieNode{Children: make(map[string]*TrieNode)},
		GlobalMask:        mask,
		JSONSensitiveKeys: &JSONKeyTrieNode{Children: make(map[byte]*JSONKeyTrieNode)},
	}
}

// AddJSONKeyRule registers a JSON object key whose value should always be
// fully redacted, regardless of content. Keys are stored lowercased so
// matching in RedactAllJSONStrings remains case-insensitive.
func (t *Trie) AddJSONKeyRule(key string) {
	t.RuleCount++
	curr := t.JSONSensitiveKeys
	lowerKey := strings.ToLower(key)
	for i := 0; i < len(lowerKey); i++ {
		b := lowerKey[i]
		if _, ok := curr.Children[b]; !ok {
			curr.Children[b] = &JSONKeyTrieNode{Children: make(map[byte]*JSONKeyTrieNode)}
		}
		curr = curr.Children[b]
	}
	curr.IsEnd = true
}

func (t *Trie) IsEmpty() bool {
	return len(t.Root.Children) == 0 && len(t.Root.RegexChildren) == 0 && len(t.RegexRules) == 0
}

func (t *Trie) AddRegexRule(id, pattern, mask string, min, max int, redactAfter string, priority int, requiredByte byte) {
	re, err := regexp.Compile(pattern)
	if err != nil {
		slog.Error("Invalid regex in rule", "rule_id", id, "pattern", pattern, "error", err)
		return
	}
	t.RuleCount++
	t.RegexRules = append(t.RegexRules, &RegexRule{
		ID: id, Re: re, Mask: mask, RedactAfter: redactAfter, RedactAfterBytes: []byte(redactAfter), Priority: priority,
		MinLength: min, MaxLength: max, RequiredByte: requiredByte,
	})
}

func (t *Trie) AddRule(id string, phrase []string, mask string, min, max int, redactAfter string, priority int) {
	if len(phrase) == 0 {
		return
	}
	curr := t.Root
	var redactIndices []int

	for i, word := range phrase {
		clean := strings.ToLower(word)

		// 1. Check for Regex Placeholders
		if matches := placeholderRegex.FindStringSubmatch(clean); len(matches) > 0 {

			if matches[1] == "redact" {
				redactIndices = append(redactIndices, i)
			}
			pattern := "(?i)" + matches[2]
			re, err := regexp.Compile(pattern)
			if err != nil {
				continue
			}

			// Link via Regex Edge
			found := false
			for _, edge := range curr.RegexChildren {
				if edge.Re.String() == re.String() {
					curr = edge.Node
					found = true
					break
				}
			}
			if !found {
				newNode := &TrieNode{Children: make(map[string]*TrieNode)}
				curr.RegexChildren = append(curr.RegexChildren, RegexEdge{Re: re, Node: newNode})
				curr = newNode
			}
			continue
		}

		// 2. Handle Literal/Wildcard
		if clean == "<redact>" {
			redactIndices = append(redactIndices, i)
		}

		key := clean
		if clean == "<redact>" || clean == "<any>" {
			key = "*"
		}

		if _, ok := curr.Children[key]; !ok {
			curr.Children[key] = &TrieNode{Children: make(map[string]*TrieNode)}
		}
		curr = curr.Children[key]
	}

	t.RuleCount++
	curr.Meta = &RuleMeta{
		ID: id, RedactIndices: redactIndices, CustomMask: mask,
		RedactAfter: redactAfter, RedactAfterBytes: []byte(redactAfter), Priority: priority,
		MinLength: min, MaxLength: max,
	}
	if len(phrase) > t.MaxDepth {
		t.MaxDepth = len(phrase)
	}
}

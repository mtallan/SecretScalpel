package redactor

import (
	"fmt"
	"regexp"
	"strings"
)

type RegexRule struct {
	ID          string
	Re          *regexp.Regexp
	Mask        string
	Offset      int
	RedactAfter string
	Priority    int
}

type RegexEdge struct {
	Re   *regexp.Regexp
	Node *TrieNode
}

type RuleMeta struct {
	ID            string
	RedactIndices []int
	CustomMask    string
	Offset        int
	RedactAfter   string
	Priority      int
}

type TrieNode struct {
	Children      map[string]*TrieNode
	RegexChildren []RegexEdge
	Meta          *RuleMeta
}

var placeholderRegex = regexp.MustCompile(`(?i)^<(redact|any):(.+)>$`)

type Trie struct {
	Root              *TrieNode
	MaxDepth          int
	GlobalMask        string
	RegexRules        []*RegexRule
	JSONSensitiveKeys map[string]bool
}

func NewTrie(mask string, min int, max int) *Trie {
	return &Trie{
		Root:              &TrieNode{Children: make(map[string]*TrieNode)},
		GlobalMask:        mask,
		JSONSensitiveKeys: make(map[string]bool),
	}
}

// AddJSONKeyRule registers a JSON object key whose value should always be
// fully redacted, regardless of content. Keys are stored lowercased so
// matching in RedactAllJSONStrings remains case-insensitive.
func (t *Trie) AddJSONKeyRule(key string) {
	t.JSONSensitiveKeys[strings.ToLower(key)] = true
}

func (t *Trie) IsEmpty() bool {
	return len(t.Root.Children) == 0 && len(t.Root.RegexChildren) == 0 && len(t.RegexRules) == 0
}

func (t *Trie) AddRegexRule(id, pattern, mask string, offset int, redactAfter string, priority int) {
	re, err := regexp.Compile(pattern)
	if err != nil {
		fmt.Printf("Invalid regex: %v\n", err)
		return
	}
	t.RegexRules = append(t.RegexRules, &RegexRule{
		ID: id, Re: re, Mask: mask, Offset: offset, RedactAfter: redactAfter, Priority: priority,
	})
}

func (t *Trie) AddRule(id string, phrase []string, mask string, min int, max int, offset int, redactAfter string, priority int) {
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

	curr.Meta = &RuleMeta{
		ID: id, RedactIndices: redactIndices, CustomMask: mask,
		Offset: offset, RedactAfter: redactAfter, Priority: priority,
	}
	if len(phrase) > t.MaxDepth {
		t.MaxDepth = len(phrase)
	}
}

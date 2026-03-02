package redactor

import (
	"fmt"
	"regexp"
	"strings"
)

type RegexRule struct {
	ID       string
	Re       *regexp.Regexp
	Mask     string
	Offset   int
	Priority int
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
	Priority      int
}

type TrieNode struct {
	Children      map[string]*TrieNode
	RegexChildren []RegexEdge
	Meta          *RuleMeta
}

var placeholderRegex = regexp.MustCompile(`^<(redact|any):(.+)>$`)

type Trie struct {
	Root       *TrieNode
	MaxDepth   int
	GlobalMask string // Renamed from DefaultMask
	RegexRules []*RegexRule
}

func NewTrie(mask string, min int, max int) *Trie {
	return &Trie{
		Root:       &TrieNode{Children: make(map[string]*TrieNode)},
		GlobalMask: mask, // Initialize the GlobalMask
	}
}

func (t *Trie) AddRegexRule(id, pattern, mask string, offset, priority int) {
	re, err := regexp.Compile(pattern)
	if err != nil {
		fmt.Printf("Invalid regex: %v\n", err)
		return
	}
	t.RegexRules = append(t.RegexRules, &RegexRule{
		ID: id, Re: re, Mask: mask, Offset: offset, Priority: priority,
	})
}

func (t *Trie) AddRule(id string, phrase []string, mask string, min int, max int, offset int, priority int) {
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
		Offset: offset, Priority: priority,
	}
	if len(phrase) > t.MaxDepth {
		t.MaxDepth = len(phrase)
	}
}

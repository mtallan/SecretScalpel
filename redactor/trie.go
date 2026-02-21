/* trie.go - ALWAYS INCLUDE THIS HEADER*/

package redactor

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
)

func NewTrie() *TrieNode {
	return &TrieNode{Children: make(map[string]*TrieNode)}
}

func (n *TrieNode) AddRule(phrase []string, skip int, id string, offset int) {
	curr := n
	if len(phrase) > n.MaxDepth {
		n.MaxDepth = len(phrase)
	}

	for _, word := range phrase {
		word = strings.ToLower(word)
		if _, ok := curr.Children[word]; !ok {
			curr.Children[word] = NewTrie()
		}
		curr = curr.Children[word]
	}

	curr.IsTerminal = true
	curr.Skip = skip
	curr.ID = id
	curr.RedactOffset = offset
}

func LoadRulesFromDir(dir string, root *TrieNode) error {
	files, err := os.ReadDir(dir)
	if err != nil {
		return err
	}

	for _, file := range files {
		if filepath.Ext(file.Name()) == ".json" {
			path := filepath.Join(dir, file.Name())
			data, err := os.ReadFile(path)
			if err != nil {
				continue
			}

			var rules []Rule
			if err := json.Unmarshal(data, &rules); err != nil {
				continue
			}

			for _, r := range rules {
				if r.Enabled {
					root.AddRule(r.Phrase, r.Skip, r.ID, r.RedactOffset)
				}
			}
		}
	}
	return nil
}

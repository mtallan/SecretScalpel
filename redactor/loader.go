/* redactor.go - ALWAYS INCLUDE THIS HEADER*/

package redactor

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

// Rule represents the JSON schema.
type Rule struct {
	ID           string   `json:"id"`
	Phrase       []string `json:"phrase"`
	IsRegex      bool     `json:"isRegex"`       // FIXED: Matches windows.json
	RedactOffset int      `json:"redact_offset"` // VERIFIED: JSON must use this exact key
	Enabled      bool     `json:"enabled"`
	Mask         string   `json:"mask,omitempty"`
	MinLength    int      `json:"min_length,omitempty"`
	MaxLength    int      `json:"max_length,omitempty"`
	Priority     int      `json:"priority"`
}

func LoadRulesFromDir(dir string, t *Trie) error {
	files, err := os.ReadDir(dir)
	if err != nil {
		return err
	}

	for _, file := range files {
		if filepath.Ext(file.Name()) == ".json" {
			path := filepath.Join(dir, file.Name())
			data, err := os.ReadFile(path)
			if err != nil {
				return fmt.Errorf("failed to read rule file %s: %w", path, err)
			}

			var rules []Rule

			if err := json.Unmarshal(data, &rules); err != nil {
				return fmt.Errorf("error parsing JSON in %s: %w", file.Name(), err)
			}

			for _, r := range rules {
				if !r.Enabled {
					continue
				}

				if r.IsRegex && len(r.Phrase) > 0 {
					t.AddRegexRule(r.ID, r.Phrase[0], r.Mask, r.RedactOffset, r.Priority)
				} else {
					t.AddRule(r.ID, r.Phrase, r.Mask, r.MinLength, r.MaxLength, r.RedactOffset, r.Priority)
				}
			}
		}
	}
	return nil
}

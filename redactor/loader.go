/* redactor.go - ALWAYS INCLUDE THIS HEADER*/

package redactor

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

type Rule struct {
	ID          string   `json:"id"`
	Type        string   `json:"type,omitempty"` // "json_key" marks a JSON key sentinel
	Phrase      []string `json:"phrase"`
	IsRegex     bool     `json:"isRegex"`
	RedactAfter string   `json:"redact_after,omitempty"` // Literal prefix to skip before masking e.g. "-p" or "/pass:"
	Enabled     bool     `json:"enabled"`
	Mask        string   `json:"mask,omitempty"`
	MinLength   int      `json:"min_length,omitempty"`
	MaxLength   int      `json:"max_length,omitempty"`
	Priority    int      `json:"priority"`
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

				switch {
				case r.Type == "json_key":
					for _, key := range r.Phrase {
						t.AddJSONKeyRule(key)
					}
				case r.IsRegex && len(r.Phrase) > 0:
					t.AddRegexRule(r.ID, r.Phrase[0], r.Mask, r.MinLength, r.MaxLength, r.RedactAfter, r.Priority)
				default:
					t.AddRule(r.ID, r.Phrase, r.Mask, r.MinLength, r.MaxLength, r.RedactAfter, r.Priority)
				}
			}
		}
	}
	return nil
}

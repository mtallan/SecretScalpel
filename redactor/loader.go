/* redactor.go - ALWAYS INCLUDE THIS HEADER*/

package redactor

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
)

type Rule struct {
	ID           string   `json:"id"`
	Type         string   `json:"type,omitempty"` // "json_key" marks a JSON key sentinel
	Phrase       []string `json:"phrase"`
	IsRegex      bool     `json:"isRegex"`
	RedactAfter  string   `json:"redact_after,omitempty"` // Literal prefix to skip before masking e.g. "-p" or "/pass:"
	Enabled      bool     `json:"enabled"`
	Mask         string   `json:"mask,omitempty"`
	MinLength    int      `json:"min_length,omitempty"`
	MaxLength    int      `json:"max_length,omitempty"`
	Priority     int      `json:"priority"`
	RequiredByte string   `json:"required_byte,omitempty"` // single ASCII char; skip regex if not present in input
}

func LoadRulesFromDir(dir string, t *Trie) error {
	files, err := os.ReadDir(dir)
	if err != nil {
		return err
	}

	seenIDs := make(map[string]string) // id -> first file that defined it

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

			beforeCount := t.RuleCount
			for _, r := range rules {
				if !r.Enabled {
					continue
				}

				if r.ID != "" {
					if firstFile, dup := seenIDs[r.ID]; dup {
						slog.Warn("Duplicate rule ID detected", "id", r.ID, "first_seen_in", firstFile, "also_in", file.Name())
					} else {
						seenIDs[r.ID] = file.Name()
					}
				}

				switch {
				case r.Type == "json_key":
					for _, key := range r.Phrase {
						t.AddJSONKeyRule(key)
					}
				case r.IsRegex && len(r.Phrase) > 0:
					var reqByte byte
					if len(r.RequiredByte) > 0 {
						reqByte = r.RequiredByte[0]
					}
					t.AddRegexRule(r.ID, r.Phrase[0], r.Mask, r.MinLength, r.MaxLength, r.RedactAfter, r.Priority, reqByte)
				default:
					t.AddRule(r.ID, r.Phrase, r.Mask, r.MinLength, r.MaxLength, r.RedactAfter, r.Priority)
				}
			}
			slog.Debug("Loaded rule file", "file", file.Name(), "rules_loaded", t.RuleCount-beforeCount)
		}
	}
	return nil
}

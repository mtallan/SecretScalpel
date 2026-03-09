package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"

	"github.com/aws/aws-lambda-go/lambda"
	"github.com/mtallan/SecretScalpel/redactor"
)

// Event is the input payload for a single log line.
// Adjust the shape here once you know the trigger (Firehose, direct invoke, etc.).
type Event struct {
	Log string `json:"log"`
}

type Response struct {
	Redacted string `json:"redacted"`
}

var trie *redactor.Trie

func init() {
	rulesDir := os.Getenv("SECRETSCALPEL_RULES_DIR")
	if rulesDir == "" {
		rulesDir = "./rules"
	}
	mask := os.Getenv("SECRETSCALPEL_MASK")
	if mask == "" {
		mask = "*"
	}

	trie = redactor.NewTrie(mask, 0, 0)
	if err := redactor.LoadRulesFromDir(rulesDir, trie); err != nil {
		slog.Error("Failed to load rules", "error", err)
		os.Exit(1)
	}
	slog.Info("Rules loaded", "total", trie.RuleCount, "regex", len(trie.RegexRules))
}

func handler(_ context.Context, event Event) (Response, error) {
	if event.Log == "" {
		return Response{}, fmt.Errorf("empty log field")
	}
	redacted := redactor.RedactAllJSONStrings([]byte(event.Log), trie)
	return Response{Redacted: string(redacted)}, nil
}

func main() {
	lambda.Start(handler)
}

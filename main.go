package main

import (
	"flag"
	"fmt"
	"log/slog"
	"os"
	"runtime"

	"github.com/mtallan/SecretScalpel/redactor"
)

const Version = "v0.1.0"

func main() {
	rulesDir     := flag.String("rules", "./rules", "path to rules directory")
	mask         := flag.String("mask", "*", "redaction mask string")
	debugRules   := flag.Bool("debug-rules", false, "replace redacted values with [RULE-ID] to show which rule matched")
	versionFlag  := flag.Bool("version", false, "print version and exit")
	healthFlag   := flag.Bool("health", false, "verify rules load correctly and exit")
	validateFlag := flag.Bool("validate-rules", false, "validate rule files and exit (0=ok, 1=error)")
	flag.Parse()

	if *versionFlag {
		fmt.Println("secretscalpel", Version)
		os.Exit(0)
	}

	logger := slog.New(slog.NewJSONHandler(os.Stderr, nil))
	slog.SetDefault(logger)

	trie := redactor.NewTrie(*mask, 0, 0)
	if err := redactor.LoadRulesFromDir(*rulesDir, trie); err != nil {
		logger.Error("Failed to load rules", "error", err)
		os.Exit(1)
	}

	if *validateFlag {
		fmt.Println("OK")
		os.Exit(0)
	}

	if trie.IsEmpty() {
		logger.Warn("No rules loaded", "path", *rulesDir)
		os.Exit(1)
	}
	logger.Info("Rules loaded", "total", trie.RuleCount, "regex", len(trie.RegexRules))
	trie.DebugRules = *debugRules

	if *healthFlag {
		fmt.Println("OK")
		os.Exit(0)
	}

	if err := redactor.ProcessStream(os.Stdin, os.Stdout, trie, runtime.NumCPU()); err != nil {
		logger.Error("Processing error", "error", err)
		os.Exit(1)
	}
}

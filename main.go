package main

import (
	"flag"
	"fmt"
	"os"
	"redactbox/redactor"
	"runtime"
)

func main() {
	rulesDir := flag.String("rules", "./rules", "path to rules directory")
	jsonMode := flag.Bool("json", false, "enable JSON mode (preserves JSON structure)")
	workers := flag.Int("workers", runtime.NumCPU(), "number of worker goroutines")
	mask := flag.String("mask", "[REDACTED]", "redaction mask string")
	flag.Parse()

	root := redactor.NewTrie(*mask, 0, 0)
	if err := redactor.LoadRulesFromDir(*rulesDir, root); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to load rules: %v\n", err)
		os.Exit(1)
	}

	if err := redactor.ProcessStream(os.Stdin, os.Stdout, root, *jsonMode, *workers); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

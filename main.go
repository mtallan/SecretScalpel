package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"runtime"

	"secretscaple/redactor"
)

const Version = "v0.1.0"

func main() {
	rulesDir := flag.String("rules", "./rules", "path to rules directory")
	jsonMode := flag.Bool("json", false, "enable JSON mode (preserves JSON structure)")
	workers := flag.Int("workers", runtime.NumCPU(), "number of worker goroutines")
	mask := flag.String("mask", "[REDACTED]", "redaction mask string")
	failOpen := flag.Bool("fail-open", false, "on error, pass input through unredacted rather than dropping")
	versionFlag := flag.Bool("version", false, "print version and exit")
	healthFlag := flag.Bool("health", false, "verify rules load correctly and exit")
	flag.Parse()

	if *versionFlag {
		fmt.Println("secretscaple", Version)
		os.Exit(0)
	}

	root := redactor.NewTrie(*mask, 0, 0)
	if err := redactor.LoadRulesFromDir(*rulesDir, root); err != nil {
		if *failOpen {
			fmt.Fprintf(os.Stderr, "WARNING: failed to load rules, passing through unredacted: %v\n", err)
			io.Copy(os.Stdout, os.Stdin)
			return
		}
		fmt.Fprintf(os.Stderr, "ERROR: failed to load rules: %v\n", err)
		os.Exit(1)
	}

	if root.IsEmpty() {
		fmt.Fprintf(os.Stderr, "WARNING: no rules loaded from %s\n", *rulesDir)
		if !*failOpen {
			os.Exit(1)
		}
	}

	if *healthFlag {
		fmt.Println("OK")
		os.Exit(0)
	}

	if err := redactor.ProcessStream(os.Stdin, os.Stdout, root, *jsonMode, *workers); err != nil {
		if *failOpen {
			fmt.Fprintf(os.Stderr, "WARNING: processing error, passing through unredacted: %v\n", err)
			fmt.Fprintf(os.Stdout, `{"secretscaple_warning":"REDACTION_FAILED_UNREDACTED_PAYLOAD_FOLLOWS"}`+"\n")
			io.Copy(os.Stdout, os.Stdin)
			return
		}
		fmt.Fprintf(os.Stderr, "ERROR: %v\n", err)
		os.Exit(1)
	}
}

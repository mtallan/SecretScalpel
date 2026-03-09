package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/pprof"
	"os"
	"os/signal"
	"runtime"
	"strconv"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/mtallan/SecretScalpel/redactor"
)

const Version = "v0.1.0"

func main() {
	rulesDir := flag.String("rules", getEnv("SECRETSCALPEL_RULES_DIR", "./rules"), "path to rules directory")
	jsonMode := flag.Bool("json", getEnvBool("SECRETSCALPEL_JSON_MODE", false), "enable JSON mode (preserves JSON structure)")
	workers := flag.Int("workers", getEnvInt("SECRETSCALPEL_WORKERS", runtime.NumCPU()), "number of worker goroutines")
	mask := flag.String("mask", getEnv("SECRETSCALPEL_MASK", "*"), "redaction mask string")
	failOpen := flag.Bool("fail-open", getEnvBool("SECRETSCALPEL_FAIL_OPEN", false), "on error, pass input through unredacted rather than dropping")
	adminAddr := flag.String("admin-addr", getEnv("SECRETSCALPEL_ADMIN_ADDR", ""), "address for the HTTP admin server (e.g. :9090); disabled if empty")
	versionFlag := flag.Bool("version", false, "print version and exit")
	healthFlag := flag.Bool("health", false, "verify rules load correctly and exit")
	validateFlag := flag.Bool("validate-rules", false, "validate rule files and exit (0=ok, 1=error)")
	flag.Parse()

	logger := slog.New(slog.NewJSONHandler(os.Stderr, nil))
	slog.SetDefault(logger)

	if *versionFlag {
		fmt.Println("secretscalpel", Version)
		os.Exit(0)
	}

	logger.Info("Starting secretscalpel",
		"version", Version,
		"workers", *workers,
		"json_mode", *jsonMode,
		"rules_dir", *rulesDir,
		"mask", *mask,
		"fail_open", *failOpen,
	)

	loadTrie := func() (*redactor.Trie, error) {
		t := redactor.NewTrie(*mask, 0, 0)
		if err := redactor.LoadRulesFromDir(*rulesDir, t); err != nil {
			return nil, err
		}
		return t, nil
	}

	if *validateFlag {
		if _, err := loadTrie(); err != nil {
			logger.Error("Rule validation failed", "error", err)
			os.Exit(1)
		}
		fmt.Println("OK")
		os.Exit(0)
	}

	root, err := loadTrie()
	if err != nil {
		if *failOpen {
			logger.Warn("Failed to load rules, passing through unredacted", "error", err)
			fmt.Fprintf(os.Stdout, `{"secretscalpel_warning":"REDACTION_FAILED_UNREDACTED_PAYLOAD_FOLLOWS"}`+"\n")
			io.Copy(os.Stdout, os.Stdin)
			return
		}
		logger.Error("Failed to load rules", "error", err)
		os.Exit(1)
	}

	if root.IsEmpty() {
		logger.Warn("No rules loaded", "path", *rulesDir)
		if !*failOpen {
			os.Exit(1)
		}
	} else {
		logger.Info("Rules loaded", "total", root.RuleCount, "regex", len(root.RegexRules))
	}

	if *healthFlag {
		fmt.Println("OK")
		os.Exit(0)
	}

	var triePtr atomic.Pointer[redactor.Trie]
	triePtr.Store(root)

	if *adminAddr != "" {
		mux := http.NewServeMux()
		mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprintf(w, `{"status":"ok","version":%q}`, Version)
		})
		mux.HandleFunc("/ready", func(w http.ResponseWriter, r *http.Request) {
			current := triePtr.Load()
			if current.IsEmpty() {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusServiceUnavailable)
				fmt.Fprintf(w, `{"status":"not ready","reason":"no rules loaded"}`)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprintf(w, `{"status":"ready","rules":%d}`, current.RuleCount)
		})
		mux.HandleFunc("/metrics", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/plain; version=0.0.4")
			redactor.Default.WritePrometheus(w)
		})

		// Register pprof handlers for profiling
		mux.HandleFunc("/debug/pprof/", pprof.Index)
		mux.HandleFunc("/debug/pprof/cmdline", pprof.Cmdline)
		mux.HandleFunc("/debug/pprof/profile", pprof.Profile)
		mux.HandleFunc("/debug/pprof/symbol", pprof.Symbol)
		mux.HandleFunc("/debug/pprof/trace", pprof.Trace)

		go func() {
			logger.Info("Admin server listening", "addr", *adminAddr)
			if err := http.ListenAndServe(*adminAddr, mux); err != nil {
				logger.Error("Admin server failed", "error", err)
			}
		}()
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM, syscall.SIGHUP)
	go func() {
		var shutdown bool
		for sig := range sigCh {
			if sig == syscall.SIGHUP {
				logger.Info("SIGHUP received, reloading rules", "rules_dir", *rulesDir)
				newTrie, err := loadTrie()
				if err != nil {
					logger.Error("Failed to reload rules, keeping existing trie", "error", err)
					continue
				}
				triePtr.Store(newTrie)
				logger.Info("Rules reloaded", "total", newTrie.RuleCount, "regex", len(newTrie.RegexRules))
				continue
			}
			if shutdown {
				os.Exit(1)
			}
			logger.Info("Shutdown signal received, draining in-flight work")
			cancel()

			// If reading from TTY, we can't unblock the read reliably and there's no
			// upstream buffer to drain. Exit quickly.
			shutdownDelay := 3 * time.Second
			if stat, err := os.Stdin.Stat(); err == nil && (stat.Mode()&os.ModeCharDevice) != 0 {
				shutdownDelay = 100 * time.Millisecond
			} else {
				if err := os.Stdin.SetReadDeadline(time.Now()); err != nil {
					logger.Warn("Could not set read deadline", "error", err)
				}
			}
			_ = os.Stdin.Close()
			shutdown = true
			go func() {
				time.Sleep(shutdownDelay)
				logger.Error("Shutdown timed out, forcing exit")
				os.Exit(1)
			}()
		}
	}()

	if err := redactor.ProcessStream(ctx, os.Stdin, os.Stdout, &triePtr, *jsonMode, *workers); err != nil {
		if *failOpen {
			logger.Warn("Processing error, passing through unredacted", "error", err)
			fmt.Fprintf(os.Stdout, `{"secretscalpel_warning":"REDACTION_FAILED_UNREDACTED_PAYLOAD_FOLLOWS"}`+"\n")
			io.Copy(os.Stdout, os.Stdin)
			return
		}
		logger.Error("Processing error", "error", err)
		os.Exit(1)
	}
}

func getEnv(key, fallback string) string {
	if value, ok := os.LookupEnv(key); ok {
		return value
	}
	return fallback
}

func getEnvBool(key string, fallback bool) bool {
	if value, ok := os.LookupEnv(key); ok {
		v, err := strconv.ParseBool(value)
		if err == nil {
			return v
		}
	}
	return fallback
}

func getEnvInt(key string, fallback int) int {
	if value, ok := os.LookupEnv(key); ok {
		v, err := strconv.Atoi(value)
		if err == nil {
			return v
		}
	}
	return fallback
}

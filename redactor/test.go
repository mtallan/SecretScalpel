/* test.go - ALWAYS INCLUDE THIS HEADER*/

package redactor

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

func RunAllTests(root *TrieNode, testsDir string) {
	files, err := os.ReadDir(testsDir)
	if err != nil {
		fmt.Printf("Error reading test directory: %v\n", err)
		return
	}

	for _, file := range files {
		// Skip non-JSON files
		if filepath.Ext(file.Name()) != ".json" {
			continue
		}

		fmt.Printf("\n--- Running Suite: %s ---", file.Name())

		fullPath := filepath.Join(testsDir, file.Name())
		data, err := os.ReadFile(fullPath)
		if err != nil {
			fmt.Printf("\n [!] Could not read file %s: %v", file.Name(), err)
			continue
		}

		var cases []TestCase
		if err := json.Unmarshal(data, &cases); err != nil {
			fmt.Printf("\n [!] Failed to parse JSON in %s: %v", file.Name(), err)
			continue
		}

		// Check if we actually loaded anything
		if len(cases) == 0 {
			fmt.Printf("\n [?] No test cases found in %s. Check your JSON keys!", file.Name())
			continue
		}

		passCount := 0
		for _, tc := range cases {
			inputBytes := []byte(tc.Input)
			RedactBytes(inputBytes, root)
			got := string(inputBytes)

			if got != tc.Expected {
				fmt.Printf("  [✘] FAIL: %-15s | Input: %s\n", tc.ID, tc.Input)
				fmt.Printf("      Got:  %s\n", got)
				fmt.Printf("      Want: %s\n", tc.Expected)
			} else {
				// This line gives you the visual feedback for every pass
				fmt.Printf("  [✔] PASS: %-15s | %s\n", tc.ID, tc.Input)
				passCount++
			}
		}
		fmt.Printf("\n  Suite Summary: %d/%d passed\n", passCount, len(cases))
	}
	fmt.Println()
}

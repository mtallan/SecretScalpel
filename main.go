package main

import (
	"fmt"
	"redactbox/redactor"
)

func main() {
	root := redactor.NewTrie()
	redactor.LoadRulesFromDir("./rules", root)

	// 1. Define your input as a byte slice (mutable)
	input := []byte(`{"cmd_line": "net use \\srv\share Pass123 /user:bob"}`)

	// 2. Call RedactBytes.
	// It modifies 'input' directly and returns NO value.
	redactor.RedactBytes(input, root)

	// 3. Print the modified slice
	// We cast to string just for the console output
	fmt.Println(string(input))

	// 4. Run tests (Ensure these were updated to handle the new signature!)
	redactor.RunAllTests(root, "./tests")
}

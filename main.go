package main

import (
	"fmt"
	"redactbox/redactor"
)

func main() {
	root := redactor.NewTrie("[REDACTED]", 2, 0)

	if err := redactor.LoadRulesFromDir("./rules", root); err != nil {
		fmt.Printf("Failed to load rules: %v\n", err)
		return
	}

	testInput := []byte(`{
  "AlertId": "ev-9921-bc10-4421",
  "Title": "Cleartext password detected in command line",
  "Severity": "High",
  "Category": "CredentialAccess",
  "Description": "A process was launched with a command line that appears to contain a plaintext password.",
  "Evidence": {
    "ProcessId": 8422,
    "ParentProcessName": "cmd.exe",
    "FileName": "psexec64.exe",
    "CommandLine": "psexec64.exe \\\\Workstation-Secure-99 -u CORP\\svc-deploy -p P@ssw0rd123! cmd.exe /c \"net user guest /active:yes\"",
    "SensitiveDataDetected": {
      "Type": "Password",
      "Value": "P@ssw0rd123!"
    }
  }
}`)

	// Use the new String Walker to shield the engine from JSON formatting
	out := redactor.RedactAllJSONStrings(testInput, root)
	//out := redactor.RedactBytes(testInput, root)
	fmt.Printf("Result:\n%s\n", out)
}

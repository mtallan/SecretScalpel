package main

import (
	"fmt"
	"redactbox/redactor"
)

func main() {
	root := redactor.NewTrie("*", 2, 0)

	if err := redactor.LoadRulesFromDir("./rules", root); err != nil {
		fmt.Printf("Failed to load rules: %v\n", err)
		return
	}

	testInput := []byte(`{
  "timestamp": "2026-02-28T11:45:12.453Z",
  "event_id": 1,
  "task": "Process Create",
  "level": "Information",
  "computer": "WS-ALICE-PRO",
  "event_data": {
    "RuleName": "technique_id=T1059,technique_name=Command and Scripting Interpreter",
    "UtcTime": "2026-02-28 11:45:12.450",
    "ProcessGuid": "{A1B2C3D4-E5F6-7890-G1H2-I3J4K5L6M7N8}",
    "ProcessId": 6732,
    "Image": "C:\\Windows\\System32\\net.exe",
    "FileVersion": "10.0.19041.1 (WinBuild.160101.0800)",
    "Description": "Net Command",
    "Product": "Microsoft® Windows® Operating System",
    "Company": "Microsoft Corporation",
    "OriginalFileName": "net.exe",
    "CommandLine": "net use Z: \\\\fileserver\\share alice P@ssw0rd domain",
    "CurrentDirectory": "C:\\Users\\alice\\Documents\\",
    "User": "CORP\\alice",
    "LogonGuid": "{A1B2C3D4-E5F6-7890-G1H2-I3J4K5L6M7N9}",
    "LogonId": "0x3e7",
    "TerminalSessionId": 1,
    "IntegrityLevel": "Medium",
    "Hashes": "SHA256=5E4D3C2B1A...[truncated]",
    "ParentProcessGuid": "{A1B2C3D4-E5F6-7890-G1H2-I3J4K5L6M7N0}",
    "ParentProcessId": 2140,
    "ParentImage": "C:\\Windows\\System32\\cmd.exe",
    "ParentCommandLine": "\"C:\\Windows\\System32\\cmd.exe\""
  }
},{
  "timestamp": "2026-02-28T11:45:12.453Z",
  "event_id": 1,
  "task": "Process Create",
  "level": "Information",
  "computer": "WS-ALICE-PRO",
  "event_data": {
    "RuleName": "technique_id=T1059,technique_name=Command and Scripting Interpreter",
    "UtcTime": "2026-02-28 11:45:12.450",
    "ProcessGuid": "{A1B2C3D4-E5F6-7890-G1H2-I3J4K5L6M7N8}",
    "ProcessId": 6732,
    "Image": "C:\\Windows\\System32\\net.exe",
    "FileVersion": "10.0.19041.1 (WinBuild.160101.0800)",
    "Description": "Net Command",
    "Product": "Microsoft® Windows® Operating System",
    "Company": "Microsoft Corporation",
    "OriginalFileName": "net.exe",
    "CommandLine": "net use Z: \\\\fileserver\\share alice P@ssw0rd domain",
    "CurrentDirectory": "C:\\Users\\alice\\Documents\\",
    "User": "CORP\\alice",
    "LogonGuid": "{A1B2C3D4-E5F6-7890-G1H2-I3J4K5L6M7N9}",
    "LogonId": "0x3e7",
    "TerminalSessionId": 1,
    "IntegrityLevel": "Medium",
    "Hashes": "SHA256=5E4D3C2B1A...[truncated]",
    "ParentProcessGuid": "{A1B2C3D4-E5F6-7890-G1H2-I3J4K5L6M7N0}",
    "ParentProcessId": 2140,
    "ParentImage": "C:\\Windows\\System32\\cmd.exe",
    "ParentCommandLine": "\"C:\\Windows\\System32\\cmd.exe\""
  }
}`)

	// Use the new String Walker to shield the engine from JSON formatting
	out := redactor.RedactAllJSONStrings(testInput, root)
	fmt.Printf("Result:\n%s\n", out)
}

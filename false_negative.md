---
name: False Negative (Missed Secret)
about: Report a credential pattern that SecretScalpel failed to redact
title: 'Missed Secret: [Command/Tool Name]'
labels: 'new-rule'
assignees: ''
---

**Tool or Command**
Which tool or command generated the log? (e.g., `psexec`, `curl`, `connection string`)

**Example Log Line (Sanitized)**
Please provide an example of the log line where the secret was missed.
*IMPORTANT: Replace the actual real secret with dummy data like `Password123`.*

```text
Example: psexec -u admin -p Password123 cmd.exe
```

**Expected Output**

```text
Example: psexec -u admin -p *********** cmd.exe
```

**Context**
- OS: [e.g. Windows, Linux]
- Log Format: [e.g. Raw text, JSON]
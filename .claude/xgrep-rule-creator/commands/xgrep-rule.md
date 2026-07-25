---
name: xgrep-rule
description: Create xgrep rules with test-first methodology, or port existing rules to new languages
argument-hint: "(describe what to detect, or provide a rule path + target language)"
allowed-tools: Bash Read Write Edit Glob Grep WebFetch
---

# Create xgrep Rule

**Arguments:** $ARGUMENTS

This command is context-driven:

- **New rule**: Describe the vulnerability or pattern to detect and the target language
- **Port rule**: Provide an existing rule file path and the target language(s)

If context is unclear, ask for:
1. The vulnerability or code pattern to detect
2. The target language(s)

Invoke the `xgrep-rule-creator` skill for the full workflow.

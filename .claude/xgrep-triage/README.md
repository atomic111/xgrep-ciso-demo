# xgrep Triage

A Claude Code skill for investigating and classifying xgrep scan findings using code graph analysis.

## What it does

- Scans targets with xgrep rules and summarizes findings
- Investigates each finding using the code graph (callers, callees, call paths, function context)
- Classifies findings as true positive, false positive, or needs review
- Provides evidence-based reports with specific function names and line numbers
- Suggests remediation for true positives

## Usage

```
/xgrep-triage ./src --rules security-rules/
```

## Installation

```bash
claude skill install ./skills/xgrep-triage
```

## Prerequisites

- `xgrep` CLI must be installed and available in PATH
- Target codebase must be accessible for graph building

## Investigation Capabilities

- **Injection** (SQL, command, XSS): Traces data from sources to sinks, checks for sanitization
- **Auth/access control**: Maps all entry points, verifies middleware coverage
- **Data exposure**: Tracks sensitive data flow to logging, errors, and API responses
- **Insecure configuration**: Checks environment-specific overrides
- **Cryptographic issues**: Evaluates algorithm and key management context

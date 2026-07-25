---
name: secure-coding
description: Review code for security vulnerabilities or get secure coding guidance for a specific language/pattern
argument-hint: "(describe what to review, or ask about a specific pattern)"
allowed-tools: Bash Read Edit Glob Grep
---

# Secure Coding Review

**Arguments:** $ARGUMENTS

Review code or answer security questions using the vulnerability pattern reference
in [references/patterns.md]({baseDir}/references/patterns.md).

## Behavior

**When reviewing code or a file:**
1. Read the file(s) to review
2. Check each function/block against the 15 vulnerability categories in the patterns reference
3. Report findings with: the vulnerable line, which pattern it matches, and the safe alternative
4. If no issues found, say so explicitly

**When answering "how do I safely..." questions:**
1. Look up the relevant category in the patterns reference
2. Give the language-specific safe pattern with a code example
3. Cite the CVE that demonstrates why the unsafe pattern is dangerous

**When generating or modifying code:**
1. Before writing, check if the code involves any of the 15 categories
2. Use the safe alternative from the start, not the dangerous pattern
3. Add a brief comment explaining the security choice only if non-obvious

## What to look for

Prioritize by severity:
1. **Critical**: SQL injection, code injection, deserialization, JWT bypass
2. **High**: SSRF, path traversal, disabled cert validation, header injection
3. **Medium**: Timing attacks, insecure TLS, CORS, weak random, sensitive logging
4. **Low**: Race conditions (TOCTOU)

## References

- Full pattern tables: [references/patterns.md]({baseDir}/references/patterns.md)
- Real CVE examples: [references/cve-examples.md]({baseDir}/references/cve-examples.md)

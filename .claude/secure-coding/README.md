# Secure Coding Skill

A Claude Code skill that provides secure coding guidance to AI agents, helping
them proactively avoid generating vulnerable code patterns.

## What it does

- Reviews code for common security anti-patterns across Go, Python, JavaScript/TypeScript, Java, Ruby, C#, and Swift
- Provides language-specific safe alternatives for each vulnerable pattern
- Covers 15 vulnerability categories derived from real CVEs
- Can be triggered proactively during code generation or on-demand for review

## Finding types covered

Timing attacks, SQL injection, SSRF, path traversal, code injection, XSS,
JWT issues, insecure TLS, certificate validation, deserialization, HTTP
header injection, CORS, sensitive data logging, weak random, race conditions.

## Usage

```
/secure-coding review this function for security issues
/secure-coding what's the safe way to compare secrets in Go?
/secure-coding check this PR for vulnerabilities
```

## Installation

Copy the `skills/secure-coding/` directory into your project or install via
the Claude Code skill registry.

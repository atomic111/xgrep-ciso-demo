---
name: xgrep-inspect
description: Investigates and navigates source code using xgrep's AST-powered code intelligence. Use when exploring unfamiliar code, finding definitions/references, understanding dependencies, or assessing change impact.
allowed-tools: Bash Read Glob Grep
---

# xgrep Code Intelligence

Navigate and understand source code using xgrep's AST-powered code graph and Zoekt-powered text search.

## When to Use

- Exploring an unfamiliar codebase ("what does this project do?", "what are the main components?")
- Finding code ("where is X defined?", "who calls Y?", "find all implementations of Z")
- Understanding relationships ("what does this function depend on?", "trace this call chain")
- Assessing change impact ("what breaks if I change this?", "what's the blast radius?")
- Getting a file overview before reading it line by line

## When NOT to Use

- Running security scans (use `xgrep scan` or `/xgrep-triage`)
- Creating or modifying rules (use `/xgrep-rule`)
- Simple text searches where grep/ripgrep suffice (single keyword in a known file)

## Commands Reference

### Orient

| Command | Purpose |
|---------|---------|
| `xgrep inspect overview [dir]` | Codebase summary: languages, packages, entry points, key types |

### Locate

| Command | Purpose |
|---------|---------|
| `xgrep inspect symbol <query> [--kind K]` | Search symbols by name (exact, prefix, substring) |
| `xgrep inspect search <query> [--lang L] [--regex]` | Fast trigram-indexed text search (Zoekt) |

Locating is **lexical** (a name or a string the code contains), not semantic — there is
no search-by-meaning. When you only know *what* the code does, not its name: run
`overview` first to learn the real vocabulary, then `symbol`/`search` those terms
(expanding synonyms yourself, e.g. `auth` → `session`/`credential`/`login`), then
`references`/`deps` to traverse to the target. This is faster and more precise than
guessing patterns with grep.

### Navigate

| Command | Purpose |
|---------|---------|
| `xgrep inspect definition --file F --line N` | Find symbol definition at position |
| `xgrep inspect hover --file F --line N` | Doc comment, type info, params (tooltip) |
| `xgrep inspect ranges <file> --start S --end E` | All symbols in a line range (bulk) |
| `xgrep inspect references <name>` | Find all callers, callees, references |
| `xgrep inspect implementations <name>` | Find interface implementations |
| `xgrep inspect outline <file>` | List all symbols in a file |

### Assess

| Command | Purpose |
|---------|---------|
| `xgrep inspect impact <name>` | Blast radius: callers, callees, affected files, risk score |
| `xgrep inspect deps <name> [--depth N]` | Call dependencies: upstream callers, downstream callees |

### Deep Dive (existing graph commands)

| Command | Purpose |
|---------|---------|
| `xgrep graph context <name> --depth N` | N-hop neighborhood with inlined source |
| `xgrep graph paths <src> <dst>` | Call paths between two functions |
| `xgrep graph callers <name>` | Direct callers |
| `xgrep graph callees <name>` | Direct callees |

## Output Formats

All `inspect` commands support `--json` for machine-readable output. Without `--json`, output is human-readable text.

## Caching

- Code graph cached to `.xgrep/graph.json` — incremental rebuild via file mtimes (~0.3s when fresh)
- Search index cached to `.xgrep/search/` — full Zoekt trigram index, skipped when fresh (~0.1s)
- Both are built automatically on first use — no setup needed

## Supported Languages

xgrep uses tree-sitter for AST parsing. Full symbol extraction (variables, fields, constants, imports, doc comments, visibility) for:
- **Go**: functions, methods, types, struct fields, variables, constants, imports
- **Python**: functions, classes, attributes, module variables, constants, imports
- **JavaScript/TypeScript**: functions, classes, fields, variables, constants, imports

Basic extraction (functions, classes, call edges) for 30+ additional languages.

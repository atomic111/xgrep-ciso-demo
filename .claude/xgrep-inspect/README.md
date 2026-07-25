# xgrep-inspect

A Claude Code skill for navigating and understanding source code using xgrep's AST-powered code intelligence.

## What it does

Provides structured code navigation that replaces dozens of grep/read calls with single commands:

- **Orient**: Codebase overview (languages, packages, entry points, key types)
- **Locate**: Symbol search + Zoekt-powered text search
- **Navigate**: Go-to-definition, find references, find implementations, file outline
- **Assess**: Impact analysis (blast radius), call dependency graph

## Usage

```
/xgrep-inspect what does this codebase do?
/xgrep-inspect where is EvalRule defined and who calls it?
/xgrep-inspect is it safe to rename CodeGraph.Build?
/xgrep-inspect show me the public API of pkg/graph
```

## Requirements

- `xgrep` CLI installed and on PATH
- Works with any codebase xgrep supports (30+ languages via tree-sitter)

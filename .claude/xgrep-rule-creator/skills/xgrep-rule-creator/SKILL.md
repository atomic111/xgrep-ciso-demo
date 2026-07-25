---
name: xgrep-rule-creator
description: Creates custom xgrep rules for detecting security vulnerabilities, bug patterns, and code anti-patterns. Supports both creating new rules from scratch and porting existing rules to new languages. Use when writing xgrep/Semgrep YAML rules or building custom static analysis detections.
allowed-tools: Bash Read Write Edit Glob Grep WebFetch
---

# xgrep Rule Creator

Create production-quality xgrep rules with proper testing and validation. Also port existing rules to new target languages.

## When to Use

- Writing xgrep rules for specific bug patterns or security vulnerabilities
- Writing taint mode rules for data flow vulnerabilities
- Writing rules to enforce coding standards
- Porting an existing rule to one or more new target languages

## When NOT to Use

- Running existing rulesets (just use `xgrep -f rules.yaml target/`)
- Triaging scan findings (use the `xgrep-triage` skill)

## Detecting Intent

**From scratch** (default): The user describes a vulnerability or pattern to detect.
**Porting**: The user provides an existing rule file AND specifies target language(s). Follow the porting workflow in [workflow.md]({baseDir}/references/workflow.md#porting-an-existing-rule).

## Rationalizations to Reject

- **"The pattern looks complete"** -- Still run `xgrep test` to verify. Untested rules have hidden false positives/negatives.
- **"It matches the vulnerable case"** -- Matching vulnerabilities is half the job. Verify safe cases don't match (false positives break trust).
- **"Taint mode is overkill"** -- If data flows from user input to a dangerous sink, taint mode gives better precision than pattern matching.
- **"One test is enough"** -- Include edge cases: different coding styles, sanitized inputs, safe alternatives, boundary conditions.
- **"I'll optimize first"** -- Write correct patterns first, optimize after all tests pass. Premature optimization causes regressions.

## Anti-Patterns

**Too broad** -- matches everything:
```yaml
# BAD: Matches any function call
pattern: $FUNC(...)

# GOOD: Specific dangerous function
pattern: eval(...)
```

**Missing safe cases in tests** -- undetected false positives:
```python
# BAD: Only tests vulnerable case
# ruleid: my-rule
dangerous(user_input)

# GOOD: Include safe cases
# ruleid: my-rule
dangerous(user_input)

# ok: my-rule
dangerous(sanitize(user_input))

# ok: my-rule
dangerous("hardcoded_safe_value")
```

**Using regex when AST patterns are better**:
```yaml
# BAD: Matches inside strings and comments
pattern-regex: "eval\\(.*\\)"

# GOOD: AST-aware matching
pattern: eval(...)
```

**Overly specific** -- misses variations:
```yaml
# BAD: Only matches exact format
pattern: os.system("rm " + $VAR)

# GOOD: Taint tracking catches all flows
mode: taint
pattern-sources:
  - pattern: input(...)
pattern-sinks:
  - pattern: os.system(...)
```

## Strictness Level

This workflow is **strict** -- do not skip steps:
- **Test-first is mandatory**: Never write a rule without tests
- **100% test pass required**: "Most tests pass" is not acceptable
- **Optimize last**: Only simplify patterns after all tests pass
- **Avoid generic patterns**: Rules must be specific
- **Prefer taint mode** for data flow vulnerabilities
- **One YAML file, one rule**: Don't combine multiple rules in a single file
- **No generic language**: Avoid `languages: generic` when targeting a specific language
- **No `todoruleid`**: Don't use `todoruleid` annotations as a crutch for unfinished rules

## Overview

Rules are created iteratively: analyze the problem, write tests first, write the rule, iterate until all tests pass, then optimize.

**Approach selection:**
- **Taint mode** (prefer for injection/flow bugs): Tracks data from untrusted sources to dangerous sinks
- **Pattern matching**: Simple syntactic patterns without data flow requirements

**Switching approaches**: If taint mode isn't working well (propagation issues, too many FPs), switch to pattern matching. If pattern matching has too many FPs on safe cases, try taint mode. The goal is a working rule.

**Output structure** -- rule + clean source file + Go table test:
```
rules/<lang>/lang/security/<category>/<rule-id>/
+-- <rule-id>.xgrep.yaml     # xgrep rule
+-- <rule-id>.<ext>           # Clean source file (no annotations)

test/rules/<lang>/security_test.go   # Go test with ExpectMatch lines
```

**Reference resources:**
- `cve/<lang>/lang/security/<category>/` -- Real CVE code samples for test cases
- `docs/contributing/secure-coding.md` -- Dangerous vs safe patterns per language
- `rules/<lang>/.../<rule>/` -- existing rules per language (the live source of coverage)

## Quick Start

```yaml
rules:
  - id: insecure-eval
    languages: [python]
    severity: ERROR
    message: User input passed to eval() allows code execution
    mode: taint
    pattern-sources:
      - pattern: request.args.get(...)
    pattern-sinks:
      - pattern: eval(...)
```

Source file (`insecure-eval.py`) -- clean, no annotations:
```python
from flask import request

def vulnerable(request):
    eval(request.args.get('code'))

def safe():
    eval("print('safe')")
```

Go test (`test/rules/python/security_test.go`):
```go
func TestPythonInsecureEval(t *testing.T) {
    dir := filepath.Join(rulesDir(), "python", "lang", "security", "injection", "insecure-eval")
    testutil.RunRuleTest(t, testutil.RuleTest{
        Rule: filepath.Join(dir, "insecure-eval.xgrep.yaml"),
        Cases: []testutil.TestCase{
            {File: "insecure-eval.py", ExpectMatch: []int{4}},
        },
    })
}
```

Run: `go test ./test/rules/python/ -run TestPythonInsecureEval -v`

## References

- Pattern syntax and operators: [quick-reference.md]({baseDir}/references/quick-reference.md)
- Step-by-step workflow (creation and porting): [workflow.md]({baseDir}/references/workflow.md)
- Language capabilities and idiom mapping: [language-guide.md]({baseDir}/references/language-guide.md)

## Workflow Checklist

Copy and track progress:

```
xgrep Rule Progress:
- [ ] Step 1: Analyze the problem
- [ ] Step 2: Write tests first
- [ ] Step 3: Write the rule
- [ ] Step 4: Iterate until all tests pass (go test ./test/rules/<lang>/)
- [ ] Step 5: Optimize the rule (remove redundancies, re-test)
- [ ] Step 6: Final validation (xgrep validate + real-world scan)
```

## Documentation

Before writing rules, read the Semgrep documentation for rule syntax fundamentals:

1. [Rule Syntax](https://semgrep.dev/docs/writing-rules/rule-syntax)
2. [Pattern Syntax](https://semgrep.dev/docs/writing-rules/pattern-syntax)
3. [Testing Rules](https://semgrep.dev/docs/writing-rules/testing-rules)
4. [Taint Analysis](https://semgrep.dev/docs/writing-rules/data-flow/taint-mode)
5. [Constant Propagation](https://semgrep.dev/docs/writing-rules/data-flow/constant-propagation)

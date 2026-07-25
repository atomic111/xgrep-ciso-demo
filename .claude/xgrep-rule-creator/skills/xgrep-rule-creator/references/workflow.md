# xgrep Rule Workflow

## Creating a New Rule

### Step 1: Analyze the Problem

Before writing anything:

1. **Identify the vulnerability or pattern**: What exactly should this rule detect? Be specific about the dangerous operation and the conditions that make it dangerous.
2. **Choose the target language(s)**: Check whether the language has tree-sitter support (full AST matching) or is regex-only. See [language-guide.md]({baseDir}/references/language-guide.md).
3. **Decide taint vs pattern matching**:
   - **Taint mode**: Data flows from untrusted input to dangerous sink (injection, XSS, path traversal)
   - **Pattern matching**: Specific syntax that is always dangerous regardless of data flow (hardcoded credentials, insecure configuration, deprecated API usage)
4. **Search for existing rules**: Check if a similar rule already exists in the codebase before writing a new one.

### Step 2: Write Tests First

Create the test source file **before** writing the rule. Source files should be
**clean code without annotations** -- test expectations are defined in Go test
files using `testutil.RunRuleTest`.

**Directory structure:**
```
rules/<lang>/lang/security/<category>/<rule-id>/
+-- <rule-id>.xgrep.yaml     # xgrep rule
+-- <rule-id>.<ext>           # Clean source file with vulnerable + safe examples
```

**Source file requirements:**
- Group vulnerable examples together (top), safe examples below
- At least 3 vulnerable patterns and 3 safe patterns
- No `# ruleid:` or `# ok:` annotations -- keep source files clean
- Use real-world patterns from CVE examples in `cve/` where possible

**Go test file** (in `test/rules/<lang>/security_test.go`):
```go
func TestPythonSqlInjection(t *testing.T) {
    dir := filepath.Join(rulesDir(), "python", "lang", "security", "injection", "sql-injection")
    testutil.RunRuleTest(t, testutil.RuleTest{
        Rule: filepath.Join(dir, "sql-injection.xgrep.yaml"),
        Cases: []testutil.TestCase{
            {
                File:        "sql-injection.py",
                ExpectMatch: []int{10, 14, 18},  // lines with vulnerable code
            },
        },
    })
}
```

**Example source file (`sql-injection.py`):**
```python
import sqlite3

def vulnerable_examples(conn, user_input):
    conn.execute("SELECT * FROM users WHERE id = " + user_input)

    query = f"DELETE FROM users WHERE name = '{user_input}'"
    conn.execute(query)

    conn.execute("UPDATE users SET name = '%s'" % user_input)

def safe_examples(conn, user_input):
    conn.execute("SELECT * FROM users WHERE id = ?", (user_input,))

    conn.execute("SELECT * FROM users WHERE id = :id", {"id": user_input})

    conn.execute("SELECT COUNT(*) FROM users")
```

**Reference material:** Check `cve/<lang>/lang/security/<category>/` for real-world
vulnerable code extracted from CVE fix commits. Use `docs/contributing/secure-coding.md`
for the dangerous-vs-safe pattern tables per language.

### Step 3: Write the Rule

Start simple and iterate. For taint mode:

```yaml
rules:
  - id: sql-injection
    languages: [python]
    severity: ERROR
    message: >-
      User input reaches SQL query without parameterization.
      Use parameterized queries instead.
    metadata:
      cwe: CWE-89
      owasp: A03:2021
      confidence: HIGH
    mode: taint
    pattern-sources:
      - pattern: user_input
    pattern-sinks:
      - pattern: $CONN.execute($QUERY, ...)
        focus-metavariable: $QUERY
```

For pattern matching:

```yaml
rules:
  - id: hardcoded-password
    languages: [python]
    severity: WARNING
    message: Hardcoded password in source code
    patterns:
      - pattern: $VAR = "..."
      - metavariable-regex:
          metavariable: $VAR
          regex: "(?i)(password|passwd|secret|token)"
      - metavariable-analysis:
          analyzer: entropy
          metavariable: $VAR
```

### Step 4: Iterate Until All Tests Pass

Run the Go test for your rule:

```bash
# Run a specific test
go test ./test/rules/<lang>/ -run TestMyRule -count=1 -v

# Run all tests for a language
go test ./test/rules/<lang>/ -count=1 -v
```

You can also use `xgrep test` for quick iteration during development, then
write the Go test once the rule is stable:

```bash
xgrep test rules/<lang>/lang/security/<category>/<rule-id>/
```

**Common issues and fixes:**

| Problem | Likely Cause | Fix |
|---------|-------------|-----|
| Expected line not matched | Pattern too specific | Broaden with `...` or `$VAR`, use `pattern-either` |
| Unexpected line matched | Pattern too broad | Add `pattern-not`, `pattern-not-inside`, or metavariable filter |
| Taint not propagating | Missing propagator | Add `pattern-propagators` for assignments/transformations |
| Wrong lines matched | Ellipsis too greedy | Use `pattern-inside` to scope, or set `generic_ellipsis_max` |
| YAML parse error with `:` | Unquoted colon in pattern | Use `pattern: \|` block scalar for patterns with colons |

**Iterate**: Change one thing at a time. Run the test after each change.

### Step 5: Optimize the Rule

Only after all tests pass:

1. **Remove redundant patterns**: If a `pattern-not` never fires, remove it
2. **Simplify combinators**: If all branches of `pattern-either` share structure, factor it out
3. **Re-test after every change**: Optimization can introduce regressions

### Step 6: Final Validation

```bash
# Validate rule syntax
xgrep validate rules/<lang>/lang/security/<category>/<rule-id>/<rule-id>.xgrep.yaml

# Run against CVE sample code to verify detection
xgrep -f <rule>.xgrep.yaml cve/<lang>/lang/security/<category>/ --json

# Run against real code to check for unexpected false positives
xgrep -f <rule>.xgrep.yaml <real-codebase> --json

# Run the Go test suite
go test ./test/rules/<lang>/ -run TestMyRule -count=1 -v
```

Review any matches on real code. If there are false positives, add safe
examples to the source file and update ExpectMatch in the Go test.

---

## Porting an Existing Rule

When given an existing rule and target language(s):

### Step 1: Analyze the Source Rule

Read the existing rule YAML carefully:

1. What vulnerability does it detect?
2. What patterns/sources/sinks does it use?
3. Are there language-specific idioms (decorators, error returns, annotations)?
4. What metavariable filters are applied?

### Step 2: Assess Applicability

For each target language, determine:

- **Directly applicable**: The vulnerability and API pattern exist in the target language (e.g., SQL injection exists in every language with DB access)
- **Applicable with adaptation**: The vulnerability exists but the API surface is different (e.g., Python `subprocess.run` vs Go `exec.Command`)
- **Not applicable**: The pattern doesn't apply (e.g., Python decorator rules don't apply to C)

Check [language-guide.md]({baseDir}/references/language-guide.md) for capabilities and idiom mappings.

### Step 3: Create Target Language Tests

For each applicable target language:

1. Create a new directory: `<rule-id>-<language>/`
2. Write idiomatic test code in the target language
3. Map each test case from the source rule to the target language equivalent
4. Add language-specific edge cases

**Example**: Porting Python SQL injection to Go:

```go
package main

import "database/sql"

func vulnerable(db *sql.DB, userInput string) {
    // ruleid: sql-injection-go
    db.Query("SELECT * FROM users WHERE id = " + userInput)

    // ruleid: sql-injection-go
    query := fmt.Sprintf("SELECT * FROM users WHERE id = '%s'", userInput)
    db.Query(query)
}

func safe(db *sql.DB, userInput string) {
    // ok: sql-injection-go
    db.Query("SELECT * FROM users WHERE id = ?", userInput)

    // ok: sql-injection-go
    db.Query("SELECT COUNT(*) FROM users")
}
```

### Step 4: Write the Variant Rule

Create a new rule file adapting patterns for the target language:

- Adjust API calls to target language equivalents
- Adjust string formatting patterns
- Keep the same metadata (CWE, OWASP, severity)
- Use language-appropriate metavariable patterns

### Step 5: Validate

```bash
# Test the new variant
xgrep test <rule-id>-<language>/

# Ensure original rule still passes
xgrep test <original-rule-id>/
```

---

## Common Anti-Patterns

### 1. Missing ellipsis in call arguments

```yaml
# BAD: Only matches single-argument calls
pattern: foo($X)

# GOOD: Matches any number of arguments
pattern: foo($X, ...)
# or
pattern: foo(...)
```

### 2. Forgetting pattern-not for safe wrappers

If `db.query(user_input)` should match but `db.query(sanitize(user_input))` should not:

```yaml
patterns:
  - pattern: $DB.query($INPUT)
  - pattern-not: $DB.query(sanitize(...))
```

### 3. Taint without sanitizer testing

Always write test cases that verify sanitizers actually block findings:

```python
# ok: my-taint-rule
sanitized = sanitize(user_input)
dangerous(sanitized)
```

### 4. Wrong language identifier

| File Type | Correct `languages` value |
|-----------|--------------------------|
| `.ts` | `typescript` |
| `.tsx` | `tsx` (NOT `typescript`) |
| `.jsx` | `javascript` |
| `.mjs` | `javascript` |
| `.kt` | `kotlin` |
| `.sc` | `scala` |

### 5. Regex when AST patterns would work

`pattern-regex` matches inside strings and comments. Use AST `pattern` when possible. Reserve `pattern-regex` for patterns that can't be expressed as AST patterns (e.g., matching inside string literals, matching whitespace patterns).

### 6. Metavariable comparison without capture

```yaml
# BAD: $SIZE is never captured
patterns:
  - metavariable-comparison:
      metavariable: $SIZE
      comparison: $SIZE > 1024

# GOOD: Pattern captures $SIZE first
patterns:
  - pattern: allocate($SIZE)
  - metavariable-comparison:
      metavariable: $SIZE
      comparison: $SIZE > 1024
```

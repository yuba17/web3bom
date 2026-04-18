---
name: compile_fixer
placeholders: [ERROR, FILES, STEP]
---

# Fix {{STEP}} Error

Fix ONLY the error below. Do not refactor, do not improve, do not add features.

## Error
```
{{ERROR}}
```

## Files
{{FILES}}

## Rules
1. Fix the MINIMUM needed to resolve the error
2. Do not change test logic or invariant assertions
3. If an import is missing, add it
4. If a type is wrong, fix the type
5. If a function signature doesn't match, fix the call site
6. Do NOT delete invariants or properties to make things compile

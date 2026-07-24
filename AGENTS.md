# Repository working rules

## Delivery

- Work in the smallest independently reviewable task that produces a useful result.
- After a microtask succeeds, run the smallest relevant local checks, commit it immediately, and push it immediately.
- Never batch unrelated successful microtasks into one commit.
- Write every commit message in English with a clear conventional prefix.

## Validation

- Prefer focused, fast tests selected from the files and contracts affected by the change.
- When a test supports parallel workers, use exactly half of the processors reported by the current machine.

## Engineering

- Keep the implementation KISS: the smallest safe design that satisfies the current contract.
- Preserve least privilege, fail-closed validation, and secret redaction.
- Do not keep dead compatibility layers while the project has no production users.
- Keep source files small and responsibilities explicit.

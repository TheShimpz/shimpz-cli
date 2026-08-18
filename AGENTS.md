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

## Command ontology

- Command hierarchy follows the product hierarchy: write resource-owned operations as
  `shimpz <resource> <operation>`. Every Assistant operation lives below `shimpz assistant`; never add a
  top-level Assistant verb or invert the hierarchy to `<operation> assistant`.
- Group a command by the resource it acts on, not by the resource that authorizes it. A Team still authorizes and
  owns an Assistant installation even though the client command is `shimpz assistant install`.
- An Action is declared by and addressed through an Assistant project. Execute one Action with
  `shimpz assistant run <action-id>`; do not create `shimpz test` or a top-level `action` namespace while Action has
  no independent lifecycle. Reserve `test` for engineering test suites.
- Top-level commands are limited to CLI-wide or session-wide operations. A Space-root operation may elide `space`
  only when it acts on the complete managed Space and the current architecture explicitly admits that surface. The
  current top-level command set is `assistant`, `auth`, and `upgrade`; help and version flags are syntax, not product
  resources. Expanding this set requires an explicit ontology and authority review plus parser tests that prove the
  resulting closed set.
- CLI placement never transfers domain authority. Preserve the producing service, authorizing principal, exact
  target, response binding, and fail-closed ambiguity checks behind every command.
- Retired command spellings are rejected rather than accepted through aliases, fallbacks, or hidden compatibility
  parsing.

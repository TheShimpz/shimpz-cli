# Repository working rules

## Ownership and authority

- This repository owns the `shimpz` client: Creator-facing Assistant workflows and the native Local Space lifecycle.
  It does not own Account authentication authority, Assistant publication authority, Team installation authority,
  Admin Supervisor authority, or the atomic Local release selection.
- The canonical current architecture is the umbrella's
  [architecture map](https://github.com/TheShimpz/shimpz/blob/main/.context/ARCHITECTURE.md), available at
  `../.context/ARCHITECTURE.md` when checked out at `cli/`. Read ADR-0015 through ADR-0030 and
  ADR-0049 and ADR-0050 before changing product concepts, command ontology, Local installation, reset, topology, storage,
  release, credentials, principals, or authority boundaries.
- Shimpz is pre-production. Update the current contract directly; do not add migrations, deprecated aliases,
  old-format parsers, version fallbacks, dual behavior, or retired-resource cleanup paths. Current-contract reset,
  compensation, and idempotent reconciliation are not compatibility paths.
- Push a successful CLI commit before advancing its umbrella gitlink; the gitlink records the exact source admitted
  to an atomic Local release.

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
- Space commands never load Creator Account credentials, call Creator authentication, or emit a Creator bearer.
- A release binary resolves privileged Space tools from fixed reviewed platform names and paths. Environment or
  configuration overrides for Docker, Compose, `sudo`, or storage tools are test-compiled only and must
  be inert in the release binary.
- A Space-managed executable is updated only through the atomic Local release. `shimpz upgrade` must refuse to
  replace it; the Local release ordinal remains its anti-rollback authority.

## Command ontology

- Command hierarchy follows the product hierarchy: write resource-owned operations as
  `shimpz <resource> <operation>`. Every Assistant operation lives below `shimpz assistant`; never add a
  top-level Assistant verb or invert the hierarchy to `<operation> assistant`.
- Group a command by the resource it acts on, not by the resource that authorizes it. A Team still authorizes and
  owns an Assistant installation even though the client command is `shimpz assistant install`.
- An Action is declared by and addressed through an Assistant project. Execute one Action with
  `shimpz assistant run <action-id>`; do not create `shimpz test` or a top-level `action` namespace while Action has
  no independent lifecycle. Reserve `test` for engineering test suites.
- Top-level commands are limited to CLI-wide or session-wide operations. ADR-0049 admits the complete Local Space
  operations without a redundant `space` noun. The exact current top-level command set is `assistant`, `auth`,
  `install`, `reset`, `start`, `status`, and `upgrade`; help and version flags are syntax, not product resources.
  Expanding this set requires an explicit ontology and authority review plus parser tests that prove the resulting
  closed set. The `space` alias is retired and rejected.
- CLI placement never transfers domain authority. Preserve the producing service, authorizing principal, exact
  target, response binding, and fail-closed ambiguity checks behind every command.
- Retired command spellings are rejected rather than accepted through aliases, fallbacks, or hidden compatibility
  parsing.

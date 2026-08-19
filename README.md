# Shimpz CLI

`shimpz` owns resource-first Assistant development and the native Local Space lifecycle. Assistant checks and
Action runs work locally without Docker: the CLI installs a pinned `uv` in its private cache, manages Python 3.14,
and runs the public `shimpz` Python SDK from the Assistant's `pyproject.toml`. Space lifecycle commands use Docker
to apply one atomic, digest-pinned release.

## Install

Install with Cargo:

```console
cargo install shimpz-cli --locked
```

Prebuilt binaries for Linux, macOS, and Windows are available in GitHub
Releases. Both installation paths provide the `shimpz` command.

## Use

```console
shimpz auth
shimpz assistant new hello-assistant
shimpz assistant develop codex
shimpz assistant develop claude hello-assistant --yolo
shimpz assistant check
shimpz assistant run create-dns --input '{"zone":"example.com"}'
shimpz assistant publish --visibility public
shimpz install
shimpz status
shimpz start
shimpz reset
shimpz upgrade
```

`shimpz auth` opens the default browser for OAuth authorization and also
prints the URL and user code in the terminal. `shimpz auth status` validates
the exact Accounts session online, while `shimpz auth logout` revokes the
complete rotating token family. Local credentials are stored in the current
OS user configuration directory with owner-only permissions.

`shimpz assistant publish` validates the Assistant, requests `assistant:publish` in its
browser authorization when needed, and continues the publication in the same
command. A separate `shimpz auth` step is not required.

`shimpz assistant install <source-digest> [--team <team-id>]` installs one exact published Assistant. When more
than one Team is available, `--team` is required.

`shimpz assistant new <name>` creates a minimal Python Assistant with one
Hello World Action. Python is the default language; it can also be selected
explicitly with `--language python`.

`shimpz assistant develop <codex|claude> [path]` starts an interactive coding agent in
the current directory, or in the optional path, with the versioned Shimpz
Assistant development guide from `https://developers.shimpz.com/assistant.md`.
The agent keeps its normal permission protections unless `--yolo` is explicitly
provided.

`shimpz install` installs or reconciles the complete Local Space from one atomic,
digest-pinned release. `shimpz status` reports it, `shimpz start` reconciles it,
and `shimpz reset` removes its exact owned state. A corrupt prior installation
is removed only after an exact interactive `Yes`; benign absence is successful.
On native Linux, Shimpz creates and verifies a LUKS2-backed storage pool. On
macOS and Windows/WSL2, Shimpz uses Docker-managed volumes and recommends
FileVault or BitLocker respectively, but does not configure or verify the
operating system's disk encryption.

`shimpz upgrade` checks the latest stable GitHub release and replaces a
standalone executable only when a newer version is available. A Space-managed
CLI is updated exclusively by the atomic Local release.

Integration tokens are read from environment variables and never accepted as CLI
arguments. For example, Integration `cloudflare` uses
`SHIMPZ_INTEGRATION_CLOUDFLARE`.

The crates.io package is named `shimpz-cli`; the installed command is
`shimpz`.

## License

Apache-2.0.

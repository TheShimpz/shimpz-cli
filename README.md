# Shimpz CLI

`shimpz` checks and tests file-backed Assistant Powers locally without Docker.
It installs a pinned `uv` in its private cache, manages Python 3.14, and runs
the public `shimpz` Python SDK from the Assistant's `pyproject.toml`.

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
shimpz new assistant hello-assistant
shimpz develop codex
shimpz develop claude --project hello-assistant --yolo
shimpz check
shimpz test create-dns --input '{"zone":"example.com"}'
shimpz upgrade
```

`shimpz auth` opens the default browser for OAuth authorization and also
prints the URL and user code in the terminal. `shimpz auth status` validates
the exact Accounts session online, while `shimpz auth logout` revokes the
complete rotating token family. Local credentials are stored in the current
OS user configuration directory with owner-only permissions.

`shimpz new assistant <name>` creates a minimal Python Assistant with one
Hello World Power. Python is the default language; it can also be selected
explicitly with `--language python`.

`shimpz develop <codex|claude>` starts an interactive coding agent in the
current directory with the versioned Shimpz Assistant development guide from
`https://developers.shimpz.com/assistant.md`. Use `--project <path>` for another
directory. The agent keeps its normal permission protections unless `--yolo`
is explicitly provided.

`shimpz upgrade` checks the latest stable GitHub release and replaces the
current executable only when a newer version is available.

Account tokens are read from environment variables and never accepted as CLI
arguments. For example, account `cloudflare` uses
`SHIMPZ_ACCOUNT_CLOUDFLARE`.

The crates.io package is named `shimpz-cli`; the installed command is
`shimpz`.

## License

Apache-2.0.

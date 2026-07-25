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
shimpz new assistant hello-assistant
shimpz check
shimpz test create-dns --input '{"zone":"example.com"}'
shimpz upgrade
```

`shimpz new assistant <name>` creates a minimal Python Assistant with one
Hello World Power. Python is the default language; it can also be selected
explicitly with `--language python`.

`shimpz upgrade` checks the latest stable GitHub release and replaces the
current executable only when a newer version is available.

Account tokens are read from environment variables and never accepted as CLI
arguments. For example, account `cloudflare` uses
`SHIMPZ_ACCOUNT_CLOUDFLARE`.

The crates.io package is named `shimpz-cli`; the installed command is
`shimpz`.

## License

Apache-2.0.

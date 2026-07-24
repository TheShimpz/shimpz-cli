# Shimpz CLI

`shimpz` checks and tests file-backed Assistant Powers locally without Docker.
It installs a pinned `uv` in its private cache, manages Python 3.14, and runs
the public `shimpz` Python SDK from the Assistant's `pyproject.toml`.

```console
shimpz check
shimpz test create-dns --input '{"zone":"example.com"}'
```

Account tokens are read from environment variables and never accepted as CLI
arguments. For example, account `cloudflare` uses
`SHIMPZ_ACCOUNT_CLOUDFLARE`.

The crates.io package is named `shimpz-cli`; the installed command is
`shimpz`.

## License

Apache-2.0.

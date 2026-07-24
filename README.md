# Shimpz CLI

`shimpz` checks and tests file-backed Assistant Powers locally without Docker.
It manages the Python toolchain through `uv` and runs the public `shimpz`
Python SDK from the Assistant's `pyproject.toml`.

```console
shimpz check
shimpz test create-dns --input '{"zone":"example.com"}'
```

The crates.io package is named `shimpz-cli`; the installed command is
`shimpz`.

## License

Apache-2.0.

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
shimpz assistant stage
shimpz assistant publish --visibility public
shimpz install
shimpz status
shimpz start
shimpz update
shimpz stop
shimpz reset
shimpz upgrade
```

`shimpz auth` opens the default browser for OAuth authorization and also
prints the URL and user code in the terminal. `shimpz auth status` validates
the exact Account session online, while `shimpz auth logout` revokes the
complete rotating token family. Local credentials are stored in the current
OS user configuration directory with owner-only permissions.

`shimpz assistant publish` validates the Assistant, requests `assistant:publish` in its
browser authorization when needed, and continues the publication in the same
command. A separate `shimpz auth` step is not required.

Action request copy is English `shimpz.text` catalog copy. `shimpz assistant run` shows its English rendering and
answers with the canonical request fingerprint and option values.

`shimpz assistant stage` builds an unpublished Local snapshot without any Shimpz Account, sign-in, or service, and
embeds the language pack of its messages. When an OpenAI API key is saved in the owner-only file
`~/.config/shimpz/openai-api-key` (`$XDG_CONFIG_HOME/shimpz/openai-api-key`, or `%APPDATA%\shimpz\openai-api-key` on
Windows, where the CLI does not check file permissions), the CLI sends each English message without a valid remembered
translation, and nothing else, to OpenAI (`gpt-6-luna`) for every interface language. It removes invisible directional
marks from each answer, composes it in Unicode NFC, admits it with the protocol's reference rules, and, once the pinned
SDK's validator admits the complete pack, remembers it per message in its cache, so an unchanged message is not
translated again while that entry stays valid. Without that file the pack shows the English text in every interface
language and staging says so. A key file that is unsafe, unreadable, or malformed, a provider failure, or a message
refused three times fails staging instead of silently falling back; a refused message is named with the reason each
language was refused. Neither pack claims a Developers translation: publication builds and translates its own pack in
Developers.

`shimpz assistant run` mints one logical `operation_id` per run and repeats it on every human-request replay, as Team
does for one logical operation. A handled Action failure arrives as one sanitized failure frame: the CLI shows its real
error type, message, provider host, HTTP status, and response excerpt after removing every Integration token and
password it supplied once more from every member, and refuses any frame outside the closed shape. A nonzero exit, any
stderr output, or a response frame over 512 KiB is a transport fault reported only by its exit status, byte count, or
size, never by raw process output.

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
digest-pinned release. `shimpz status` summarizes its health, Admin address, and
release ordinal; `shimpz start` resumes or repairs it, `shimpz update` applies only a newer atomic release without
resuming a stopped Space, `shimpz stop` stops every owned workload without removing data, and `shimpz reset` removes
its exact owned state.
A stopped Space resumes with `shimpz start`. A corrupt prior installation is removed only after an exact
interactive `Yes`; benign absence is successful.
On native Linux, Shimpz creates and verifies a LUKS2-backed storage pool. On
macOS and Windows/WSL2, Shimpz uses Docker-managed volumes and recommends
FileVault or BitLocker respectively, but does not configure or verify the
operating system's disk encryption.

`shimpz upgrade` checks the latest stable GitHub release and replaces a
standalone executable only when a newer version is available. A Space-managed
CLI is updated exclusively by the atomic Local release through `shimpz update` or complete reconciliation.

`shimpz assistant run` makes the Action's provider calls itself, as Team does: the
Action never receives a credential. Integration tokens are read from environment
variables, never accepted as CLI arguments, and sent only to that provider's
reviewed API hosts; for example, Integration `cloudflare` uses
`SHIMPZ_INTEGRATION_CLOUDFLARE`. Stored Inputs are asked for in the terminal,
kept only in memory, and placed where `shimpz.toml` declares them.

The crates.io package is named `shimpz-cli`; the installed command is
`shimpz`.

## License

Apache-2.0.

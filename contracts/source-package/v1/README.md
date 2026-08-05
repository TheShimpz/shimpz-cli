# Shimpz source package v1

This directory is the language-neutral authority for the bytes uploaded by
`shimpz publish`. A source package is an uncompressed canonical POSIX ustar
archive whose SHA-256 digest is its public identity.

Every package carries one canonical root `icon.png`. It is a static,
1024-by-1024 PNG no larger than 1 MiB. The icon is covered by the source
digest; remote icon URLs, alternate filenames, animation, and platform-specific
icon variants are not part of this contract. Consumers may derive display
sizes from this single lossless source without changing Assistant identity.

`contract.json` freezes the source allowlist, portable path rules, resource
caps, canonical entry order, and exact ustar header values. `vectors.json`
contains positive packages with golden archive digests and negative packages
with stable rejection codes. Paths intentionally use a portable ASCII subset;
there is no platform or Unicode normalization.

Only regular author files are admitted. Parent directories are synthesized,
empty directories are omitted, and archive entries are sorted by their
canonical ASCII path bytes. All metadata is platform-owned. The archive ends
after exactly two zero blocks and never uses GNU, PAX, sparse, or compression
extensions.

From this directory, validate the authority and every vector:

```console
python verify.py
```

Copy the already-verified authority into an empty or previously synchronized
out-of-tree consumer directory without regenerating fixtures:

```console
python verify.py --sync /path/to/consumer/protocol/source-package/v1
```

The sync refuses symlinks and unknown destination files. Consumers record the
upstream commit and verify `contract-files.sha256` before running their own
implementation against the unchanged vectors.

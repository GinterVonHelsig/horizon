# TOP-DELIVERY archive and recovery

The daily archive is written to `/mnt/pve/synology/top-delivery-archives` as
an age-encrypted, zstd-compressed tarball using the public recipient in
`/etc/top-delivery/age-recipient.txt`. It contains the TOP-DELIVERY
controller/design and a curated historical export of manifests and text
artifacts from `/root/.codex/sol-runs`.

Excluded: credentials, tokens, `.env` files, private keys, logs, captures,
tool state, caches and large runtime data. The source `.codex` tree is never
modified by the exporter.

To rehearse recovery, copy one archive to an isolated directory, decrypt it
with the operator-held age identity, extract it, verify `SHA256SUMS`, and
compare the recovered manifest and artifact counts. Never extract over the
live controller directory.

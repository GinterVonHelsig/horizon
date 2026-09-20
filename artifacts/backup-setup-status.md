# TOP-DELIVERY backup setup status

## Completed

- Initialized a dedicated Git repository.
- Created private remote:
  `https://github.com/GinterVonHelsig/TOP-DELIVERY`
- Pushed the architecture and archive implementation.
- Added a daily UTC systemd timer definition.
- Added curated historical export of `.codex/sol-runs` manifests and text
  artifacts, excluding credentials, tokens, environment files, keys, logs,
  captures and tool state.
- Corrected Synology NFS ownership handling in the exporter.

## Pending

The first encrypted archive rehearsal could not proceed because the supplied
`/root/.config/age/keys.txt` fails `age-keygen -y` with a malformed mixed-case
secret-key error. No key material was printed or copied. The exporter now
uses only a public recipient at `/etc/top-delivery/age-recipient.txt`; the
private identity is not needed for daily backups. The systemd timer remains
disabled until that public recipient is installed and archive/restore passes.

Required remediation: install a valid `age1...` recipient, run archive and
restore rehearsal using the operator-held private identity, then enable and
verify the daily timer.

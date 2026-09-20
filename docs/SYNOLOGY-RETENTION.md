# Synology retention (F8 freeze)

Keep last 5 valid overlay-tree snapshots under `/mnt/pve/synology/TOP-DELIVERY/backups/`.
A snapshot is valid only if `tree/` + `MANIFEST.sha256` + `tree-sha256.txt` exist.

Never auto-delete `sol-pgbackrest`, `top-delivery-vm-backups`, `dump`, `images`, or `top-delivery-*.tar.zst.age` archives.

Cleanup is fail-closed: missing inventory means no delete.

Do not copy `/etc/top-delivery/*.env`, `gh` tokens, or `/opt/top-delivery-auth` onto the NAS.

Example env files in-tree use reserved `+1555555xxxx` values, not live E.164.

Restore rehearsal path (named, not executed onto live `current`):
`/opt/operator-harness/worktrees/20260908T-f8-restore-rehearsal-named-not-executed/`

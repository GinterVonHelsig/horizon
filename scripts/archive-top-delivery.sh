#!/usr/bin/env bash
set -euo pipefail

ROOT=/opt/top-delivery-p1/current
RUNS=/root/.codex/sol-runs
DEST=/mnt/pve/synology/top-delivery-archives
AGE_RECIPIENT_FILE=/etc/top-delivery/age-recipient.txt
STAMP=$(date -u +%Y%m%dT%H%M%SZ)
WORK="$DEST/.staging-$STAMP"
ARCHIVE="$DEST/top-delivery-$STAMP.tar.zst.age"

umask 077
test -d "$ROOT"
test -d /mnt/pve/synology
test -r "$AGE_RECIPIENT_FILE"
mkdir -p "$DEST" "$WORK/TOP-DELIVERY" "$WORK/history"

rsync -rlt --delete --no-owner --no-group \
  --exclude='.git/' --exclude='*.env' --exclude='.env.*' \
  --exclude='*secret*' --exclude='*credential*' --exclude='*token*' \
  --exclude='*.key' --exclude='*.pem' --exclude='*.log' \
  --exclude='id_rsa*' --exclude='id_ed25519*' --exclude='*identity*' \
  --exclude='*password*' --exclude='*.p12' --exclude='*.pfx' --exclude='*.kdbx' \
  "$ROOT/" "$WORK/TOP-DELIVERY/"

find "$RUNS" -type f \( -name 'manifest.json' -o -name '*.md' -o -name '*.yaml' -o -name '*.yml' \) \
  -size -10M -not -path '*/.cache/*' -not -path '*/logs/*' -not -path '*/captures/*' \
  -not -iname '*secret*' -not -iname '*credential*' -not -iname '*token*' -not -iname '*.env*' \
  -print0 | while IFS= read -r -d '' f; do
    rel=${f#"$RUNS/"}
    mkdir -p "$WORK/history/$(dirname "$rel")"
    cp --preserve=timestamps --no-preserve=ownership "$f" "$WORK/history/$rel"
  done

find "$WORK" -type f -print0 | sort -z | xargs -0 sha256sum > "$WORK/SHA256SUMS"
printf 'archive=%s\ncreated_utc=%s\nsource=%s\nhistorical_source=%s\n' \
  "$ARCHIVE" "$STAMP" "$ROOT" "$RUNS" > "$WORK/archive-metadata.txt"
sha256sum "$AGE_RECIPIENT_FILE" | awk '{print $1}' > "$ARCHIVE.recipient.sha256"

RECIPIENT=$(tr -d '[:space:]' < "$AGE_RECIPIENT_FILE")
case "$RECIPIENT" in age1*) ;; *) echo "invalid age recipient" >&2; exit 2 ;; esac
tar -C "$WORK/.." -cf - "$(basename "$WORK")" | zstd -T0 -19 | age -r "$RECIPIENT" -o "$ARCHIVE"
sha256sum "$ARCHIVE" > "$ARCHIVE.sha256"
cp "$WORK/SHA256SUMS" "$ARCHIVE.files"
rm -rf "$WORK"

find "$DEST" -maxdepth 1 -type f -name 'top-delivery-*.tar.zst.age' -printf '%T@ %p\n' \
  | sort -nr | tail -n +91 | cut -d' ' -f2- | while IFS= read -r old; do
      rm -f -- "$old" "$old.sha256" "$old.files" "$old.recipient.sha256"
    done
printf '%s\n' "$ARCHIVE"

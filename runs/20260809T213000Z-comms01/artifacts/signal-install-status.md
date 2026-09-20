# Signal/Hermes installation status

## PROD cleanup

- Removed the Signal CLI symlink created during the accidental PROD attempt.
- Removed OpenJDK 21 and OpenJDK 25 installed by that attempt.
- Preserved pre-existing Hermes, curl, jq, tar, and the older pre-existing
  `/opt/signal-cli-0.14.7` payload.
- No trading service, production database, broker, ledger, or network state
  was changed.

## Comms-01

- Installed OpenJDK 21 and OpenJDK 25 as required by the existing Signal CLI
  payload.
- Installed Signal CLI 0.14.7 under `/opt/signal-cli-0.14.7`.
- Created isolated account directory `/var/lib/signal-cli` owned by
  `topdelivery` with mode 0700.
- Generated a one-time linked-device URI using the isolated account directory.

## Pending operator action

The linked-device URI must be approved from the operator's Signal mobile app
under Settings → Linked Devices → Link New Device. The URI is intentionally
not stored in GitHub, Synology, logs or TOP-DELIVERY artifacts. After approval,
start the signal-cli HTTP daemon, configure the Hermes allowlist to the
operator identity, and run Signal delivery/replay/rate-limit tests.

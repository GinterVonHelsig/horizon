# Comms-01 SSH access evidence

- Added `comms-01` → `192.168.0.91` to the PROD host's `/etc/hosts`.
- Verified the VM ED25519 fingerprint before accepting the replacement host key:
  `SHA256:tfsoPvoMz8ckSa31/v6z7yi6mOIyoCXaSoOQa9rK+LM`.
- Added the existing PROD root public key idempotently to both `debian` and
  `root` authorized-key files on Comms-01.
- Verified from PROD:

```text
ssh comms-01 → hostname comms-01
user root
NVIDIA GeForce RTX 3090, 550.163.01
top-delivery-auth active
```

No passwords, private keys, broker credentials, production database access, or
network routing changes were introduced.

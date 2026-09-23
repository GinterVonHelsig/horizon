# Submission transport source ownership and compatibility

Derived contract/source inspection on Comms-01, 2026-09-20; no authoritative
original Git revision was located for these installed files:

| Installed source | SHA256 |
|---|---|
| /usr/local/lib/top_delivery_host_gateway/server.py | a885084e939ef493e07e65c6ac1d4244425363da774ea3bc33744388a364f9cf |
| /usr/local/lib/top-delivery/comms01_submit_gateway.py | f208b237907b1a0939e6efd76c9e70bb32d9ab8d023100c1c791e5724d555117 |
| /usr/local/sbin/top-delivery-submit | 44422f5958ef831616a12d822b3329c303cef8577cee48ba5011849a1c92fff6 |
| /opt/operator-harness/bin/top-delivery-host-gateway | 7e1a033583f901d64ab67270d2599113d4334dbf2f0debc350996d3ce0a71e72 |
| /etc/systemd/system/top-delivery-host-gateway.service | 4f9a94d5c6a02b9681e882f45d11057c25d0ec7f1a8530d0f4d04e852ae5dc3c |

The maintained transport factors the two paths into one checked runtime rather
than packaging the divergent current/d7305d4 pins or historical recovery prompt.
Names/ordinary inspect-submit operations, AF_UNIX peer authentication, prompt
allowlist/hash and canonical systemd attestation unit are retained. Changes:
mandatory explicit pinned consumer configuration; same immutable Horizon runtime;
same durable journal; blocked exits nonzero; no success on failed child JSON;
no implicit socket unlink or peer-credential fallback; historical execute-recovery
is recognized but always blocked. It cannot resume parked goals. No installed
file was modified. This is submission transport, not a delivery executor or
unified Comms Relay implementation. See docs/submission-release-package.md.

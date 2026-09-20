# VM creation standard

All new trading-platform VMs must be created from a verified template or
archive with a run ID and immutable source hash recorded in TOP-DELIVERY.

## Identity and sizing

- Trading and platform VMs use the 9000-series IDs.
- Each VM receives a descriptive name, owner, purpose, run ID and source hash.
- Resource limits and remaining host headroom are recorded before mutation.
- Production and staging credentials, databases, Redis namespaces and service
  names are separate.

## Console and SSH

- Configure a normal VGA console (`vga: std` or equivalent).
- Do not configure `serial0` as the primary console.
- Configure cloud-init or an equivalent first-boot mechanism with the approved
  SSH public key.
- Verify `sshd`, the host fingerprint, key-only login, and qemu-guest-agent
  before declaring the VM ready.
- If SSH or DHCP fails, use the normal VGA console or offline disk inspection;
  never silently fall back to a serial-only deployment.
- Proxmox hosts must expose hardware virtualization before production-like
  VMs are declared ready; verify `/dev/kvm` and the host kernel log. If SVM or
  VT-x is disabled by BIOS, record the exact finding and require physical
  BIOS/UEFI remediation.

## Acceptance

- VM starts and stops cleanly;
- SSH works using a run-scoped known-hosts file;
- qemu-guest-agent is active;
- network is limited to the approved existing bridge;
- backups and restore rehearsal pass;
- no production credentials or broker routes are present.

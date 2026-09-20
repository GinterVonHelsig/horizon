# VM9104 provisioning note

VM9104 was cloned from the verified stopped VM100 template on home05
(`192.168.0.49`). It has 4 vCPU, 8192 MiB fixed RAM, a 100 GiB local-lvm
disk, virtio NIC on the existing `vmbr0`, cloud-init SSH key configuration,
standard VGA, and no `serial0`.

The initial KVM start failed because home05 has no `/dev/kvm`. The VM was
started with `kvm=0` as a reversible, bounded remediation. It is running but
has not acquired an IPv4 DHCP lease; only the NIC's IPv6 link-local neighbor
has been observed. No production or broker state was changed.

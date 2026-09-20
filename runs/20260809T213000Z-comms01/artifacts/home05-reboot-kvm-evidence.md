# home05 hardware virtualization evidence

The authorized reboot of home05 completed and the cluster returned reachable.
The host remains quorate. VM9104 was stopped before reboot and remains
stopped.

Post-reboot checks:

```text
/dev/kvm: absent
modprobe kvm_amd: Operation not supported
SVM disabled (by BIOS) in MSR_VM_CR
kvm_amd: SVM not supported by CPU
```

Conclusion: hardware virtualization cannot be enabled from the operating
system. The physical BIOS/UEFI setting for AMD SVM/AMD-V must be enabled,
then home05 rebooted. No network, production, broker, database, or prior-run
state was changed.

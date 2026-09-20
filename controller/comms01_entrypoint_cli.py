"""Attested helper CLI for Comms-01 operation entrypoints on Comms-01.

Invoked from ``systemd-run`` as ``top-delivery-entrypoint@<service>.service`` so
``assert_service_name`` can bind the delegate unit to the target service without
raw SSH ``systemctl``.
"""

from __future__ import annotations

import sys


def main(argv: list[str] | None = None) -> int:
    args = argv or sys.argv[1:]
    if len(args) != 2:
        print(
            "usage: comms01_entrypoint_cli.py <operation> <service_name>",
            file=sys.stderr,
        )
        return 2
    operation, service_name = args
    if operation == "service-status":
        from comms01_operation_entrypoints import service_status

        sys.stdout.write(service_status(service_name=service_name))
        return 0
    if operation == "service-restart":
        from comms01_operation_entrypoints import service_restart

        service_restart(service_name=service_name)
        return 0
    print(f"unsupported operation: {operation}", file=sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())

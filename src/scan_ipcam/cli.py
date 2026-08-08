from __future__ import annotations

import argparse
import json
import sys

from scan_ipcam.scanner import scan_network


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Scan the local network for IP cameras")
    parser.add_argument("--subnet", help="Optional CIDR subnet to scan")
    parser.add_argument("--timeout", type=float, default=0.35, help="Per-host timeout in seconds")
    parser.add_argument(
        "--no-onvif",
        action="store_true",
        help="Skip ONVIF WS-Discovery",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Print machine-readable JSON",
    )
    return parser


async def _run(args: argparse.Namespace) -> int:
    devices = await scan_network(
        timeout=args.timeout,
        include_onvif=not args.no_onvif,
        subnet=args.subnet,
    )
    if args.json:
        print(json.dumps([device.to_dict() for device in devices], indent=2))
        return 0

    if not devices:
        print("No cameras discovered.")
        return 0

    for device in devices:
        ports = ", ".join(f"{port.port}/{port.service}" for port in device.open_ports)
        details = " ".join(
            part
            for part in (
                "ONVIF" if device.onvif else None,
                device.manufacturer,
                device.model,
            )
            if part
        )
        hostname = f" ({device.hostname})" if device.hostname else ""
        print(f"{device.ip}{hostname} [{device.source}] ports: {ports} {details}".rstrip())
    return 0


def main(argv: list[str] | None = None) -> int:
    import asyncio

    parser = build_parser()
    args = parser.parse_args(argv)
    return asyncio.run(_run(args))


if __name__ == "__main__":
    sys.exit(main())

from __future__ import annotations

import asyncio
import ipaddress
import socket
from dataclasses import asdict, dataclass
from typing import Iterable

from wsdiscovery import WSDiscovery

COMMON_CAMERA_PORTS = (80, 443, 554, 8000, 8080, 8554, 8899)
ONVIF_SERVICE_TYPE = "dn:NetworkVideoTransmitter"


@dataclass(frozen=True)
class OpenPort:
    port: int
    service: str


@dataclass
class CameraDevice:
    ip: str
    hostname: str | None
    source: str
    open_ports: list[OpenPort]
    onvif: bool = False
    manufacturer: str | None = None
    model: str | None = None

    def to_dict(self) -> dict:
        payload = asdict(self)
        payload["open_ports"] = [asdict(port) for port in self.open_ports]
        return payload


def _local_ipv4_networks() -> list[ipaddress.IPv4Network]:
    networks: list[ipaddress.IPv4Network] = []
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.connect(("8.8.8.8", 80))
            local_ip = sock.getsockname()[0]
        interface = ipaddress.ip_address(local_ip)
        if interface.is_private:
            networks.append(ipaddress.ip_network(f"{local_ip}/24", strict=False))
    except OSError:
        pass
    return networks


def _iter_hosts(network: ipaddress.IPv4Network) -> Iterable[str]:
    if network.prefixlen >= 31:
        yield str(network.network_address)
        if network.broadcast_address != network.network_address:
            yield str(network.broadcast_address)
        return
    for host in network.hosts():
        yield str(host)


async def _probe_port(ip: str, port: int, timeout: float) -> OpenPort | None:
    try:
        _, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port),
            timeout=timeout,
        )
        writer.close()
        await writer.wait_closed()
        return OpenPort(port=port, service=_guess_service(port))
    except (asyncio.TimeoutError, OSError):
        return None


def _guess_service(port: int) -> str:
    return {
        80: "http",
        443: "https",
        554: "rtsp",
        8000: "http-alt",
        8080: "http-proxy",
        8554: "rtsp-alt",
        8899: "onvif",
    }.get(port, "unknown")


async def _scan_host(ip: str, timeout: float) -> CameraDevice | None:
    probes = await asyncio.gather(
        *(_probe_port(ip, port, timeout) for port in COMMON_CAMERA_PORTS)
    )
    open_ports = [port for port in probes if port is not None]
    if not open_ports:
        return None

    hostname = None
    try:
        hostname, _, _ = await asyncio.to_thread(socket.gethostbyaddr, ip)
    except (socket.herror, socket.gaierror):
        pass

    return CameraDevice(
        ip=ip,
        hostname=hostname,
        source="port-scan",
        open_ports=open_ports,
    )


async def discover_onvif(timeout: float = 3.0) -> list[CameraDevice]:
    def _discover() -> list[CameraDevice]:
        devices: list[CameraDevice] = []
        wsd = WSDiscovery()
        wsd.start()
        try:
            services = wsd.searchServices(
                types=[ONVIF_SERVICE_TYPE],
                timeout=int(timeout),
            )
            for service in services:
                xaddrs = service.getXAddrs()
                if not xaddrs:
                    continue
                endpoint = xaddrs[0]
                ip = endpoint.split("//")[-1].split("/")[0].split(":")[0]
                scopes = service.getScopes() or []
                manufacturer = _scope_value(scopes, "name")
                model = _scope_value(scopes, "hardware")
                devices.append(
                    CameraDevice(
                        ip=ip,
                        hostname=None,
                        source="onvif",
                        open_ports=[OpenPort(port=80, service="onvif")],
                        onvif=True,
                        manufacturer=manufacturer,
                        model=model,
                    )
                )
        finally:
            wsd.stop()
        return devices

    return await asyncio.to_thread(_discover)


def _scope_value(scopes: list[str], key: str) -> str | None:
    prefix = f"onvif://www.onvif.org/{key}/"
    for scope in scopes:
        if scope.startswith(prefix):
            return scope[len(prefix) :]
    return None


def _merge_devices(*groups: list[CameraDevice]) -> list[CameraDevice]:
    merged: dict[str, CameraDevice] = {}
    for group in groups:
        for device in group:
            existing = merged.get(device.ip)
            if existing is None:
                merged[device.ip] = device
                continue
            port_numbers = {port.port for port in existing.open_ports}
            for port in device.open_ports:
                if port.port not in port_numbers:
                    existing.open_ports.append(port)
            existing.onvif = existing.onvif or device.onvif
            existing.manufacturer = existing.manufacturer or device.manufacturer
            existing.model = existing.model or device.model
            if existing.source != device.source:
                existing.source = f"{existing.source}+{device.source}"
    return sorted(merged.values(), key=lambda item: ipaddress.ip_address(item.ip))


async def scan_network(
    *,
    timeout: float = 0.35,
    include_onvif: bool = True,
    subnet: str | None = None,
) -> list[CameraDevice]:
    networks = (
        [ipaddress.ip_network(subnet, strict=False)]
        if subnet
        else _local_ipv4_networks()
    )

    port_devices: list[CameraDevice] = []
    if networks:
        port_scan_tasks = [
            _scan_host(host, timeout)
            for network in networks
            for host in _iter_hosts(network)
        ]
        port_results = await asyncio.gather(*port_scan_tasks)
        port_devices = [device for device in port_results if device is not None]

    onvif_devices: list[CameraDevice] = []
    if include_onvif:
        onvif_devices = await discover_onvif(timeout=max(timeout * 4, 2.0))

    return _merge_devices(port_devices, onvif_devices)

from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, patch

import pytest

from scan_ipcam.scanner import CameraDevice, OpenPort, _merge_devices, scan_network


def test_merge_devices_combines_same_ip() -> None:
    first = CameraDevice(
        ip="192.168.1.10",
        hostname=None,
        source="port-scan",
        open_ports=[OpenPort(port=554, service="rtsp")],
    )
    second = CameraDevice(
        ip="192.168.1.10",
        hostname="cam-10",
        source="onvif",
        open_ports=[OpenPort(port=80, service="onvif")],
        onvif=True,
        manufacturer="VIVTRON",
        model="T1PT-102W",
    )
    merged = _merge_devices([first], [second])
    assert len(merged) == 1
    assert merged[0].onvif is True
    assert merged[0].manufacturer == "VIVTRON"
    assert {port.port for port in merged[0].open_ports} == {80, 554}


@pytest.mark.asyncio
async def test_scan_network_returns_sorted_devices() -> None:
    device = CameraDevice(
        ip="10.0.0.5",
        hostname=None,
        source="port-scan",
        open_ports=[OpenPort(port=554, service="rtsp")],
    )

    with (
        patch("scan_ipcam.scanner._local_ipv4_networks", return_value=[]),
        patch("scan_ipcam.scanner.discover_onvif", new=AsyncMock(return_value=[device])),
    ):
        devices = await scan_network(include_onvif=True)

    assert [item.ip for item in devices] == ["10.0.0.5"]


@pytest.mark.asyncio
async def test_scan_network_handles_empty_networks() -> None:
    with patch("scan_ipcam.scanner._local_ipv4_networks", return_value=[]):
        devices = await scan_network(include_onvif=False)
    assert devices == []

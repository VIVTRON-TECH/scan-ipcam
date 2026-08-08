from fastapi.testclient import TestClient

from scan_ipcam.server import app


def test_health_endpoint() -> None:
    client = TestClient(app)
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json()["status"] == "ok"


def test_scan_endpoint_returns_payload(monkeypatch) -> None:
    from scan_ipcam.scanner import CameraDevice, OpenPort

    async def fake_scan(**_kwargs):
        return [
            CameraDevice(
                ip="192.168.1.50",
                hostname="camera.local",
                source="port-scan",
                open_ports=[OpenPort(port=554, service="rtsp")],
            )
        ]

    monkeypatch.setattr("scan_ipcam.server.scan_network", fake_scan)
    client = TestClient(app)
    response = client.post("/api/scan", json={"include_onvif": False})
    assert response.status_code == 200
    payload = response.json()
    assert payload["count"] == 1
    assert payload["devices"][0]["ip"] == "192.168.1.50"

# scan-ipcam

Discover IP cameras on the local network using port scanning and ONVIF WS-Discovery.

## Requirements

- Python 3.11+

## Setup

```bash
./scripts/cloud-agent-install.sh
```

## Development

Run the API and web UI:

```bash
uvicorn scan_ipcam.server:app --host 0.0.0.0 --port 8000 --reload
```

Open `http://localhost:8000` and click **Scan network**.

## CLI

```bash
scan-ipcam --json
scan-ipcam --subnet 192.168.1.0/24
```

## Tests

```bash
pytest
```

## Cloud Agent

The repository includes `.cursor/environment.json` for Cloud Agent environments. The install script bootstraps Python dependencies, and the `api` terminal starts the development server on port 8000.

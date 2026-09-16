# mTLS Live Dashboard

Greenfield prototype for observing an mTLS flow from its first visible network event through TLS records and application data.

## Run

```sh
go run .
```

Open <http://localhost:8787>. The dashboard starts in demo mode with a realistic DNS-first mTLS transcript.

For live capture, install Wireshark's `tshark`, then start with a capture interface. If omitted, the server selects the first active non-loopback interface:

```sh
CAPTURE_INTERFACE=eth0 go run .
```

Capturing packets may require elevated capabilities. Prefer granting the capture binary only the required capabilities rather than running the whole server as root.

## API

- `POST /api/sessions` creates a capture session. Body: `{ "mode": "demo" | "live", "interface": "eth0", "bpf": "tcp port 443" }`.
- `POST /api/sessions/:id/trigger` attaches API metadata to a session.
- `GET /api/sessions` lists sessions.
- `GET /api/sessions/:id` returns the normalized transcript.
- `GET /api/sessions/:id/stream` streams events with Server-Sent Events.
- `POST /api/sessions/:id/stop` stops a live capture.

The prototype deliberately shows encrypted application data as encrypted bytes. Readable content should only be added after an explicitly authorized TLS key-log/decryption integration.

Build a standalone binary with:

```sh
go build -o mtls-live .
./mtls-live
```

## Plan: Live mTLS Handshake Dashboard

Greenfield design for a live Wireshark/tshark-backed dashboard that captures the initiating DNS or TCP SYN, correlates the API trigger, renders the mTLS handshake and TLS records, and shows readable carried content only when valid decryption material is available.

**Steps**
1. Define the capture contract and scope: interface/filter, capture session lifecycle, retention limits, supported TLS versions, and explicit distinction between encrypted bytes and decrypted content.
2. Build a privileged capture worker around libpcap/tshark with a narrow capture filter. Emit normalized packet events, including DNS, TCP SYN/SYN-ACK/ACK, TLS handshake messages, TLS records, certificate metadata, alerts, retransmissions, and connection close events.
3. Add correlation and session state: associate API trigger metadata, DNS resolution, TCP 5-tuple, TLS connection identifiers, timestamps, and client/server direction into one flow. Support late correlation and ambiguous flows rather than assuming the first packet is always ClientHello.
4. Expose a control/query API: start/stop capture, trigger capture from an API request, stream live events over WebSocket or SSE, fetch session summaries, fetch packet/record detail, and export PCAP plus a redacted JSON transcript.
5. Implement the dashboard: session picker, API-trigger panel, packet timeline beginning at DNS or TCP SYN, handshake state machine, TLS record table, expandable packet details, certificate chain view, encrypted/decrypted content indicators, and pause/follow/export controls.
6. Add security and operational safeguards: least-privilege capture helper, authorization, redaction, bounded buffers, sensitive-payload policy, audit trail, backpressure, and clear UI warnings when content is unavailable or decrypted.
7. Validate with deterministic PCAP fixtures and controlled mTLS test clients, then perform live smoke tests against a disposable interface and verify DNS-first, SYN-first, retransmission, TLS 1.2, TLS 1.3, failure, and decryption-enabled scenarios.

**Relevant design modules**
- Capture worker: packet acquisition and tshark/libpcap adaptation.
- Normalizer: packet and TLS dissector output into a stable event schema.
- Correlator: API request metadata plus DNS/TCP/TLS flow association.
- Session store: bounded event log and searchable indexes.
- Streaming API: lifecycle commands and live event delivery.
- Dashboard client: timeline, record inspector, certificate view, and content viewer.

**Verification**
1. Replay PCAP fixtures and assert normalized ordering, direction, packet IDs, TLS record boundaries, and correlation IDs.
2. Run a controlled mTLS exchange and verify the dashboard starts at DNS when present, otherwise TCP SYN, then shows ClientHello, server certificate/request, client certificate, Finished, application records, and close state.
3. Verify TLS 1.3 encrypted handshake records are labeled correctly and readable content appears only with configured key material.
4. Verify API-trigger metadata remains linked when capture starts before the network flow or when packets arrive out of order.
5. Test authorization, redaction, buffer limits, dropped-event reporting, and PCAP export.

**Decisions**
- New implementation only; do not inspect or reuse existing workspace implementation.
- Use Wireshark-compatible capture/dissection semantics, but keep the dashboard dependent on a normalized internal event model rather than raw tshark output.
- Treat decrypted application content as optional and explicitly gated by operator-provided key material or endpoint instrumentation.
- Store packet payloads only under an explicit sensitive-data policy; default to bounded retention and redaction.

**Further ideas**
- Add a handshake health score for latency, retransmits, alerts, certificate validity, and cipher negotiation.
- Add a side-by-side client/server transcript with clock skew correction.
- Add filters for API route, request ID, SNI, ALPN, certificate subject, alert code, and record type.
- Add comparison mode for successful versus failed handshakes.
- Add OpenTelemetry trace/span links and a “trigger API request” replay action that never reuses captured secrets.
- Support live and replay modes using the same event stream contract.

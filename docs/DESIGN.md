# Design and analysis contract

Wireglass is a file-only pipeline: capture reader → link/network/transport decoder → bounded bidirectional flow table → metadata extractors → explainable indicators → text or JSON report. It has no capture-device backend, socket creation, packet injection, DNS lookup, or external enrichment.

## Bounds

- Capture files default to 2 GiB; individual classic-PCAP packets and PCAPNG blocks are capped at 16 MiB and 64 MiB respectively.
- Analysis defaults to 2,000,000 packets and 8,192 flows. DNS events and findings are capped independently.
- TCP metadata collection is limited to 16 KiB per direction per tracked flow and is enabled only for HTTP/TLS well-known ports.
- Flow lookup uses a bounded open-addressed table. Unsupported link types and non-initial IP fragments are counted instead of guessed.

## Interpretation

`DNS.HIGH_ENTROPY_LABEL` is emitted for a first DNS label of at least 35 characters with estimated Shannon entropy of at least 3.55 bits per character. `FLOW.PERIODIC_TIMING` is emitted when at least six observed intervals span 30 seconds, have coefficient of variation at most 0.15, and average no more than 15 minutes. These are triage leads, not verdicts. Benign software update checks, telemetry, CDNs, and monitoring systems can look regular or encoded.

## Current parser boundaries

Classic PCAP microsecond/nanosecond formats and PCAPNG section, interface, enhanced-packet, and simple-packet blocks are supported. Link types include Ethernet with up to four VLAN tags, raw IPv4/IPv6, Linux cooked v1/v2, and explicit IPv4/IPv6 link types. IPv4/IPv6, TCP, UDP, DNS A/AAAA answers, HTTP Host, and TLS ClientHello SNI/ALPN are decoded.

Wireglass does not currently reassemble IP fragments. TCP stream collection accepts in-order data and trims already-seen overlap; a forward sequence gap resets the bounded inspection buffer and increments a gap counter. It does not reconstruct arbitrary out-of-order segments, decrypt TLS, parse QUIC, validate checksums, correlate DNS request/response pairs, or fully decode every PCAPNG option. A partial report should be treated as incomplete evidence.

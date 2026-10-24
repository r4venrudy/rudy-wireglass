# Report format

Text output is intended for a human reviewing a capture. JSON output uses schema identifier rudy-wireglass/v1 and is intended for scripts, case-note pipelines, and test fixtures.

## Top-level fields

- capture: format, packet/byte counters, link types, flow and DNS counts, and configured-bound indicators.
- flows: bidirectional conversation records. a and b are canonical endpoint order, so packet direction counts refer to that order, not presumed client/server roles.
- dns: individual observed DNS query or response messages. Responses are not yet correlated to their request.
- findings: review leads with stable rule_id, severity, evidence text, and optional flow/DNS index.
- error: empty on success; parse errors are returned through stderr and process status 2.

first_seen and last_seen are capture timestamps in seconds. A zero timestamp may mean the PCAPNG Simple Packet Block had no timestamp. bytes_a_to_b and bytes_b_to_a count decoded layer-3 packet lengths, not Ethernet framing bytes. The tool reports only metadata visible in the capture; encrypted application payload is not decrypted.

## Exit status

| Status | Meaning |
| --- | --- |
| 0 | Capture parsed and report written; strict mode had no findings |
| 1 | strict mode was selected and at least one configured heuristic emitted a finding |
| 2 | Invalid arguments, unreadable/malformed capture, or report write failure |

Packet-level truncation and unsupported protocols are counted in an otherwise successful report. A file-level structural error stops the scan and returns 2.

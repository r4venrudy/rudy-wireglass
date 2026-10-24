# Security policy

Rudy Wireglass processes untrusted capture files. The parser uses bounded capture, packet, flow, DNS, and stream limits. Please report reproducible parser crashes or memory-safety issues privately through GitHub's **Report a vulnerability** flow for this repository. Include the affected version, operating system, and a minimal sanitized capture where possible. Do not attach confidential production traffic to a public issue.

Wireglass is an offline defensive analysis tool. It does not open network sockets, transmit packets, inject traffic, or modify captures.

#ifndef RUDY_WIREGLASS_H
#define RUDY_WIREGLASS_H

#include <stddef.h>
#include <stdint.h>

#define WG_VERSION "0.1.0-preview"
#define WG_NAME "Rudy Wireglass"

typedef enum {
    WG_SEV_INFO = 0,
    WG_SEV_LOW = 1,
    WG_SEV_MEDIUM = 2,
    WG_SEV_HIGH = 3
} wg_severity;

typedef struct {
    uint64_t max_file_bytes;
    uint64_t max_packets;
    uint32_t max_flows;
    uint32_t max_dns_events;
    uint32_t max_findings;
    uint32_t max_stream_bytes;
} wg_limits;

typedef struct {
    uint8_t family;
    uint8_t protocol;
    uint8_t address[2][16];
    uint16_t port[2];
    uint64_t packets[2];
    uint64_t bytes[2];
    double first_seen;
    double last_seen;
    double interval_mean;
    double interval_m2;
    uint32_t interval_count;
    uint32_t syn_count;
    uint32_t fin_count;
    uint32_t rst_count;
    uint32_t stream_gaps;
    char tls_sni[256];
    char tls_alpn[128];
    char http_host[256];
    uint8_t *stream[2];
    uint32_t stream_len[2];
    uint32_t stream_cap[2];
    uint32_t next_seq[2];
    uint8_t seq_set[2];
    uint8_t used;
} wg_flow;

typedef struct {
    char query[256];
    char answers[384];
    char src[64];
    char dst[64];
    uint16_t id;
    uint16_t qtype;
    uint8_t is_response;
    uint8_t rcode;
    uint16_t answer_count;
    double timestamp;
} wg_dns_event;

typedef struct {
    char rule_id[48];
    char title[96];
    char detail[320];
    wg_severity severity;
    int32_t flow_index;
    int32_t dns_index;
} wg_finding;

typedef struct {
    char capture_format[16];
    char error[256];
    uint64_t packets_seen;
    uint64_t packets_decoded;
    uint64_t packets_truncated;
    uint64_t packets_unsupported;
    uint64_t bytes_captured;
    uint64_t ipv4_packets;
    uint64_t ipv6_packets;
    uint64_t tcp_packets;
    uint64_t udp_packets;
    uint32_t linktype_count;
    uint32_t linktypes[16];
    wg_flow *flows;
    uint32_t flow_count;
    uint32_t flow_capacity;
    wg_dns_event *dns_events;
    uint32_t dns_count;
    uint32_t dns_capacity;
    wg_finding *findings;
    uint32_t finding_count;
    uint32_t finding_capacity;
    uint8_t flow_limit_hit;
    uint8_t stopped_at_packet_limit;
} wg_report;

void wg_limits_default(wg_limits *limits);
int wg_analyze_file(const char *path, const wg_limits *limits, wg_report *report);
void wg_report_free(wg_report *report);
int wg_write_json(const wg_report *report, const char *path);
int wg_write_text(const wg_report *report, const char *path);

#endif

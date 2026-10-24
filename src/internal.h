#ifndef WG_INTERNAL_H
#define WG_INTERNAL_H

#include "wireglass.h"
#include <stdio.h>

typedef struct {
    uint32_t linktype;
    double ts_scale;
    int64_t ts_offset;
} wg_interface;

typedef struct {
    wg_report *report;
    const wg_limits *limits;
    uint32_t interface_count;
    wg_interface interfaces[256];
    uint64_t stream_bytes_used;
    uint64_t max_total_stream_bytes;
    uint8_t stopped;
} wg_context;

uint16_t wg_u16(const uint8_t *p, int little);
uint32_t wg_u32(const uint8_t *p, int little);
uint64_t wg_u64(const uint8_t *p, int little);
void wg_add_linktype(wg_report *r, uint32_t linktype);
int wg_parse_pcap(wg_context *ctx, FILE *f, const uint8_t first[4]);
int wg_parse_pcapng(wg_context *ctx, FILE *f, const uint8_t first[4]);
void wg_process_packet(wg_context *ctx, uint32_t linktype, const uint8_t *data,
                       uint32_t caplen, uint32_t wirelen, double timestamp);
void wg_add_finding(wg_report *r, const char *rule, wg_severity severity,
                    const char *title, const char *detail, int flow_index,
                    int dns_index);
void wg_finalize_findings(wg_report *r);
int wg_json_string(FILE *f, const char *s);

#endif

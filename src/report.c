#include "internal.h"

#include <ctype.h>
#include <string.h>

static const char *severity_name(wg_severity s) {
    switch (s) {
        case WG_SEV_HIGH: return "high";
        case WG_SEV_MEDIUM: return "medium";
        case WG_SEV_LOW: return "low";
        default: return "info";
    }
}

static const char *protocol_name(uint8_t p) {
    return p == 6 ? "tcp" : p == 17 ? "udp" : "ip";
}

static void endpoint(const wg_flow *f, int side, char *out, size_t cap) {
    char addr[64];
    if (f->family == 4) {
        snprintf(addr, sizeof(addr), "%u.%u.%u.%u", f->address[side][0],
                 f->address[side][1], f->address[side][2], f->address[side][3]);
    } else {
        size_t p = 0, i;
        for (i = 0; i < 16; i += 2) {
            int n = snprintf(addr + p, sizeof(addr) - p, "%s%x", i ? ":" : "",
                             ((unsigned)f->address[side][i] << 8) | f->address[side][i + 1]);
            if (n < 0 || (size_t)n >= sizeof(addr) - p) break;
            p += (size_t)n;
        }
    }
    snprintf(out, cap, "%s:%u", addr, (unsigned)f->port[side]);
}

int wg_json_string(FILE *f, const char *s) {
    const unsigned char *p = (const unsigned char *)(s ? s : "");
    if (fputc('"', f) == EOF) return 0;
    while (*p) {
        unsigned char c = *p++;
        switch (c) {
            case '"': if (fputs("\\\"", f) == EOF) return 0; break;
            case '\\': if (fputs("\\\\", f) == EOF) return 0; break;
            case '\b': if (fputs("\\b", f) == EOF) return 0; break;
            case '\f': if (fputs("\\f", f) == EOF) return 0; break;
            case '\n': if (fputs("\\n", f) == EOF) return 0; break;
            case '\r': if (fputs("\\r", f) == EOF) return 0; break;
            case '\t': if (fputs("\\t", f) == EOF) return 0; break;
            default:
                if (c < 0x20 || c >= 0x7f) {
                    if (fprintf(f, "\\u%04x", (unsigned)c) < 0) return 0;
                } else if (fputc(c, f) == EOF) return 0;
        }
    }
    return fputc('"', f) != EOF;
}

static FILE *open_output(const char *path, int *close_after) {
    if (!path || strcmp(path, "-") == 0) {
        *close_after = 0;
        return stdout;
    }
    *close_after = 1;
    return fopen(path, "wb");
}

int wg_write_json(const wg_report *r, const char *path) {
    int close_after, first, write_ok;
    FILE *f;
    if (!r || !path) return 0;
    f = open_output(path, &close_after);
    uint32_t i;
    if (!f) return 0;
    fprintf(f, "{\n  \"schema\":\"rudy-wireglass/v1\",\n  \"version\":\"%s\",\n  \"capture\":{\"format\":", WG_VERSION);
    wg_json_string(f, r->capture_format);
    fprintf(f, ",\"packets_seen\":%llu,\"packets_decoded\":%llu,\"packets_truncated\":%llu,\"packets_unsupported\":%llu,\"bytes_captured\":%llu,\"ipv4\":%llu,\"ipv6\":%llu,\"tcp\":%llu,\"udp\":%llu,\"flow_count\":%u,\"dns_event_count\":%u,\"flow_limit_hit\":%s,\"packet_limit_hit\":%s},\n",
            (unsigned long long)r->packets_seen, (unsigned long long)r->packets_decoded,
            (unsigned long long)r->packets_truncated, (unsigned long long)r->packets_unsupported,
            (unsigned long long)r->bytes_captured, (unsigned long long)r->ipv4_packets,
            (unsigned long long)r->ipv6_packets, (unsigned long long)r->tcp_packets,
            (unsigned long long)r->udp_packets, r->flow_count, r->dns_count,
            r->flow_limit_hit ? "true" : "false", r->stopped_at_packet_limit ? "true" : "false");
    fprintf(f, "  \"linktypes\":[");
    for (i = 0; i < r->linktype_count; ++i) fprintf(f, "%s%u", i ? "," : "", r->linktypes[i]);
    fprintf(f, "],\n  \"flows\":[");
    first = 1;
    for (i = 0; i < r->flow_capacity; ++i) {
        const wg_flow *flow = &r->flows[i];
        char a[96], b[96];
        if (!flow->used) continue;
        endpoint(flow, 0, a, sizeof(a)); endpoint(flow, 1, b, sizeof(b));
        fprintf(f, "%s\n    {\"index\":%u,\"family\":%u,\"protocol\":\"%s\",\"a\":",
                first ? "" : ",", i, flow->family, protocol_name(flow->protocol));
        wg_json_string(f, a); fprintf(f, ",\"b\":"); wg_json_string(f, b);
        fprintf(f, ",\"packets_a_to_b\":%llu,\"packets_b_to_a\":%llu,\"bytes_a_to_b\":%llu,\"bytes_b_to_a\":%llu,\"first_seen\":%.6f,\"last_seen\":%.6f,\"syn\":%u,\"fin\":%u,\"rst\":%u,\"stream_gaps\":%u,\"tls_sni\":",
                (unsigned long long)flow->packets[0], (unsigned long long)flow->packets[1],
                (unsigned long long)flow->bytes[0], (unsigned long long)flow->bytes[1],
                flow->first_seen, flow->last_seen, flow->syn_count, flow->fin_count,
                flow->rst_count, flow->stream_gaps);
        wg_json_string(f, flow->tls_sni); fprintf(f, ",\"tls_alpn\":"); wg_json_string(f, flow->tls_alpn);
        fprintf(f, ",\"http_host\":"); wg_json_string(f, flow->http_host); fputc('}', f);
        first = 0;
    }
    fprintf(f, "\n  ],\n  \"dns\":[");
    for (i = 0; i < r->dns_count; ++i) {
        const wg_dns_event *d = &r->dns_events[i];
        fprintf(f, "%s\n    {\"id\":%u,\"query\":", i ? "," : "", d->id);
        wg_json_string(f, d->query); fprintf(f, ",\"qtype\":%u,\"response\":%s,\"rcode\":%u,\"answer_count\":%u,\"answers\":",
                d->qtype, d->is_response ? "true" : "false", d->rcode, d->answer_count);
        wg_json_string(f, d->answers); fprintf(f, ",\"src\":"); wg_json_string(f, d->src);
        fprintf(f, ",\"dst\":"); wg_json_string(f, d->dst); fprintf(f, ",\"timestamp\":%.6f}", d->timestamp);
    }
    fprintf(f, "\n  ],\n  \"findings\":[");
    for (i = 0; i < r->finding_count; ++i) {
        const wg_finding *x = &r->findings[i];
        fprintf(f, "%s\n    {\"rule_id\":", i ? "," : ""); wg_json_string(f, x->rule_id);
        fprintf(f, ",\"severity\":"); wg_json_string(f, severity_name(x->severity));
        fprintf(f, ",\"title\":"); wg_json_string(f, x->title);
        fprintf(f, ",\"detail\":"); wg_json_string(f, x->detail);
        fprintf(f, ",\"flow_index\":%d,\"dns_index\":%d}", x->flow_index, x->dns_index);
    }
    fprintf(f, "\n  ],\n  \"error\":"); wg_json_string(f, r->error);
    fprintf(f, "\n}\n");
    write_ok = !ferror(f);
    if (close_after && fclose(f) != 0) write_ok = 0;
    return write_ok;
}

int wg_write_text(const wg_report *r, const char *path) {
    int close_after, rc = 1;
    FILE *f;
    if (!r || !path) return 0;
    f = open_output(path, &close_after);
    uint32_t i;
    if (!f) return 0;
    fprintf(f, "Rudy Wireglass %s - offline capture review\n", WG_VERSION);
    fprintf(f, "Capture: %s | packets: %llu seen, %llu decoded | IPv4: %llu | IPv6: %llu | TCP: %llu | UDP: %llu\n",
            r->capture_format, (unsigned long long)r->packets_seen,
            (unsigned long long)r->packets_decoded, (unsigned long long)r->ipv4_packets,
            (unsigned long long)r->ipv6_packets, (unsigned long long)r->tcp_packets,
            (unsigned long long)r->udp_packets);
    fprintf(f, "Flows: %u | DNS messages: %u | truncated: %llu | unsupported: %llu\n",
            r->flow_count, r->dns_count, (unsigned long long)r->packets_truncated,
            (unsigned long long)r->packets_unsupported);
    if (r->error[0]) fprintf(f, "Capture warning/error: %s\n", r->error);
    if (r->flow_limit_hit) fputs("Flow limit reached; remaining conversations were not recorded.\n", f);
    if (r->stopped_at_packet_limit) fputs("Packet limit reached; analysis stopped at the configured bound.\n", f);
    fputs("\nFLOWS\n-----\n", f);
    for (i = 0; i < r->flow_capacity; ++i) {
        const wg_flow *flow = &r->flows[i];
        char a[96], b[96];
        if (!flow->used) continue;
        endpoint(flow, 0, a, sizeof(a)); endpoint(flow, 1, b, sizeof(b));
        fprintf(f, "%s %s <-> %s | packets %llu/%llu | bytes %llu/%llu | %.3f to %.3f s",
                protocol_name(flow->protocol), a, b, (unsigned long long)flow->packets[0],
                (unsigned long long)flow->packets[1], (unsigned long long)flow->bytes[0],
                (unsigned long long)flow->bytes[1], flow->first_seen, flow->last_seen);
        if (flow->tls_sni[0]) fprintf(f, " | TLS SNI %s", flow->tls_sni);
        if (flow->tls_alpn[0]) fprintf(f, " | ALPN %s", flow->tls_alpn);
        if (flow->http_host[0]) fprintf(f, " | HTTP Host %s", flow->http_host);
        if (flow->rst_count) fprintf(f, " | RST %u", flow->rst_count);
        fputc('\n', f);
    }
    fputs("\nDNS\n---\n", f);
    for (i = 0; i < r->dns_count; ++i) {
        const wg_dns_event *d = &r->dns_events[i];
        fprintf(f, "%s %s (type %u, id %u, rcode %u)", d->is_response ? "RESPONSE" : "QUERY",
                d->query, d->qtype, d->id, d->rcode);
        if (d->answers[0]) fprintf(f, " -> %s", d->answers);
        fputc('\n', f);
    }
    fputs("\nINDICATORS - triage leads, not verdicts\n---------------------------------------\n", f);
    for (i = 0; i < r->finding_count; ++i) {
        const wg_finding *x = &r->findings[i];
        fprintf(f, "[%s] %s (%s): %s\n", severity_name(x->severity), x->title, x->rule_id, x->detail);
    }
    if (!r->finding_count) fputs("No configured heuristic triggered. This does not establish that the capture is benign.\n", f);
    if (ferror(f)) rc = 0;
    if (close_after && fclose(f) != 0) rc = 0;
    return rc;
}

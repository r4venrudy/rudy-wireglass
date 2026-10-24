#include "internal.h"

#include <ctype.h>
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define WG_DLT_EN10MB 1u
#define WG_DLT_RAW_OLD 12u
#define WG_DLT_RAW 101u
#define WG_DLT_LINUX_SLL 113u
#define WG_DLT_IPV4 228u
#define WG_DLT_IPV6 229u
#define WG_DLT_LINUX_SLL2 276u

typedef struct {
    uint8_t family;
    uint8_t protocol;
    uint8_t src[16];
    uint8_t dst[16];
    uint16_t src_port;
    uint16_t dst_port;
    uint32_t seq;
    uint8_t tcp_flags;
    const uint8_t *payload;
    size_t payload_len;
    uint32_t l3_bytes;
} wg_packet_info;

static int is_vlan(uint16_t type) {
    return type == 0x8100 || type == 0x88a8 || type == 0x9100;
}

static void addr_text(uint8_t family, const uint8_t *addr, char *out, size_t cap) {
    size_t i;
    if (family == 4) {
        snprintf(out, cap, "%u.%u.%u.%u", addr[0], addr[1], addr[2], addr[3]);
        return;
    }
    if (family == 6) {
        size_t used = 0;
        for (i = 0; i < 16; i += 2) {
            int n = snprintf(out + used, cap - used, "%s%x", i ? ":" : "",
                             ((unsigned)addr[i] << 8) | addr[i + 1]);
            if (n < 0 || (size_t)n >= cap - used) break;
            used += (size_t)n;
        }
        return;
    }
    snprintf(out, cap, "?");
}

static int endpoint_compare(uint8_t family, const uint8_t *a, uint16_t ap,
                            const uint8_t *b, uint16_t bp) {
    int c = memcmp(a, b, family == 4 ? 4u : 16u);
    if (c != 0) return c;
    return ap < bp ? -1 : ap > bp ? 1 : 0;
}

static uint64_t flow_hash(uint8_t family, uint8_t protocol,
                          const uint8_t *a, uint16_t ap,
                          const uint8_t *b, uint16_t bp) {
    uint64_t h = UINT64_C(1469598103934665603);
    size_t n = family == 4 ? 4u : 16u, i;
    const uint8_t *parts[4] = {a, (const uint8_t *)&ap, b, (const uint8_t *)&bp};
    size_t sizes[4] = {n, 2, n, 2};
    h = (h ^ family) * UINT64_C(1099511628211);
    h = (h ^ protocol) * UINT64_C(1099511628211);
    for (i = 0; i < 4; ++i) {
        size_t j;
        for (j = 0; j < sizes[i]; ++j) h = (h ^ parts[i][j]) * UINT64_C(1099511628211);
    }
    return h;
}

static int flow_key_equal(const wg_flow *f, uint8_t family, uint8_t protocol,
                          const uint8_t *a, uint16_t ap,
                          const uint8_t *b, uint16_t bp) {
    return f->used && f->family == family && f->protocol == protocol &&
           f->port[0] == ap && f->port[1] == bp &&
           memcmp(f->address[0], a, family == 4 ? 4u : 16u) == 0 &&
           memcmp(f->address[1], b, family == 4 ? 4u : 16u) == 0;
}

static wg_flow *get_flow(wg_context *ctx, const wg_packet_info *p, int *direction,
                         int *flow_index) {
    wg_report *r = ctx->report;
    int order = endpoint_compare(p->family, p->src, p->src_port, p->dst, p->dst_port);
    const uint8_t *a = order <= 0 ? p->src : p->dst;
    const uint8_t *b = order <= 0 ? p->dst : p->src;
    uint16_t ap = order <= 0 ? p->src_port : p->dst_port;
    uint16_t bp = order <= 0 ? p->dst_port : p->src_port;
    uint64_t h = flow_hash(p->family, p->protocol, a, ap, b, bp);
    uint32_t i, start;
    start = (uint32_t)(h % r->flow_capacity);
    for (i = 0; i < r->flow_capacity; ++i) {
        uint32_t slot = (start + i) % r->flow_capacity;
        wg_flow *f = &r->flows[slot];
        if (!f->used) {
            if (r->flow_count >= r->flow_capacity) {
                r->flow_limit_hit = 1;
                return NULL;
            }
            memset(f, 0, sizeof(*f));
            f->used = 1;
            f->family = p->family;
            f->protocol = p->protocol;
            memcpy(f->address[0], a, p->family == 4 ? 4u : 16u);
            memcpy(f->address[1], b, p->family == 4 ? 4u : 16u);
            f->port[0] = ap;
            f->port[1] = bp;
            f->first_seen = p->payload_len || p->l3_bytes ? -1.0 : 0.0;
            r->flow_count++;
            *direction = order <= 0 ? 0 : 1;
            *flow_index = (int)slot;
            return f;
        }
        if (flow_key_equal(f, p->family, p->protocol, a, ap, b, bp)) {
            *direction = order <= 0 ? 0 : 1;
            *flow_index = (int)slot;
            return f;
        }
    }
    r->flow_limit_hit = 1;
    return NULL;
}

static int dns_read_name(const uint8_t *msg, size_t length, size_t offset,
                         char *out, size_t outcap, size_t *consumed) {
    size_t p = offset, used = 0, original = 0;
    unsigned jumps = 0;
    int jumped = 0;
    while (p < length) {
        uint8_t n = msg[p++];
        if ((n & 0xc0u) == 0xc0u) {
            uint16_t pointer;
            if (p >= length || ++jumps > 32) return 0;
            pointer = (uint16_t)(((n & 0x3fu) << 8) | msg[p++]);
            if (pointer >= length) return 0;
            if (!jumped) original = p - offset;
            jumped = 1;
            p = pointer;
            continue;
        }
        if ((n & 0xc0u) != 0 || n > 63) return 0;
        if (n == 0) {
            if (!jumped) original = p - offset;
            if (used == 0) {
                if (outcap < 2) return 0;
                out[used++] = '.';
            }
            out[used] = '\0';
            *consumed = original;
            return 1;
        }
        if (p + n > length || used + n + 2 >= outcap) return 0;
        if (used) out[used++] = '.';
        memcpy(out + used, msg + p, n);
        used += n;
        p += n;
        if (!jumped) original = p - offset;
    }
    return 0;
}

static double label_entropy(const char *s) {
    unsigned counts[256] = {0};
    size_t n = 0, i;
    double e = 0.0;
    for (i = 0; s[i] && s[i] != '.'; ++i) {
        counts[(unsigned char)s[i]]++;
        n++;
    }
    if (n == 0) return 0.0;
    for (i = 0; i < 256; ++i) if (counts[i]) {
        double p = (double)counts[i] / (double)n;
        e -= p * (log(p) / log(2.0));
    }
    return e;
}

static void dns_event(wg_context *ctx, const wg_packet_info *p, double ts) {
    const uint8_t *m = p->payload;
    size_t n = p->payload_len, qend, used, pos;
    uint16_t qd, an, flags, type;
    char qname[256], answers[384] = "";
    wg_dns_event *ev;
    char src[64], dst[64];
    uint32_t i, emitted = 0;
    if (n < 12 || ctx->report->dns_count >= ctx->report->dns_capacity) return;
    flags = (uint16_t)((m[2] << 8) | m[3]);
    qd = (uint16_t)((m[4] << 8) | m[5]);
    an = (uint16_t)((m[6] << 8) | m[7]);
    if (qd == 0 || qd > 16) return;
    if (!dns_read_name(m, n, 12, qname, sizeof(qname), &used)) return;
    qend = 12 + used;
    if (qend + 4 > n) return;
    type = (uint16_t)((m[qend] << 8) | m[qend + 1]);
    pos = 12;
    if ((flags & 0x8000u) != 0) {
        for (i = 0; i < qd; ++i) {
            char ignored[256];
            size_t skip;
            if (!dns_read_name(m, n, pos, ignored, sizeof(ignored), &skip) || pos + skip + 4 > n) return;
            pos += skip + 4;
        }
        for (i = 0; i < an && i < 128; ++i) {
            char rrname[256];
            size_t skip;
            uint16_t rrtype, rdlen;
            if (!dns_read_name(m, n, pos, rrname, sizeof(rrname), &skip) || pos + skip + 10 > n) break;
            pos += skip;
            rrtype = (uint16_t)((m[pos] << 8) | m[pos + 1]);
            rdlen = (uint16_t)((m[pos + 8] << 8) | m[pos + 9]);
            pos += 10;
            if (pos + rdlen > n) break;
            if (rrtype == 1 && rdlen == 4) {
                char ip[64];
                snprintf(ip, sizeof(ip), "%u.%u.%u.%u", m[pos], m[pos + 1], m[pos + 2], m[pos + 3]);
                if (emitted++) strncat(answers, ", ", sizeof(answers) - strlen(answers) - 1);
                strncat(answers, ip, sizeof(answers) - strlen(answers) - 1);
            } else if (rrtype == 28 && rdlen == 16) {
                char ip[64];
                addr_text(6, m + pos, ip, sizeof(ip));
                if (emitted++) strncat(answers, ", ", sizeof(answers) - strlen(answers) - 1);
                strncat(answers, ip, sizeof(answers) - strlen(answers) - 1);
            }
            pos += rdlen;
        }
    }
    ev = &ctx->report->dns_events[ctx->report->dns_count++];
    memset(ev, 0, sizeof(*ev));
    snprintf(ev->query, sizeof(ev->query), "%s", qname);
    snprintf(ev->answers, sizeof(ev->answers), "%s", answers);
    addr_text(p->family, p->src, src, sizeof(src));
    addr_text(p->family, p->dst, dst, sizeof(dst));
    snprintf(ev->src, sizeof(ev->src), "%s", src);
    snprintf(ev->dst, sizeof(ev->dst), "%s", dst);
    ev->id = (uint16_t)((m[0] << 8) | m[1]);
    ev->qtype = type;
    ev->is_response = (uint8_t)((flags >> 15) & 1u);
    ev->rcode = (uint8_t)(flags & 0x0fu);
    ev->answer_count = an;
    ev->timestamp = ts;

    if (!ev->is_response) {
        size_t first_label = strcspn(qname, ".");
        double entropy = label_entropy(qname);
        if (first_label >= 35 && entropy >= 3.55) {
            char detail[320];
            uint32_t prior, count = 1;
            int existing = -1;
            for (prior = 0; prior + 1 < ctx->report->dns_count; ++prior)
                if (!ctx->report->dns_events[prior].is_response &&
                    strcmp(ctx->report->dns_events[prior].query, qname) == 0) count++;
            snprintf(detail, sizeof(detail), "query=%.120s; first-label=%u characters; Shannon entropy=%.2f bits/character; observed=%u. Review context; this signal is not proof of tunneling.",
                     qname, (unsigned)first_label, entropy, count);
            for (prior = 0; prior < ctx->report->finding_count; ++prior) {
                wg_finding *old = &ctx->report->findings[prior];
                if (strcmp(old->rule_id, "DNS.HIGH_ENTROPY_LABEL") == 0 && old->dns_index >= 0 &&
                    (uint32_t)old->dns_index < ctx->report->dns_count &&
                    strcmp(ctx->report->dns_events[old->dns_index].query, qname) == 0) {
                    existing = (int)prior;
                    break;
                }
            }
            if (existing >= 0) {
                snprintf(ctx->report->findings[existing].detail,
                         sizeof(ctx->report->findings[existing].detail), "%s", detail);
            } else {
                wg_add_finding(ctx->report, "DNS.HIGH_ENTROPY_LABEL", WG_SEV_MEDIUM,
                               "Long high-entropy DNS label", detail, -1,
                               (int)(ctx->report->dns_count - 1));
            }
        }
    }
}

static int read_u24(const uint8_t *p) {
    return ((int)p[0] << 16) | ((int)p[1] << 8) | (int)p[2];
}

static void parse_tls_client_hello(wg_flow *f, int d) {
    const uint8_t *b = f->stream[d];
    size_t n = f->stream_len[d], p, end;
    uint16_t record_len, ext_len;
    if (n < 9 || b[0] != 22 || b[1] != 3 || b[5] != 1) return;
    record_len = (uint16_t)((b[3] << 8) | b[4]);
    if (record_len > 16384 || n < (size_t)record_len + 5) return;
    if (read_u24(b + 6) + 4 > (int)record_len) return;
    p = 9 + 2 + 32;
    if (p >= n) return;
    p += 1 + b[p];
    if (p + 2 > n) return;
    p += 2 + ((size_t)b[p] << 8) + b[p + 1];
    if (p >= n) return;
    p += 1 + b[p];
    if (p + 2 > n) return;
    ext_len = (uint16_t)((b[p] << 8) | b[p + 1]);
    p += 2;
    end = p + ext_len;
    if (end > (size_t)record_len + 5) return;
    while (p + 4 <= end) {
        uint16_t type = (uint16_t)((b[p] << 8) | b[p + 1]);
        uint16_t length = (uint16_t)((b[p + 2] << 8) | b[p + 3]);
        size_t q = p + 4, ext_end = q + length;
        if (ext_end > end) return;
        if (type == 0 && length >= 5) {
            uint16_t list_len = (uint16_t)((b[q] << 8) | b[q + 1]);
            uint16_t name_len;
            q += 2;
            if (q + 3 <= ext_end && b[q] == 0) {
                name_len = (uint16_t)((b[q + 1] << 8) | b[q + 2]);
                q += 3;
                if (name_len > 0 && q + name_len <= ext_end && name_len < sizeof(f->tls_sni)) {
                    memcpy(f->tls_sni, b + q, name_len);
                    f->tls_sni[name_len] = '\0';
                }
            }
            (void)list_len;
        } else if (type == 16 && length >= 3) {
            uint16_t list_len = (uint16_t)((b[q] << 8) | b[q + 1]);
            uint8_t alpn_len;
            q += 2;
            if (q < ext_end) {
                alpn_len = b[q++];
                if (alpn_len > 0 && q + alpn_len <= ext_end && alpn_len < sizeof(f->tls_alpn)) {
                    memcpy(f->tls_alpn, b + q, alpn_len);
                    f->tls_alpn[alpn_len] = '\0';
                }
            }
            (void)list_len;
        }
        p = ext_end;
    }
}

static int ascii_equal(char a, char b) {
    return tolower((unsigned char)a) == tolower((unsigned char)b);
}

static void parse_http_host(wg_flow *f, int d) {
    const uint8_t *b = f->stream[d];
    size_t n = f->stream_len[d], i, j;
    if (n < 8 || f->http_host[0]) return;
    for (i = 0; i + 6 < n; ++i) {
        if (i > 0 && !(b[i - 1] == '\n')) continue;
        if (ascii_equal((char)b[i], 'h') && ascii_equal((char)b[i + 1], 'o') &&
            ascii_equal((char)b[i + 2], 's') && ascii_equal((char)b[i + 3], 't') && b[i + 4] == ':') {
            j = i + 5;
            while (j < n && (b[j] == ' ' || b[j] == '\t')) ++j;
            size_t start = j;
            while (j < n && b[j] != '\r' && b[j] != '\n' && j - start < sizeof(f->http_host) - 1) ++j;
            if (j > start) {
                memcpy(f->http_host, b + start, j - start);
                f->http_host[j - start] = '\0';
                return;
            }
        }
    }
}

static void append_stream(wg_context *ctx, wg_flow *f, int d, uint32_t seq,
                          const uint8_t *payload, size_t length, uint16_t srcport,
                          uint16_t dstport) {
    uint32_t max = ctx->limits->max_stream_bytes;
    uint32_t expected;
    size_t skip = 0, amount;
    if (length == 0 || max == 0) return;
    if (!f->seq_set[d]) {
        f->seq_set[d] = 1;
        f->next_seq[d] = seq;
    }
    expected = f->next_seq[d];
    if (seq != expected) {
        int32_t diff = (int32_t)(seq - expected);
        if (diff < 0) {
            uint32_t overlap = (uint32_t)(expected - seq);
            if (overlap >= length) return; /* exact retransmission or already-covered bytes */
            skip = overlap;
        } else {
            f->stream_gaps++;
            f->stream_len[d] = 0;
            f->next_seq[d] = seq;
        }
    }
    amount = length - skip;
    if (amount > max - (f->stream_len[d] < max ? f->stream_len[d] : max))
        amount = max - (f->stream_len[d] < max ? f->stream_len[d] : max);
    if (amount == 0) return;
    if (f->stream_cap[d] < f->stream_len[d] + amount) {
        uint32_t want = f->stream_cap[d] ? f->stream_cap[d] : 256;
        uint8_t *next;
        while (want < f->stream_len[d] + amount && want < max) {
            uint32_t doubled = want > max / 2 ? max : want * 2;
            if (doubled == want) break;
            want = doubled;
        }
        if (want > max) want = max;
        if (ctx->stream_bytes_used + (uint64_t)(want - f->stream_cap[d]) > ctx->max_total_stream_bytes)
            return;
        next = (uint8_t *)realloc(f->stream[d], want);
        if (!next) return;
        ctx->stream_bytes_used += (uint64_t)(want - f->stream_cap[d]);
        f->stream[d] = next;
        f->stream_cap[d] = want;
    }
    memcpy(f->stream[d] + f->stream_len[d], payload + skip, amount);
    f->stream_len[d] += (uint32_t)amount;
    f->next_seq[d] = seq + (uint32_t)length;
    if (srcport == 80 || dstport == 80) parse_http_host(f, d);
    if (srcport == 443 || dstport == 443 || srcport == 8443 || dstport == 8443)
        parse_tls_client_hello(f, d);
}

static void update_flow(wg_context *ctx, const wg_packet_info *p, double ts) {
    wg_flow *f;
    int d, slot;
    char src[64], dst[64];
    f = get_flow(ctx, p, &d, &slot);
    if (!f) return;
    if (f->first_seen < 0.0) f->first_seen = ts;
    if (f->last_seen > 0.0 && ts > f->last_seen) {
        double interval = ts - f->last_seen;
        double delta;
        f->interval_count++;
        delta = interval - f->interval_mean;
        f->interval_mean += delta / (double)f->interval_count;
        f->interval_m2 += delta * (interval - f->interval_mean);
    }
    if (ts > f->last_seen) f->last_seen = ts;
    f->packets[d]++;
    f->bytes[d] += p->l3_bytes;
    if (p->protocol == 6) {
        if (p->tcp_flags & 0x02) f->syn_count++;
        if (p->tcp_flags & 0x01) f->fin_count++;
        if (p->tcp_flags & 0x04) f->rst_count++;
        if (p->payload_len) append_stream(ctx, f, d, p->seq + ((p->tcp_flags & 0x02) ? 1u : 0u),
                                          p->payload, p->payload_len, p->src_port, p->dst_port);
    }
    addr_text(p->family, p->src, src, sizeof(src));
    addr_text(p->family, p->dst, dst, sizeof(dst));
    (void)src;
    (void)dst;
    (void)slot;
}

static int parse_ipv4(const uint8_t *b, size_t n, wg_packet_info *p) {
    size_t ihl, total;
    uint16_t frag;
    if (n < 20 || (b[0] >> 4) != 4) return 0;
    ihl = (size_t)(b[0] & 0x0fu) * 4;
    total = ((size_t)b[2] << 8) | b[3];
    if (ihl < 20 || ihl > n || total < ihl || total > n) return -1;
    frag = (uint16_t)((b[6] << 8) | b[7]);
    if ((frag & 0x1fffu) != 0) return -2;
    memset(p, 0, sizeof(*p));
    p->family = 4;
    p->protocol = b[9];
    memcpy(p->src, b + 12, 4);
    memcpy(p->dst, b + 16, 4);
    p->payload = b + ihl;
    p->payload_len = total - ihl;
    p->l3_bytes = (uint32_t)total;
    return 1;
}

static int parse_ipv6(const uint8_t *b, size_t n, wg_packet_info *p) {
    size_t total, off = 40;
    uint8_t next;
    unsigned extensions = 0;
    if (n < 40 || (b[0] >> 4) != 6) return 0;
    total = 40u + (((size_t)b[4] << 8) | b[5]);
    if (total > n) return -1;
    memset(p, 0, sizeof(*p));
    p->family = 6;
    memcpy(p->src, b + 8, 16);
    memcpy(p->dst, b + 24, 16);
    next = b[6];
    while (next == 0 || next == 43 || next == 60 || next == 51 || next == 44) {
        size_t extlen;
        if (++extensions > 8 || off + 2 > total) return -1;
        if (next == 44) {
            uint16_t frag;
            if (off + 8 > total) return -1;
            frag = (uint16_t)((b[off + 2] << 8) | b[off + 3]);
            if ((frag & 0xfff8u) != 0) return -2;
            extlen = 8;
        } else if (next == 51) {
            extlen = ((size_t)b[off + 1] + 2u) * 4u;
        } else {
            extlen = ((size_t)b[off + 1] + 1u) * 8u;
        }
        if (extlen < 8 || off + extlen > total) return -1;
        next = b[off];
        off += extlen;
    }
    if (next == 50) return -2; /* ESP payload is encrypted */
    p->protocol = next;
    p->payload = b + off;
    p->payload_len = total - off;
    p->l3_bytes = (uint32_t)total;
    return 1;
}

static void parse_transport(wg_context *ctx, wg_packet_info *p, double ts) {
    size_t hdr;
    if (p->protocol == 6) {
        if (p->payload_len < 20) { ctx->report->packets_truncated++; return; }
        p->src_port = (uint16_t)((p->payload[0] << 8) | p->payload[1]);
        p->dst_port = (uint16_t)((p->payload[2] << 8) | p->payload[3]);
        p->seq = ((uint32_t)p->payload[4] << 24) | ((uint32_t)p->payload[5] << 16) |
                 ((uint32_t)p->payload[6] << 8) | p->payload[7];
        hdr = (size_t)(p->payload[12] >> 4) * 4;
        p->tcp_flags = p->payload[13];
        if (hdr < 20 || hdr > p->payload_len) { ctx->report->packets_truncated++; return; }
        p->payload += hdr;
        p->payload_len -= hdr;
        ctx->report->tcp_packets++;
        update_flow(ctx, p, ts);
    } else if (p->protocol == 17) {
        uint16_t udp_len;
        if (p->payload_len < 8) { ctx->report->packets_truncated++; return; }
        p->src_port = (uint16_t)((p->payload[0] << 8) | p->payload[1]);
        p->dst_port = (uint16_t)((p->payload[2] << 8) | p->payload[3]);
        udp_len = (uint16_t)((p->payload[4] << 8) | p->payload[5]);
        if (udp_len < 8 || udp_len > p->payload_len) { ctx->report->packets_truncated++; return; }
        p->payload += 8;
        p->payload_len = udp_len - 8;
        ctx->report->udp_packets++;
        if (p->src_port == 53 || p->dst_port == 53) dns_event(ctx, p, ts);
        update_flow(ctx, p, ts);
    }
}

void wg_process_packet(wg_context *ctx, uint32_t linktype, const uint8_t *data,
                       uint32_t caplen, uint32_t wirelen, double timestamp) {
    size_t off = 0;
    uint16_t ethertype = 0;
    wg_packet_info p;
    int rc;
    (void)wirelen;
    if (ctx->report->packets_seen >= ctx->limits->max_packets) {
        ctx->report->stopped_at_packet_limit = 1;
        ctx->stopped = 1;
        return;
    }
    ctx->report->packets_seen++;
    ctx->report->bytes_captured += caplen;

    if (linktype == WG_DLT_EN10MB) {
        if (caplen < 14) { ctx->report->packets_truncated++; return; }
        ethertype = (uint16_t)((data[12] << 8) | data[13]);
        off = 14;
        while (is_vlan(ethertype) && off + 4 <= caplen) {
            ethertype = (uint16_t)((data[off + 2] << 8) | data[off + 3]);
            off += 4;
        }
    } else if (linktype == WG_DLT_LINUX_SLL) {
        if (caplen < 16) { ctx->report->packets_truncated++; return; }
        ethertype = (uint16_t)((data[14] << 8) | data[15]);
        off = 16;
    } else if (linktype == WG_DLT_LINUX_SLL2) {
        if (caplen < 20) { ctx->report->packets_truncated++; return; }
        ethertype = (uint16_t)((data[0] << 8) | data[1]);
        off = 20;
    } else if (linktype == WG_DLT_RAW || linktype == WG_DLT_RAW_OLD) {
        if (caplen == 0) { ctx->report->packets_truncated++; return; }
        ethertype = (data[0] >> 4) == 4 ? 0x0800 : (data[0] >> 4) == 6 ? 0x86dd : 0;
    } else if (linktype == WG_DLT_IPV4) {
        ethertype = 0x0800;
    } else if (linktype == WG_DLT_IPV6) {
        ethertype = 0x86dd;
    } else {
        ctx->report->packets_unsupported++;
        return;
    }

    if (ethertype == 0x0800) {
        rc = parse_ipv4(data + off, caplen - off, &p);
        if (rc <= 0) {
            if (rc == -1) ctx->report->packets_truncated++;
            else if (rc == -2) ctx->report->packets_unsupported++;
            return;
        }
        ctx->report->ipv4_packets++;
    } else if (ethertype == 0x86dd) {
        rc = parse_ipv6(data + off, caplen - off, &p);
        if (rc <= 0) {
            if (rc == -1) ctx->report->packets_truncated++;
            else if (rc == -2) ctx->report->packets_unsupported++;
            return;
        }
        ctx->report->ipv6_packets++;
    } else {
        ctx->report->packets_unsupported++;
        return;
    }
    ctx->report->packets_decoded++;
    parse_transport(ctx, &p, timestamp);
}

void wg_finalize_findings(wg_report *r) {
    uint32_t i;
    for (i = 0; i < r->flow_capacity; ++i) {
        wg_flow *f = &r->flows[i];
        if (!f->used || f->interval_count < 6 || f->last_seen <= f->first_seen ||
            f->last_seen - f->first_seen < 30.0 || f->interval_mean <= 0.0) continue;
        {
            double variance = f->interval_m2 / (double)(f->interval_count > 1 ? f->interval_count - 1 : 1);
            double cv = sqrt(variance) / f->interval_mean;
            if (cv <= 0.15 && f->interval_mean <= 900.0) {
                char a[64], b[64], detail[320];
                addr_text(f->family, f->address[0], a, sizeof(a));
                addr_text(f->family, f->address[1], b, sizeof(b));
                snprintf(detail, sizeof(detail), "%s:%u <-> %s:%u; %u observed intervals; mean=%.2fs; coefficient-of-variation=%.3f. Regular timing can be benign; inspect process and asset context.",
                         a, f->port[0], b, f->port[1], f->interval_count, f->interval_mean, cv);
                wg_add_finding(r, "FLOW.PERIODIC_TIMING", WG_SEV_LOW,
                               "Regularly timed flow", detail, (int)i, -1);
            }
        }
    }
}

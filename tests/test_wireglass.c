#include "wireglass.h"

#ifdef NDEBUG
#undef NDEBUG
#endif
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void put16le(unsigned char *p, unsigned v) { p[0] = (unsigned char)v; p[1] = (unsigned char)(v >> 8); }
static void put32le(unsigned char *p, unsigned long v) {
    p[0] = (unsigned char)v; p[1] = (unsigned char)(v >> 8); p[2] = (unsigned char)(v >> 16); p[3] = (unsigned char)(v >> 24);
}
static void put16be(unsigned char *p, unsigned v) { p[0] = (unsigned char)(v >> 8); p[1] = (unsigned char)v; }
static void put32be(unsigned char *p, unsigned long v) {
    p[0] = (unsigned char)(v >> 24); p[1] = (unsigned char)(v >> 16); p[2] = (unsigned char)(v >> 8); p[3] = (unsigned char)v;
}

static size_t dns_message(unsigned char *out, unsigned id, int response, const char *name,
                          const unsigned char *answer) {
    size_t p = 12, i = 0;
    memset(out, 0, 512);
    put16be(out, id); put16be(out + 2, response ? 0x8180 : 0x0100);
    put16be(out + 4, 1); put16be(out + 6, response ? 1 : 0);
    while (name[i]) {
        size_t start = i;
        while (name[i] && name[i] != '.') ++i;
        out[p++] = (unsigned char)(i - start);
        memcpy(out + p, name + start, i - start); p += i - start;
        if (name[i] == '.') ++i;
    }
    out[p++] = 0; put16be(out + p, 1); p += 2; put16be(out + p, 1); p += 2;
    if (response) {
        out[p++] = 0xc0; out[p++] = 0x0c; put16be(out + p, 1); p += 2;
        put16be(out + p, 1); p += 2; put32be(out + p, 60); p += 4;
        put16be(out + p, 4); p += 2; memcpy(out + p, answer, 4); p += 4;
    }
    return p;
}

static size_t ethernet_ipv4_udp(unsigned char *out, const unsigned char *src,
                                const unsigned char *dst, unsigned sport, unsigned dport,
                                const unsigned char *payload, size_t payload_len) {
    size_t p = 14;
    memset(out, 0, 2048);
    memset(out, 0x11, 6); memset(out + 6, 0x22, 6); put16be(out + 12, 0x0800);
    out[p] = 0x45; put16be(out + p + 2, (unsigned)(20 + 8 + payload_len));
    out[p + 8] = 64; out[p + 9] = 17; memcpy(out + p + 12, src, 4); memcpy(out + p + 16, dst, 4);
    p += 20; put16be(out + p, sport); put16be(out + p + 2, dport);
    put16be(out + p + 4, (unsigned)(8 + payload_len)); p += 8;
    memcpy(out + p, payload, payload_len);
    return p + payload_len;
}

static size_t ethernet_ipv4_tcp(unsigned char *out, const unsigned char *src,
                                const unsigned char *dst, unsigned sport, unsigned dport,
                                unsigned long seq, unsigned flags, const unsigned char *payload,
                                size_t payload_len) {
    size_t p = 14;
    memset(out, 0, 2048);
    memset(out, 0x33, 6); memset(out + 6, 0x44, 6); put16be(out + 12, 0x0800);
    out[p] = 0x45; put16be(out + p + 2, (unsigned)(20 + 20 + payload_len));
    out[p + 8] = 64; out[p + 9] = 6; memcpy(out + p + 12, src, 4); memcpy(out + p + 16, dst, 4);
    p += 20; put16be(out + p, sport); put16be(out + p + 2, dport); put32be(out + p + 4, seq);
    out[p + 12] = 0x50; out[p + 13] = (unsigned char)flags; put16be(out + p + 14, 4096);
    p += 20; memcpy(out + p, payload, payload_len);
    return p + payload_len;
}

static size_t tls_client_hello(unsigned char *out) {
    const char sni[] = "example.net";
    const char alpn[] = "h2";
    unsigned char body[128], handshake[160];
    size_t p = 0, h = 0, i, ext_len_at;
    body[p++] = 3; body[p++] = 3;
    for (i = 0; i < 32; ++i) body[p++] = (unsigned char)i;
    body[p++] = 0; /* session id */
    put16be(body + p, 2); p += 2; put16be(body + p, 0x1301); p += 2;
    body[p++] = 1; body[p++] = 0;
    ext_len_at = p; p += 2;
    put16be(body + p, 0); put16be(body + p + 2, (unsigned)(5 + sizeof(sni) - 1)); p += 4;
    put16be(body + p, (unsigned)(3 + sizeof(sni) - 1)); p += 2;
    body[p++] = 0; put16be(body + p, (unsigned)(sizeof(sni) - 1)); p += 2;
    memcpy(body + p, sni, sizeof(sni) - 1); p += sizeof(sni) - 1;
    put16be(body + p, 16); put16be(body + p + 2, (unsigned)(3 + sizeof(alpn) - 1)); p += 4;
    put16be(body + p, (unsigned)sizeof(alpn)); p += 2;
    body[p++] = (unsigned char)(sizeof(alpn) - 1); memcpy(body + p, alpn, sizeof(alpn) - 1); p += sizeof(alpn) - 1;
    put16be(body + ext_len_at, (unsigned)(p - ext_len_at - 2));
    handshake[h++] = 1; handshake[h++] = (unsigned char)(p >> 16);
    handshake[h++] = (unsigned char)(p >> 8); handshake[h++] = (unsigned char)p;
    memcpy(handshake + h, body, p); h += p;
    out[0] = 22; out[1] = 3; out[2] = 1; put16be(out + 3, (unsigned)h);
    memcpy(out + 5, handshake, h);
    return h + 5;
}

typedef struct { const unsigned char *data; size_t len; unsigned sec; unsigned usec; } frame;

static void write_pcap(const char *path, const frame *frames, size_t count) {
    FILE *f = fopen(path, "wb");
    unsigned char h[24], rh[16];
    size_t i;
    assert(f);
    memset(h, 0, sizeof(h)); memcpy(h, "\xd4\xc3\xb2\xa1", 4);
    put16le(h + 4, 2); put16le(h + 6, 4); put32le(h + 16, 65535); put32le(h + 20, 1);
    assert(fwrite(h, 1, sizeof(h), f) == sizeof(h));
    for (i = 0; i < count; ++i) {
        memset(rh, 0, sizeof(rh)); put32le(rh, frames[i].sec); put32le(rh + 4, frames[i].usec);
        put32le(rh + 8, frames[i].len); put32le(rh + 12, frames[i].len);
        assert(fwrite(rh, 1, sizeof(rh), f) == sizeof(rh));
        assert(fwrite(frames[i].data, 1, frames[i].len, f) == frames[i].len);
    }
    fclose(f);
}

static void write_block(FILE *f, unsigned type, const unsigned char *body, size_t body_len) {
    unsigned char h[8], t[4];
    unsigned total = (unsigned)(body_len + 12);
    put32le(h, type); put32le(h + 4, total); put32le(t, total);
    assert(fwrite(h, 1, 8, f) == 8);
    if (body_len) assert(fwrite(body, 1, body_len, f) == body_len);
    assert(fwrite(t, 1, 4, f) == 4);
}

static void write_block_be(FILE *f, unsigned type, const unsigned char *body, size_t body_len) {
    unsigned char h[8], t[4];
    unsigned total = (unsigned)(body_len + 12);
    put32be(h, type); put32be(h + 4, total); put32be(t, total);
    assert(fwrite(h, 1, 8, f) == 8);
    if (body_len) assert(fwrite(body, 1, body_len, f) == body_len);
    assert(fwrite(t, 1, 4, f) == 4);
}

static void write_pcapng(const char *path) {
    FILE *f = fopen(path, "wb");
    unsigned char shb[28], idb[20], epb[40], packet[14];
    assert(f);
    memset(shb, 0, sizeof(shb)); put32le(shb, 0x0a0d0d0a); put32le(shb + 4, 28);
    put32le(shb + 8, 0x1a2b3c4d); put16le(shb + 12, 1); put16le(shb + 14, 0); put32le(shb + 24, 28);
    assert(fwrite(shb, 1, sizeof(shb), f) == sizeof(shb));
    memset(idb, 0, sizeof(idb)); put16le(idb, 1); put32le(idb + 4, 65535);
    write_block(f, 1, idb, sizeof(idb));
    memset(packet, 0, sizeof(packet)); put16be(packet + 12, 0x0806);
    memset(epb, 0, sizeof(epb)); put32le(epb, 0); put32le(epb + 4, 0); put32le(epb + 8, 100000);
    put32le(epb + 12, sizeof(packet)); put32le(epb + 16, sizeof(packet)); memcpy(epb + 20, packet, sizeof(packet));
    write_block(f, 6, epb, sizeof(epb));
    fclose(f);
}

static void write_pcapng_big_endian(const char *path) {
    FILE *f = fopen(path, "wb");
    unsigned char shb[28], idb[8], epb[40], packet[14];
    assert(f);
    memset(shb, 0xff, sizeof(shb)); memcpy(shb, "\x0a\x0d\x0d\x0a", 4);
    put32be(shb + 4, 28); put32be(shb + 8, 0x1a2b3c4d);
    put16be(shb + 12, 1); put16be(shb + 14, 0); put32be(shb + 24, 28);
    assert(fwrite(shb, 1, sizeof(shb), f) == sizeof(shb));
    memset(idb, 0, sizeof(idb)); put16be(idb, 1); put32be(idb + 4, 65535);
    write_block_be(f, 1, idb, sizeof(idb));
    memset(packet, 0, sizeof(packet)); put16be(packet + 12, 0x0806);
    memset(epb, 0, sizeof(epb)); put32be(epb, 0); put32be(epb + 4, 0); put32be(epb + 8, 100000);
    put32be(epb + 12, sizeof(packet)); put32be(epb + 16, sizeof(packet)); memcpy(epb + 20, packet, sizeof(packet));
    write_block_be(f, 6, epb, sizeof(epb));
    fclose(f);
}

static void test_capture(void) {
    const char *path = "wireglass_test.pcap";
    unsigned char packet[2048], dns[512], http[] = "GET / HTTP/1.1\r\nHost: example.org\r\n\r\n";
    unsigned char tls[256];
    unsigned char src1[4] = {10, 0, 0, 5}, dst1[4] = {8, 8, 8, 8};
    unsigned char src2[4] = {10, 0, 0, 6}, dst2[4] = {8, 8, 4, 4};
    unsigned char src3[4] = {10, 0, 0, 5}, dst3[4] = {93, 184, 216, 34};
    unsigned char src4[4] = {10, 0, 0, 5}, dst4[4] = {203, 0, 113, 10};
    frame frames[12];
    size_t n = 0, i, tls_len;
    wg_report r;
    wg_limits limits;
    unsigned char answer[4] = {203, 0, 113, 7};
    char query[48] = "a9x7q2m8v4n6c1b3z5k0p9r2t7w4x6m8q1v3c5b";
    memset(frames, 0, sizeof(frames));

    /* Seven evenly spaced high-entropy DNS questions create a reviewable cadence fixture. */
    for (i = 0; i < 7; ++i) {
        size_t dnslen = dns_message(dns, (unsigned)(0x100 + i), 0, query, NULL);
        size_t packetlen = ethernet_ipv4_udp(packet, src1, dst1, 53000, 53, dns, dnslen);
        frames[n].data = (unsigned char *)malloc(packetlen); assert(frames[n].data);
        memcpy((void *)frames[n].data, packet, packetlen); frames[n].len = packetlen;
        frames[n].sec = (unsigned)(100 + i * 10); frames[n].usec = 0; n++;
    }
    {
        size_t dnslen = dns_message(dns, 0x222, 1, "example.com", answer);
        size_t packetlen = ethernet_ipv4_udp(packet, src2, dst2, 53001, 53, dns, dnslen);
        frames[n].data = (unsigned char *)malloc(packetlen); assert(frames[n].data);
        memcpy((void *)frames[n].data, packet, packetlen); frames[n].len = packetlen; frames[n].sec = 180; n++;
    }
    {
        size_t packetlen = ethernet_ipv4_tcp(packet, src3, dst3, 40000, 80, 1000, 0x18, http, sizeof(http) - 1);
        frames[n].data = (unsigned char *)malloc(packetlen); assert(frames[n].data);
        memcpy((void *)frames[n].data, packet, packetlen); frames[n].len = packetlen; frames[n].sec = 181; n++;
    }
    tls_len = tls_client_hello(tls);
    {
        size_t split = 39;
        size_t packetlen = ethernet_ipv4_tcp(packet, src4, dst4, 50000, 443, 10000, 0x18, tls, split);
        frames[n].data = (unsigned char *)malloc(packetlen); assert(frames[n].data);
        memcpy((void *)frames[n].data, packet, packetlen); frames[n].len = packetlen; frames[n].sec = 182; n++;
        packetlen = ethernet_ipv4_tcp(packet, src4, dst4, 50000, 443, (unsigned long)(10000 + split), 0x18, tls + split, tls_len - split);
        frames[n].data = (unsigned char *)malloc(packetlen); assert(frames[n].data);
        memcpy((void *)frames[n].data, packet, packetlen); frames[n].len = packetlen; frames[n].sec = 183; n++;
    }
    write_pcap(path, frames, n);
    for (i = 0; i < n; ++i) free((void *)frames[i].data);
    wg_limits_default(&limits);
    assert(wg_analyze_file(path, &limits, &r));
    assert(strcmp(r.capture_format, "pcap") == 0);
    assert(r.packets_seen == n && r.packets_decoded == n);
    assert(r.flow_count == 4);
    assert(r.dns_count == 8);
    assert(r.finding_count >= 2); /* entropy lead and regular-timing lead */
    {
        int saw_a_answer = 0, saw_http = 0, saw_tls = 0;
        for (i = 0; i < r.dns_count; ++i) if (strcmp(r.dns_events[i].query, "example.com") == 0 && strstr(r.dns_events[i].answers, "203.0.113.7")) saw_a_answer = 1;
        for (i = 0; i < r.flow_capacity; ++i) if (r.flows[i].used) {
            if (strcmp(r.flows[i].http_host, "example.org") == 0) saw_http = 1;
            if (strcmp(r.flows[i].tls_sni, "example.net") == 0 && strcmp(r.flows[i].tls_alpn, "h2") == 0) saw_tls = 1;
        }
        assert(saw_a_answer && saw_http && saw_tls);
    }
    assert(wg_write_json(&r, "wireglass_test.json"));
    wg_report_free(&r);
    limits.max_packets = 2;
    assert(wg_analyze_file(path, &limits, &r));
    assert(r.packets_seen == 2 && r.stopped_at_packet_limit);
    wg_report_free(&r);
    remove(path); remove("wireglass_test.json");
}

static void test_pcapng(void) {
    const char *path = "wireglass_test.pcapng";
    wg_report r;
    wg_limits limits;
    write_pcapng(path);
    wg_limits_default(&limits);
    assert(wg_analyze_file(path, &limits, &r));
    assert(strcmp(r.capture_format, "pcapng") == 0);
    assert(r.packets_seen == 1 && r.packets_unsupported == 1);
    assert(r.linktype_count == 1 && r.linktypes[0] == 1);
    wg_report_free(&r);
    remove(path);
    path = "wireglass_test_be.pcapng";
    write_pcapng_big_endian(path);
    assert(wg_analyze_file(path, &limits, &r));
    assert(strcmp(r.capture_format, "pcapng") == 0);
    assert(r.packets_seen == 1 && r.packets_unsupported == 1);
    wg_report_free(&r);
    remove(path);
}

static void test_reject_malformed(void) {
    const char *path = "wireglass_bad.pcap";
    unsigned char h[40];
    FILE *f = fopen(path, "wb");
    wg_report r;
    wg_limits limits;
    assert(f);
    memset(h, 0, sizeof(h)); memcpy(h, "\xd4\xc3\xb2\xa1", 4);
    put16le(h + 4, 2); put16le(h + 6, 4); put32le(h + 16, 65535); put32le(h + 20, 1);
    put32le(h + 24, 10); put32le(h + 28, 0); put32le(h + 32, 100); put32le(h + 36, 20); /* caplen > wirelen */
    fwrite(h, 1, sizeof(h), f); fclose(f);
    wg_limits_default(&limits);
    assert(!wg_analyze_file(path, &limits, &r));
    assert(strstr(r.error, "bounds") != NULL);
    wg_report_free(&r); remove(path);
}

int main(void) {
    test_capture();
    test_pcapng();
    test_reject_malformed();
    puts("wireglass tests passed");
    return 0;
}

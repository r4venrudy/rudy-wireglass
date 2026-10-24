#include "internal.h"

#include <stdlib.h>
#include <string.h>

#define WG_MAX_BLOCK (64u * 1024u * 1024u)
#define WG_MAX_PACKET (16u * 1024u * 1024u)

uint16_t wg_u16(const uint8_t *p, int little) {
    return little ? (uint16_t)((uint16_t)p[0] | ((uint16_t)p[1] << 8))
                  : (uint16_t)(((uint16_t)p[0] << 8) | p[1]);
}

uint32_t wg_u32(const uint8_t *p, int little) {
    if (little) return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
                        ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

uint64_t wg_u64(const uint8_t *p, int little) {
    uint64_t a = wg_u32(p, little), b = wg_u32(p + 4, little);
    return little ? a | (b << 32) : (a << 32) | b;
}

void wg_add_linktype(wg_report *r, uint32_t linktype) {
    uint32_t i;
    for (i = 0; i < r->linktype_count; ++i)
        if (r->linktypes[i] == linktype) return;
    if (r->linktype_count < 16) r->linktypes[r->linktype_count++] = linktype;
}

static int read_exact(FILE *f, void *buffer, size_t size) {
    return fread(buffer, 1, size, f) == size;
}

static int fail(wg_report *r, const char *message) {
    if (r->error[0] == '\0') snprintf(r->error, sizeof(r->error), "%s", message);
    return 0;
}

int wg_parse_pcap(wg_context *ctx, FILE *f, const uint8_t first[4]) {
    uint8_t global[20] = {0}, record[16] = {0};
    int little, nanos;
    uint32_t snaplen, linktype;

    if (memcmp(first, "\xd4\xc3\xb2\xa1", 4) == 0) { little = 1; nanos = 0; }
    else if (memcmp(first, "\xa1\xb2\xc3\xd4", 4) == 0) { little = 0; nanos = 0; }
    else if (memcmp(first, "\x4d\x3c\xb2\xa1", 4) == 0) { little = 1; nanos = 1; }
    else if (memcmp(first, "\xa1\xb2\x3c\x4d", 4) == 0) { little = 0; nanos = 1; }
    else return fail(ctx->report, "unrecognized capture magic");

    if (!read_exact(f, global, sizeof(global))) return fail(ctx->report, "truncated pcap global header");
    if (wg_u16(global, little) != 2 || wg_u16(global + 2, little) != 4)
        return fail(ctx->report, "unsupported pcap version (expected 2.4)");
    snaplen = wg_u32(global + 12, little);
    linktype = wg_u32(global + 16, little) & 0x0000ffffu;
    if (snaplen == 0 || snaplen > WG_MAX_PACKET)
        return fail(ctx->report, "pcap snap length is outside the safe limit");

    snprintf(ctx->report->capture_format, sizeof(ctx->report->capture_format), "%s",
             nanos ? "pcap-ns" : "pcap");
    wg_add_linktype(ctx->report, linktype);

    for (;;) {
        size_t got = fread(record, 1, sizeof(record), f);
        uint32_t caplen, wirelen, sec, subsec;
        uint8_t *packet;
        if (got == 0 && feof(f)) break;
        if (got != sizeof(record)) return fail(ctx->report, "truncated pcap packet header");
        sec = wg_u32(record, little);
        subsec = wg_u32(record + 4, little);
        caplen = wg_u32(record + 8, little);
        wirelen = wg_u32(record + 12, little);
        if (subsec >= (nanos ? 1000000000u : 1000000u))
            return fail(ctx->report, "pcap packet timestamp fraction is out of range");
        if (caplen > snaplen || caplen > WG_MAX_PACKET || caplen > wirelen)
            return fail(ctx->report, "pcap packet length exceeds its declared bounds");
        packet = (uint8_t *)malloc(caplen ? caplen : 1);
        if (!packet) return fail(ctx->report, "out of memory while reading packet");
        if (!read_exact(f, packet, caplen)) {
            free(packet);
            return fail(ctx->report, "truncated pcap packet data");
        }
        wg_process_packet(ctx, linktype, packet, caplen, wirelen,
                          (double)sec + ((double)subsec / (nanos ? 1e9 : 1e6)));
        free(packet);
        if (ctx->stopped) break;
    }
    return 1;
}

static int parse_idb_options(wg_interface *iface, const uint8_t *b, size_t p,
                             size_t end, int little) {
    while (p + 4 <= end) {
        uint16_t code = wg_u16(b + p, little), length = wg_u16(b + p + 2, little);
        size_t padded = ((size_t)length + 3u) & ~(size_t)3u;
        p += 4;
        if (p + padded > end) return 0;
        if (code == 0) return length == 0;
        if (code == 9 && length == 1) {
            uint8_t v = b[p];
            unsigned exp = v & 0x7fu, i;
            double base = (v & 0x80u) ? 2.0 : 10.0;
            iface->ts_scale = 1.0;
            if (exp > 63) exp = 63;
            for (i = 0; i < exp; ++i) iface->ts_scale /= base;
        } else if (code == 14 && length == 8) {
            iface->ts_offset = (int64_t)wg_u64(b + p, little);
        }
        p += padded;
    }
    return p == end;
}

static int parse_block(wg_context *ctx, const uint8_t *b, uint32_t length,
                       int *little, uint8_t *have_section) {
    uint32_t type = wg_u32(b, *little), trailer;
    wg_report *r = ctx->report;

    if (type == 0x0a0d0d0a) {
        uint32_t bom;
        if (length < 28) return fail(r, "pcapng section header is too short");
        if (memcmp(b + 8, "\x4d\x3c\x2b\x1a", 4) == 0) *little = 1;
        else if (memcmp(b + 8, "\x1a\x2b\x3c\x4d", 4) == 0) *little = 0;
        else return fail(r, "pcapng section has an invalid byte-order marker");
        trailer = wg_u32(b + length - 4, *little);
        if (trailer != length) return fail(r, "pcapng block length trailer does not match");
        bom = wg_u32(b + 8, *little);
        if (bom != 0x1a2b3c4d) return fail(r, "pcapng section byte-order marker is invalid");
        if (wg_u16(b + 12, *little) != 1) return fail(r, "unsupported pcapng major version");
        ctx->interface_count = 0;
        *have_section = 1;
        return 1;
    }
    trailer = wg_u32(b + length - 4, *little);
    if (trailer != length) return fail(r, "pcapng block length trailer does not match");
    if (!*have_section) return fail(r, "pcapng data appeared before a section header");

    if (type == 1) { /* Interface Description Block */
        wg_interface *iface;
        if (length < 20) return fail(r, "pcapng interface block is too short");
        if (ctx->interface_count >= 256) return fail(r, "pcapng interface limit exceeded");
        iface = &ctx->interfaces[ctx->interface_count++];
        iface->linktype = wg_u16(b + 8, *little);
        iface->ts_scale = 1e-6;
        iface->ts_offset = 0;
        wg_add_linktype(r, iface->linktype);
        if (!parse_idb_options(iface, b, 16, length - 4, *little))
            return fail(r, "malformed pcapng interface options");
    } else if (type == 6) { /* Enhanced Packet Block */
        uint32_t id, caplen, wirelen;
        uint64_t ticks;
        wg_interface *iface;
        if (length < 32) return fail(r, "pcapng enhanced packet block is too short");
        id = wg_u32(b + 8, *little);
        if (id >= ctx->interface_count) return fail(r, "pcapng packet references an unknown interface");
        caplen = wg_u32(b + 20, *little);
        wirelen = wg_u32(b + 24, *little);
        if (caplen > WG_MAX_PACKET || caplen > wirelen || 28u + (((caplen + 3u) & ~3u)) > length - 4u)
            return fail(r, "pcapng packet length exceeds its declared bounds");
        iface = &ctx->interfaces[id];
        ticks = ((uint64_t)wg_u32(b + 12, *little) << 32) | wg_u32(b + 16, *little);
        wg_process_packet(ctx, iface->linktype, b + 28, caplen, wirelen,
                          ((double)ticks * iface->ts_scale) + (double)iface->ts_offset);
    } else if (type == 3) { /* Simple Packet Block: no timestamp or interface id */
        uint32_t wirelen, caplen;
        if (length < 16) return fail(r, "pcapng simple packet block is too short");
        if (ctx->interface_count == 0) return fail(r, "pcapng simple packet has no interface");
        wirelen = wg_u32(b + 8, *little);
        caplen = (uint32_t)(length - 16u);
        if (caplen > wirelen) caplen = wirelen;
        wg_process_packet(ctx, ctx->interfaces[0].linktype, b + 12, caplen, wirelen, 0.0);
    }
    return 1;
}

int wg_parse_pcapng(wg_context *ctx, FILE *f, const uint8_t first[4]) {
    uint8_t header[8] = {0}, *block = NULL;
    int little = 1;
    uint8_t have_section = 0;
    int first_block = 1;
    (void)first;
    snprintf(ctx->report->capture_format, sizeof(ctx->report->capture_format), "pcapng");

    for (;;) {
        size_t got;
        uint32_t length;
        if (first_block) {
            memcpy(header, first, 4);
            if (!read_exact(f, header + 4, 4)) return fail(ctx->report, "truncated pcapng section header");
            first_block = 0;
        } else {
            got = fread(header, 1, sizeof(header), f);
            if (got == 0 && feof(f)) break;
            if (got != sizeof(header)) return fail(ctx->report, "truncated pcapng block header");
        }

        if (memcmp(header, "\x0a\x0d\x0d\x0a", 4) == 0) {
            uint8_t bom[4] = {0};
            if (!read_exact(f, bom, sizeof(bom))) return fail(ctx->report, "truncated pcapng byte-order marker");
            if (memcmp(bom, "\x4d\x3c\x2b\x1a", 4) == 0) little = 1;
            else if (memcmp(bom, "\x1a\x2b\x3c\x4d", 4) == 0) little = 0;
            else return fail(ctx->report, "pcapng section has an invalid byte-order marker");
            length = wg_u32(header + 4, little);
            if (length < 28 || length > WG_MAX_BLOCK) return fail(ctx->report, "pcapng section length is outside the safe limit");
            block = (uint8_t *)calloc(length, 1);
            if (!block) return fail(ctx->report, "out of memory while reading pcapng block");
            memcpy(block, header, 8);
            memcpy(block + 8, bom, 4);
            if (!read_exact(f, block + 12, length - 12u)) { free(block); return fail(ctx->report, "truncated pcapng section block"); }
        } else {
            length = wg_u32(header + 4, little);
            if (length < 12 || length > WG_MAX_BLOCK || (length & 3u) != 0)
                return fail(ctx->report, "pcapng block length is outside the safe limit");
            block = (uint8_t *)calloc(length, 1);
            if (!block) return fail(ctx->report, "out of memory while reading pcapng block");
            memcpy(block, header, 8);
            if (!read_exact(f, block + 8, length - 8u)) { free(block); return fail(ctx->report, "truncated pcapng block data"); }
        }

        if (!parse_block(ctx, block, length, &little, &have_section)) {
            free(block);
            return 0;
        }
        free(block);
        block = NULL;
        if (ctx->stopped) break;
    }
    return 1;
}

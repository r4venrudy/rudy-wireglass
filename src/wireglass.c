#define _FILE_OFFSET_BITS 64
#define _POSIX_C_SOURCE 200809L

#include "internal.h"

#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

#ifdef _WIN32
#include <io.h>
#define WG_FSEEK _fseeki64
#define WG_FTELL _ftelli64
#else
#define WG_FSEEK fseeko
#define WG_FTELL ftello
#endif

void wg_limits_default(wg_limits *l) {
    if (!l) return;
    l->max_file_bytes = UINT64_C(2) * 1024u * 1024u * 1024u;
    l->max_packets = UINT64_C(2000000);
    l->max_flows = 8192;
    l->max_dns_events = 8192;
    l->max_findings = 8192;
    l->max_stream_bytes = 16384;
}

void wg_add_finding(wg_report *r, const char *rule, wg_severity severity,
                    const char *title, const char *detail, int flow_index,
                    int dns_index) {
    wg_finding *f;
    if (!r || r->finding_count >= r->finding_capacity) return;
    f = &r->findings[r->finding_count++];
    memset(f, 0, sizeof(*f));
    snprintf(f->rule_id, sizeof(f->rule_id), "%s", rule ? rule : "UNKNOWN");
    snprintf(f->title, sizeof(f->title), "%s", title ? title : "Indicator");
    snprintf(f->detail, sizeof(f->detail), "%s", detail ? detail : "");
    f->severity = severity;
    f->flow_index = flow_index;
    f->dns_index = dns_index;
}

void wg_report_free(wg_report *r) {
    uint32_t i;
    if (!r) return;
    if (r->flows) {
        for (i = 0; i < r->flow_capacity; ++i) {
            free(r->flows[i].stream[0]);
            free(r->flows[i].stream[1]);
        }
    }
    free(r->flows);
    free(r->dns_events);
    free(r->findings);
    memset(r, 0, sizeof(*r));
}

int wg_analyze_file(const char *path, const wg_limits *limits, wg_report *r) {
    wg_context ctx;
    wg_limits defaults;
    FILE *f = NULL;
    uint8_t magic[4];
    off_t size;
    int ok = 0;
    if (!path || !r) return 0;
    memset(r, 0, sizeof(*r));
    wg_limits_default(&defaults);
    if (!limits) limits = &defaults;
    if (!limits->max_flows || !limits->max_packets || limits->max_flows > 1000000 ||
        limits->max_dns_events > 100000 || limits->max_findings > 100000 ||
        limits->max_stream_bytes > 1024u * 1024u) {
        snprintf(r->error, sizeof(r->error), "analysis limits are invalid or exceed the hard safety ceiling");
        return 0;
    }
    r->flow_capacity = limits->max_flows;
    r->dns_capacity = limits->max_dns_events;
    r->finding_capacity = limits->max_findings;
    r->flows = (wg_flow *)calloc(r->flow_capacity, sizeof(wg_flow));
    r->dns_events = (wg_dns_event *)calloc(r->dns_capacity ? r->dns_capacity : 1, sizeof(wg_dns_event));
    r->findings = (wg_finding *)calloc(r->finding_capacity ? r->finding_capacity : 1, sizeof(wg_finding));
    if (!r->flows || !r->dns_events || !r->findings) {
        snprintf(r->error, sizeof(r->error), "out of memory while allocating bounded analysis state");
        goto done;
    }
    f = fopen(path, "rb");
    if (!f) {
        snprintf(r->error, sizeof(r->error), "cannot open capture file");
        goto done;
    }
    if (WG_FSEEK(f, 0, SEEK_END) != 0 || (size = WG_FTELL(f)) < 0 ||
        (uint64_t)size > limits->max_file_bytes || WG_FSEEK(f, 0, SEEK_SET) != 0) {
        snprintf(r->error, sizeof(r->error), "capture file exceeds configured size limit or is not seekable");
        goto done;
    }
    if (fread(magic, 1, sizeof(magic), f) != sizeof(magic)) {
        snprintf(r->error, sizeof(r->error), "capture file is too short");
        goto done;
    }
    memset(&ctx, 0, sizeof(ctx));
    ctx.report = r;
    ctx.limits = limits;
    ctx.max_total_stream_bytes = UINT64_C(64) * 1024u * 1024u;
    if (memcmp(magic, "\x0a\x0d\x0d\x0a", 4) == 0)
        ok = wg_parse_pcapng(&ctx, f, magic);
    else
        ok = wg_parse_pcap(&ctx, f, magic);
    if (ok) wg_finalize_findings(r);
done:
    if (f) fclose(f);
    return ok;
}

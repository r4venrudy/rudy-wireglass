#include "wireglass.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void usage(FILE *f) {
    fputs("Rudy Wireglass — offline PCAP/PCAPNG forensics\n\n"
          "Usage: wireglass scan CAPTURE [options]\n\n"
          "Options:\n"
          "  --format text|json       Report format (default: text)\n"
          "  --output FILE            Write report to FILE; use - for stdout\n"
          "  --max-packets N          Stop after N packets (default: 2000000)\n"
          "  --max-flows N            Bound tracked flows (default: 8192)\n"
          "  --max-file-mib N         Bound capture size in MiB (default: 2048)\n"
          "  --strict                 Exit 1 when a heuristic indicator is present\n"
          "  --version                Print version\n"
          "  --help                   Show this help\n\n"
          "The analyzer reads local files only. It does not open sockets, send packets,\n"
          "or assert that a heuristic proves malicious activity.\n", f);
}

static int parse_u64(const char *s, uint64_t *out) {
    char *end = NULL;
    unsigned long long value;
    if (!s || !*s || *s == '-') return 0;
    errno = 0;
    value = strtoull(s, &end, 10);
    if (errno || !end || *end) return 0;
    *out = (uint64_t)value;
    return 1;
}

int main(int argc, char **argv) {
    const char *capture = NULL, *format = "text", *output = "-";
    wg_limits limits;
    wg_report report;
    int strict = 0, i, exit_code = 0;
    wg_limits_default(&limits);
    if (argc == 1) { usage(stderr); return 2; }
    if (strcmp(argv[1], "--help") == 0 || strcmp(argv[1], "-h") == 0) { usage(stdout); return 0; }
    if (strcmp(argv[1], "--version") == 0) { printf("%s %s (C11)\n", WG_NAME, WG_VERSION); return 0; }
    if (strcmp(argv[1], "scan") != 0) { usage(stderr); return 2; }
    if (argc < 3 || argv[2][0] == '-') { usage(stderr); return 2; }
    capture = argv[2];
    for (i = 3; i < argc; ++i) {
        uint64_t value;
        if (strcmp(argv[i], "--strict") == 0) strict = 1;
        else if (strcmp(argv[i], "--format") == 0 && i + 1 < argc) format = argv[++i];
        else if (strcmp(argv[i], "--output") == 0 && i + 1 < argc) output = argv[++i];
        else if (strcmp(argv[i], "--max-packets") == 0 && i + 1 < argc) {
            if (!parse_u64(argv[++i], &value) || value == 0) { fputs("invalid --max-packets\n", stderr); return 2; }
            limits.max_packets = value;
        } else if (strcmp(argv[i], "--max-flows") == 0 && i + 1 < argc) {
            if (!parse_u64(argv[++i], &value) || value == 0 || value > 1000000) { fputs("invalid --max-flows (1..1000000)\n", stderr); return 2; }
            limits.max_flows = (uint32_t)value;
        } else if (strcmp(argv[i], "--max-file-mib") == 0 && i + 1 < argc) {
            if (!parse_u64(argv[++i], &value) || value == 0 || value > UINT64_MAX / (1024u * 1024u)) { fputs("invalid --max-file-mib\n", stderr); return 2; }
            limits.max_file_bytes = value * 1024u * 1024u;
        } else { fprintf(stderr, "unknown or incomplete option: %s\n", argv[i]); return 2; }
    }
    if (strcmp(format, "text") != 0 && strcmp(format, "json") != 0) {
        fputs("--format must be text or json\n", stderr); return 2;
    }
    if (!wg_analyze_file(capture, &limits, &report)) {
        fprintf(stderr, "wireglass: %s\n", report.error[0] ? report.error : "analysis failed");
        wg_report_free(&report);
        return 2;
    }
    if (strcmp(format, "json") == 0) {
        if (!wg_write_json(&report, output)) { fprintf(stderr, "wireglass: cannot write report to %s\n", output); exit_code = 2; }
    } else if (!wg_write_text(&report, output)) {
        fprintf(stderr, "wireglass: cannot write report to %s\n", output); exit_code = 2;
    }
    if (strict && report.finding_count && exit_code == 0) exit_code = 1;
    wg_report_free(&report);
    return exit_code;
}

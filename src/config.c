#include "shadowdns.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>

void sd_config_defaults(sd_config_t *cfg) {
    memset(cfg, 0, sizeof(*cfg));
    snprintf(cfg->bind_host, sizeof(cfg->bind_host), "0.0.0.0");
    cfg->dns_port = 5353;
    cfg->http_port = 8088;
    snprintf(cfg->upstreams[0], sizeof(cfg->upstreams[0]), "1.1.1.1");
    snprintf(cfg->upstreams[1], sizeof(cfg->upstreams[1]), "8.8.8.8");
    cfg->upstream_count = 2;
    snprintf(cfg->web_root, sizeof(cfg->web_root), "web");
    snprintf(cfg->blocklist_path, sizeof(cfg->blocklist_path), "config/blocklist.txt");
    snprintf(cfg->telemetry_path, sizeof(cfg->telemetry_path), "config/telemetry.txt");
    snprintf(cfg->allowlist_path, sizeof(cfg->allowlist_path), "config/allowlist.txt");
    cfg->block_mode = 1;
    cfg->resolve_process = 1;
    cfg->quiet = 0;
}

static void usage(const char *argv0) {
    fprintf(stderr,
        "ShadowDNS %s — DNS leak & C2 radar\n\n"
        "Usage: %s [options]\n\n"
        "  --dns-port PORT       Listen UDP DNS port (default 5353; use 53 as root)\n"
        "  --http-port PORT      Dashboard / API port (default 8088)\n"
        "  --bind HOST           Bind address (default 0.0.0.0)\n"
        "  --upstream IP         Upstream resolver (repeatable)\n"
        "  --web-root DIR        Static dashboard directory\n"
        "  --blocklist FILE      Domain blocklist\n"
        "  --telemetry FILE      Telemetry domain list\n"
        "  --allowlist FILE      Allowlist (never block)\n"
        "  --alert-only          Detect but never NXDOMAIN-block\n"
        "  --no-proc             Skip /proc process attribution\n"
        "  --quiet               Less stdout chatter\n"
        "  -h, --help            Show help\n",
        SD_VERSION, argv0);
}

int sd_config_load_args(sd_config_t *cfg, int argc, char **argv) {
    sd_config_defaults(cfg);
    static struct option opts[] = {
        {"dns-port", required_argument, 0, 'd'},
        {"http-port", required_argument, 0, 'p'},
        {"bind", required_argument, 0, 'b'},
        {"upstream", required_argument, 0, 'u'},
        {"web-root", required_argument, 0, 'w'},
        {"blocklist", required_argument, 0, 'B'},
        {"telemetry", required_argument, 0, 'T'},
        {"allowlist", required_argument, 0, 'A'},
        {"alert-only", no_argument, 0, 'a'},
        {"no-proc", no_argument, 0, 'n'},
        {"quiet", no_argument, 0, 'q'},
        {"help", no_argument, 0, 'h'},
        {0, 0, 0, 0}
    };
    int up_reset = 0;
    int c;
    while ((c = getopt_long(argc, argv, "d:p:b:u:w:hq", opts, NULL)) != -1) {
        switch (c) {
            case 'd': cfg->dns_port = atoi(optarg); break;
            case 'p': cfg->http_port = atoi(optarg); break;
            case 'b': snprintf(cfg->bind_host, sizeof(cfg->bind_host), "%s", optarg); break;
            case 'u':
                if (!up_reset) { cfg->upstream_count = 0; up_reset = 1; }
                if (cfg->upstream_count < SD_MAX_UPSTREAMS) {
                    snprintf(cfg->upstreams[cfg->upstream_count],
                             sizeof(cfg->upstreams[0]), "%s", optarg);
                    cfg->upstream_count++;
                }
                break;
            case 'w': snprintf(cfg->web_root, sizeof(cfg->web_root), "%s", optarg); break;
            case 'B': snprintf(cfg->blocklist_path, sizeof(cfg->blocklist_path), "%s", optarg); break;
            case 'T': snprintf(cfg->telemetry_path, sizeof(cfg->telemetry_path), "%s", optarg); break;
            case 'A': snprintf(cfg->allowlist_path, sizeof(cfg->allowlist_path), "%s", optarg); break;
            case 'a': cfg->block_mode = 0; break;
            case 'n': cfg->resolve_process = 0; break;
            case 'q': cfg->quiet = 1; break;
            case 'h': usage(argv[0]); exit(0);
            default: usage(argv[0]); return -1;
        }
    }
    if (cfg->upstream_count == 0) {
        snprintf(cfg->upstreams[0], sizeof(cfg->upstreams[0]), "1.1.1.1");
        cfg->upstream_count = 1;
    }
    return 0;
}

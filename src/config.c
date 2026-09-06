#include "shadowdns.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <strings.h>

const sd_config_t *sd_runtime_cfg;

void sd_config_defaults(sd_config_t *cfg) {
    memset(cfg, 0, sizeof(*cfg));
    snprintf(cfg->bind_host, sizeof(cfg->bind_host), "0.0.0.0");
    cfg->dns_port = 5353;
    cfg->http_port = 8088;
    cfg->upstreams[0].kind = SD_UP_UDP;
    snprintf(cfg->upstreams[0].host, sizeof(cfg->upstreams[0].host), "1.1.1.1");
    cfg->upstreams[0].port = 53;
    cfg->upstreams[1].kind = SD_UP_UDP;
    snprintf(cfg->upstreams[1].host, sizeof(cfg->upstreams[1].host), "8.8.8.8");
    cfg->upstreams[1].port = 53;
    cfg->upstream_count = 2;
    snprintf(cfg->web_root, sizeof(cfg->web_root), "web");
    snprintf(cfg->blocklist_path, sizeof(cfg->blocklist_path), "config/blocklist.txt");
    snprintf(cfg->telemetry_path, sizeof(cfg->telemetry_path), "config/telemetry.txt");
    snprintf(cfg->allowlist_path, sizeof(cfg->allowlist_path), "config/allowlist.txt");
    snprintf(cfg->policy_path, sizeof(cfg->policy_path), "config/policy.sd");
    snprintf(cfg->split_path, sizeof(cfg->split_path), "config/split.conf");
    snprintf(cfg->jsonl_path, sizeof(cfg->jsonl_path), "shadowdns.jsonl");
    cfg->block_mode = 1;
    cfg->resolve_process = 1;
    cfg->enable_ebpf = 1;
    cfg->fluxtap_bridge = 1;
}

static void usage(const char *argv0) {
    fprintf(stderr,
        "ShadowDNS %s — DNS leak & C2 radar\n\n"
        "Usage: %s [options]\n\n"
        "  --dns-port PORT       UDP DNS listen port (default 5353)\n"
        "  --http-port PORT      dashboard/API port (default 8088)\n"
        "  --bind HOST           bind address\n"
        "  --upstream SPEC       udp:IP[:port] | dot:IP[:853] | doh:host[/path]\n"
        "  --policy FILE         policy DSL file\n"
        "  --split FILE          split-horizon map\n"
        "  --jsonl FILE          append JSONL events\n"
        "  --webhook URL         POST CRIT/HIGH events\n"
        "  --telegram TOKEN:CHAT notify via Bot API (token:chat_id)\n"
        "  --alert-only          never NXDOMAIN-block\n"
        "  --no-ebpf             disable eBPF attribution\n"
        "  --no-proc             skip /proc fallback attribution\n"
        "  --tui                 ANSI terminal UI instead of only HTTP\n"
        "  --quiet               less stdout\n"
        "  -h, --help\n",
        SD_VERSION, argv0);
}

static int parse_upstream(const char *spec, sd_upstream_t *u) {
    memset(u, 0, sizeof(*u));
    snprintf(u->doh_path, sizeof(u->doh_path), "/dns-query");
    if (!strncmp(spec, "udp:", 4)) {
        u->kind = SD_UP_UDP;
        spec += 4;
        u->port = 53;
    } else if (!strncmp(spec, "dot:", 4)) {
        u->kind = SD_UP_DOT;
        spec += 4;
        u->port = 853;
    } else if (!strncmp(spec, "doh:", 4)) {
        u->kind = SD_UP_DOH;
        spec += 4;
        u->port = 443;
    } else {
        u->kind = SD_UP_UDP;
        u->port = 53;
    }
    char tmp[256];
    snprintf(tmp, sizeof(tmp), "%s", spec);
    char *slash = strchr(tmp, '/');
    if (slash && u->kind == SD_UP_DOH) {
        *slash = '\0';
        snprintf(u->doh_path, sizeof(u->doh_path), "/%s", slash + 1);
    }
    char *colon = strrchr(tmp, ':');
    /* avoid cutting IPv6; only for simple host:port */
    if (colon && strchr(tmp, ':') == colon) {
        *colon = '\0';
        u->port = atoi(colon + 1);
    }
    snprintf(u->host, sizeof(u->host), "%s", tmp);
    return u->host[0] ? 0 : -1;
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
        {"policy", required_argument, 0, 'P'},
        {"split", required_argument, 0, 'S'},
        {"jsonl", required_argument, 0, 'J'},
        {"webhook", required_argument, 0, 'W'},
        {"telegram", required_argument, 0, 'G'},
        {"alert-only", no_argument, 0, 'a'},
        {"no-proc", no_argument, 0, 'n'},
        {"no-ebpf", no_argument, 0, 'e'},
        {"tui", no_argument, 0, 't'},
        {"quiet", no_argument, 0, 'q'},
        {"help", no_argument, 0, 'h'},
        {0, 0, 0, 0}
    };
    int up_reset = 0;
    int c;
    optind = 1;
    while ((c = getopt_long(argc, argv, "d:p:b:u:w:hq", opts, NULL)) != -1) {
        switch (c) {
            case 'd': cfg->dns_port = atoi(optarg); break;
            case 'p': cfg->http_port = atoi(optarg); break;
            case 'b': snprintf(cfg->bind_host, sizeof(cfg->bind_host), "%s", optarg); break;
            case 'u':
                if (!up_reset) { cfg->upstream_count = 0; up_reset = 1; }
                if (cfg->upstream_count < SD_MAX_UPSTREAMS) {
                    if (parse_upstream(optarg, &cfg->upstreams[cfg->upstream_count]) == 0)
                        cfg->upstream_count++;
                }
                break;
            case 'w': snprintf(cfg->web_root, sizeof(cfg->web_root), "%s", optarg); break;
            case 'B': snprintf(cfg->blocklist_path, sizeof(cfg->blocklist_path), "%s", optarg); break;
            case 'T': snprintf(cfg->telemetry_path, sizeof(cfg->telemetry_path), "%s", optarg); break;
            case 'A': snprintf(cfg->allowlist_path, sizeof(cfg->allowlist_path), "%s", optarg); break;
            case 'P': snprintf(cfg->policy_path, sizeof(cfg->policy_path), "%s", optarg); break;
            case 'S': snprintf(cfg->split_path, sizeof(cfg->split_path), "%s", optarg); break;
            case 'J': snprintf(cfg->jsonl_path, sizeof(cfg->jsonl_path), "%s", optarg); break;
            case 'W': snprintf(cfg->webhook_url, sizeof(cfg->webhook_url), "%s", optarg); break;
            case 'G': {
                char *sep = strchr(optarg, ':');
                if (sep) {
                    size_t n = (size_t)(sep - optarg);
                    if (n >= sizeof(cfg->telegram_token)) n = sizeof(cfg->telegram_token) - 1;
                    memcpy(cfg->telegram_token, optarg, n);
                    cfg->telegram_token[n] = '\0';
                    snprintf(cfg->telegram_chat, sizeof(cfg->telegram_chat), "%s", sep + 1);
                }
                break;
            }
            case 'a': cfg->block_mode = 0; break;
            case 'n': cfg->resolve_process = 0; break;
            case 'e': cfg->enable_ebpf = 0; break;
            case 't': cfg->enable_tui = 1; break;
            case 'q': cfg->quiet = 1; break;
            case 'h': usage(argv[0]); exit(0);
            default: usage(argv[0]); return -1;
        }
    }
    if (cfg->upstream_count == 0) {
        cfg->upstreams[0].kind = SD_UP_UDP;
        snprintf(cfg->upstreams[0].host, sizeof(cfg->upstreams[0].host), "1.1.1.1");
        cfg->upstreams[0].port = 53;
        cfg->upstream_count = 1;
    }
    return 0;
}

const char *sd_sev_name(sd_severity_t s) {
    static const char *n[] = {"info", "low", "med", "high", "crit"};
    if (s < 0 || s > 4) return "info";
    return n[s];
}

const char *sd_act_name(sd_action_t a) {
    return a == SD_ACTION_BLOCK ? "block" : a == SD_ACTION_ALERT ? "alert" : "allow";
}

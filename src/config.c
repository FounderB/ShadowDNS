#include "shadowdns.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <strings.h>
#include <arpa/inet.h>

const sd_config_t *sd_runtime_cfg;

void sd_config_defaults(sd_config_t *cfg) {
    memset(cfg, 0, sizeof(*cfg));
    /* Secure-by-default: localhost only */
    snprintf(cfg->bind_host, sizeof(cfg->bind_host), "127.0.0.1");
    cfg->dns_port = 5353;
    cfg->http_port = 8089;
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
    cfg->tls_insecure = 0;
    cfg->open_resolver = 0;
}

static void usage(const char *argv0) {
    fprintf(stderr,
        "ShadowDNS %s — DNS leak & C2 radar (secure defaults)\n\n"
        "Usage: %s [options]\n\n"
        "  --dns-port PORT       UDP DNS listen port (default 5353)\n"
        "  --http-port PORT      dashboard/API port (default 8089)\n"
        "  --bind HOST           bind address (default 127.0.0.1)\n"
        "  --listen-all          bind 0.0.0.0 (explicit open listen)\n"
        "  --token TOKEN         API/dashboard auth token (or SD_API_TOKEN)\n"
        "  --allow-client CIDR   allow DNS client CIDR (repeatable)\n"
        "  --open-resolver       allow any DNS client (dangerous)\n"
        "  --upstream SPEC       udp:IP | dot:IP[:853] | doh:host[/path]\n"
        "  --insecure-tls        skip TLS cert verify (DoH/DoT/webhook)\n"
        "  --telegram-token-file FILE  read bot token (prefer over argv)\n"
        "  --telegram-chat ID    telegram chat id\n"
        "  --webhook URL         POST HIGH/CRIT (SSRF-hardened)\n"
        "  --jsonl FILE          append JSONL (0600)\n"
        "  --alert-only          never NXDOMAIN-block\n"
        "  --no-ebpf / --no-proc / --tui / --quiet\n"
        "  -h, --help\n",
        SD_VERSION, argv0);
}

static int parse_upstream(const char *spec, sd_upstream_t *u) {
    memset(u, 0, sizeof(*u));
    snprintf(u->doh_path, sizeof(u->doh_path), "/dns-query");
    if (!strncmp(spec, "udp:", 4)) { u->kind = SD_UP_UDP; spec += 4; u->port = 53; }
    else if (!strncmp(spec, "dot:", 4)) { u->kind = SD_UP_DOT; spec += 4; u->port = 853; }
    else if (!strncmp(spec, "doh:", 4)) { u->kind = SD_UP_DOH; spec += 4; u->port = 443; }
    else { u->kind = SD_UP_UDP; u->port = 53; }
    char tmp[256];
    snprintf(tmp, sizeof(tmp), "%s", spec);
    /* reject CRLF injection in host/path */
    if (strchr(tmp, '\r') || strchr(tmp, '\n')) return -1;
    char *slash = strchr(tmp, '/');
    if (slash && u->kind == SD_UP_DOH) {
        *slash = '\0';
        if (strchr(slash + 1, '\r') || strchr(slash + 1, '\n')) return -1;
        snprintf(u->doh_path, sizeof(u->doh_path), "/%s", slash + 1);
    }
    char *colon = strrchr(tmp, ':');
    if (colon && strchr(tmp, ':') == colon) {
        *colon = '\0';
        u->port = atoi(colon + 1);
    }
    snprintf(u->host, sizeof(u->host), "%s", tmp);
    return u->host[0] ? 0 : -1;
}

static int parse_cidr(const char *s, sd_cidr_t *out) {
    char buf[64];
    snprintf(buf, sizeof(buf), "%s", s);
    int bits = 32;
    char *slash = strchr(buf, '/');
    if (slash) {
        *slash = '\0';
        bits = atoi(slash + 1);
        if (bits < 0 || bits > 32) return -1;
    }
    struct in_addr a;
    if (inet_pton(AF_INET, buf, &a) != 1) return -1;
    uint32_t ip = ntohl(a.s_addr);
    uint32_t mask = bits == 0 ? 0u : (bits == 32 ? 0xffffffffu : (0xffffffffu << (32 - bits)));
    out->network = ip & mask;
    out->mask = mask;
    return 0;
}

static void load_token_file(const char *path, char *out, size_t out_sz) {
    FILE *f = fopen(path, "r");
    if (!f) return;
    if (!fgets(out, (int)out_sz, f)) { fclose(f); return; }
    fclose(f);
    size_t n = strlen(out);
    while (n && (out[n - 1] == '\n' || out[n - 1] == '\r' || out[n - 1] == ' '))
        out[--n] = '\0';
}

int sd_config_client_allowed(const sd_config_t *cfg, const char *ip) {
    if (!cfg || !ip) return 0;
    if (cfg->open_resolver) return 1;
    /* always allow loopback */
    if (!strcmp(ip, "127.0.0.1") || !strcmp(ip, "::1") || !strncmp(ip, "127.", 4))
        return 1;
    if (cfg->allow_cidr_count == 0) {
        /* secure default: only loopback unless CIDRs or --open-resolver */
        return 0;
    }
    struct in_addr a;
    if (inet_pton(AF_INET, ip, &a) != 1) return 0;
    uint32_t hip = ntohl(a.s_addr);
    for (int i = 0; i < cfg->allow_cidr_count; i++) {
        if ((hip & cfg->allow_cidrs[i].mask) == cfg->allow_cidrs[i].network)
            return 1;
    }
    return 0;
}

int sd_config_load_args(sd_config_t *cfg, int argc, char **argv) {
    sd_config_defaults(cfg);
    /* env token preferred over leaving empty */
    const char *env_tok = getenv("SD_API_TOKEN");
    if (env_tok && env_tok[0])
        snprintf(cfg->api_token, sizeof(cfg->api_token), "%s", env_tok);
    const char *env_tg = getenv("SD_TELEGRAM_TOKEN");
    if (env_tg && env_tg[0])
        snprintf(cfg->telegram_token, sizeof(cfg->telegram_token), "%s", env_tg);
    const char *env_chat = getenv("SD_TELEGRAM_CHAT");
    if (env_chat && env_chat[0])
        snprintf(cfg->telegram_chat, sizeof(cfg->telegram_chat), "%s", env_chat);

    static struct option opts[] = {
        {"dns-port", required_argument, 0, 'd'},
        {"http-port", required_argument, 0, 'p'},
        {"bind", required_argument, 0, 'b'},
        {"listen-all", no_argument, 0, 'L'},
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
        {"telegram-token-file", required_argument, 0, 'F'},
        {"telegram-chat", required_argument, 0, 'C'},
        {"token", required_argument, 0, 'K'},
        {"allow-client", required_argument, 0, 'c'},
        {"open-resolver", no_argument, 0, 'O'},
        {"insecure-tls", no_argument, 0, 'I'},
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
            case 'L': snprintf(cfg->bind_host, sizeof(cfg->bind_host), "0.0.0.0"); break;
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
            case 'W':
                if (strchr(optarg, '\r') || strchr(optarg, '\n')) break;
                snprintf(cfg->webhook_url, sizeof(cfg->webhook_url), "%s", optarg);
                break;
            case 'G': {
                /* deprecated: prefer token-file + chat / env
                 * Bot tokens can contain ':' — split on the *last* colon. */
                char *sep = strrchr(optarg, ':');
                if (sep && sep != optarg) {
                    size_t n = (size_t)(sep - optarg);
                    if (n >= sizeof(cfg->telegram_token)) n = sizeof(cfg->telegram_token) - 1;
                    memcpy(cfg->telegram_token, optarg, n);
                    cfg->telegram_token[n] = '\0';
                    snprintf(cfg->telegram_chat, sizeof(cfg->telegram_chat), "%s", sep + 1);
                    fprintf(stderr, "warning: --telegram exposes token in argv; use --telegram-token-file or SD_TELEGRAM_TOKEN\n");
                }
                break;
            }
            case 'F': load_token_file(optarg, cfg->telegram_token, sizeof(cfg->telegram_token)); break;
            case 'C': snprintf(cfg->telegram_chat, sizeof(cfg->telegram_chat), "%s", optarg); break;
            case 'K': snprintf(cfg->api_token, sizeof(cfg->api_token), "%s", optarg); break;
            case 'c':
                if (cfg->allow_cidr_count < SD_MAX_ALLOW_CIDR) {
                    if (parse_cidr(optarg, &cfg->allow_cidrs[cfg->allow_cidr_count]) == 0)
                        cfg->allow_cidr_count++;
                }
                break;
            case 'O': cfg->open_resolver = 1; break;
            case 'I': cfg->tls_insecure = 1; break;
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
    if (!cfg->api_token[0]) {
        fprintf(stderr,
                "warning: no --token / SD_API_TOKEN set — API is open on %s:%d (localhost only by default)\n",
                cfg->bind_host, cfg->http_port);
    }
    if (strcmp(cfg->bind_host, "127.0.0.1") != 0 && strcmp(cfg->bind_host, "::1") != 0) {
        fprintf(stderr, "warning: binding %s — ensure firewall + --token\n", cfg->bind_host);
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

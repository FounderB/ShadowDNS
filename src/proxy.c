#include "shadowdns.h"

#include <arpa/inet.h>
#include <errno.h>
#include <netdb.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>
#include <poll.h>
#include <strings.h>
#include <time.h>

typedef struct {
    const sd_config_t *cfg;
    int sock;
} proxy_ctx_t;

static int forward_query(const sd_config_t *cfg, const uint8_t *req, size_t req_len,
                         uint8_t *resp, size_t resp_sz, int *latency_ms) {
    uint64_t t0 = sd_now_ms();
    for (int u = 0; u < cfg->upstream_count; u++) {
        int fd = socket(AF_INET, SOCK_DGRAM, 0);
        if (fd < 0) continue;

        struct timeval tv = {.tv_sec = 2, .tv_usec = 0};
        setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

        struct sockaddr_in addr;
        memset(&addr, 0, sizeof(addr));
        addr.sin_family = AF_INET;
        addr.sin_port = htons(53);
        if (inet_pton(AF_INET, cfg->upstreams[u], &addr.sin_addr) != 1) {
            close(fd);
            continue;
        }

        if (sendto(fd, req, req_len, 0, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
            close(fd);
            continue;
        }

        ssize_t n = recvfrom(fd, resp, resp_sz, 0, NULL, NULL);
        close(fd);
        if (n > 0) {
            *latency_ms = (int)(sd_now_ms() - t0);
            return (int)n;
        }
    }
    *latency_ms = (int)(sd_now_ms() - t0);
    return -1;
}

static void handle_packet(const sd_config_t *cfg, int sock,
                          const uint8_t *buf, ssize_t n,
                          const struct sockaddr_in *peer) {
    sd_event_t ev;
    memset(&ev, 0, sizeof(ev));
    ev.ts = time(NULL);
    inet_ntop(AF_INET, &peer->sin_addr, ev.client_ip, sizeof(ev.client_ip));
    ev.client_port = ntohs(peer->sin_port);

    if (sd_dns_extract_question(buf, (size_t)n, ev.qname, sizeof(ev.qname),
                                &ev.qtype, &ev.qclass) != 0) {
        return;
    }

    sd_store_note_name(ev.qname);

    if (cfg->resolve_process) {
        sd_proc_lookup_udp(ev.client_port, ev.process, sizeof(ev.process),
                           ev.pid, sizeof(ev.pid));
    }

    sd_detect(&ev);

    uint8_t resp[4096];
    int resp_len = -1;

    if (ev.action == SD_ACTION_BLOCK && cfg->block_mode) {
        resp_len = sd_dns_build_nxdomain(buf, (size_t)n, resp, sizeof(resp));
        ev.rcode = 3;
        ev.answer_count = 0;
        ev.latency_ms = 0;
    } else {
        resp_len = forward_query(cfg, buf, (size_t)n, resp, sizeof(resp), &ev.latency_ms);
        if (resp_len > 0) {
            /* restore original transaction id */
            sd_dns_set_id(resp, (size_t)resp_len, sd_dns_get_id(buf, (size_t)n));
            ev.rcode = sd_dns_rcode(resp, (size_t)resp_len);
            ev.answer_count = sd_dns_answer_count(resp, (size_t)resp_len);
            if (ev.rcode == 3) {
                if (!strstr(ev.tags, "nxdomain")) {
                    size_t tn = strlen(ev.tags);
                    if (tn == 0) snprintf(ev.tags, sizeof(ev.tags), "nxdomain");
                    else if (tn + 9 < sizeof(ev.tags))
                        snprintf(ev.tags + tn, sizeof(ev.tags) - tn, ",nxdomain");
                }
            }
        } else {
            resp_len = sd_dns_build_nxdomain(buf, (size_t)n, resp, sizeof(resp));
            ev.rcode = 2; /* SERVFAIL-ish presentation */
            snprintf(ev.reason, sizeof(ev.reason), "upstream timeout");
            if (ev.severity < SD_SEV_LOW) ev.severity = SD_SEV_LOW;
        }
    }

    if (resp_len > 0) {
        sendto(sock, resp, (size_t)resp_len, 0,
               (const struct sockaddr *)peer, sizeof(*peer));
    }

    sd_store_push(&ev);

    if (!cfg->quiet) {
        const char *sev[] = {"INFO", "LOW", "MED", "HIGH", "CRIT"};
        const char *act[] = {"ALLOW", "ALERT", "BLOCK"};
        fprintf(stdout, "[%s] %-5s %-5s %-6s %s",
                sev[ev.severity], act[ev.action],
                sd_dns_type_name(ev.qtype),
                ev.process[0] ? ev.process : "-",
                ev.qname);
        if (ev.reason[0] && strcmp(ev.reason, "clean") != 0)
            fprintf(stdout, "  (%s)", ev.reason);
        fputc('\n', stdout);
        fflush(stdout);
    }
}

int sd_proxy_run(const sd_config_t *cfg) {
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        perror("socket");
        return -1;
    }

    int yes = 1;
    setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons((uint16_t)cfg->dns_port);
    if (inet_pton(AF_INET, cfg->bind_host, &addr.sin_addr) != 1) {
        fprintf(stderr, "invalid bind host: %s\n", cfg->bind_host);
        close(sock);
        return -1;
    }

    if (bind(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("bind dns");
        close(sock);
        return -1;
    }

    fprintf(stderr, "ShadowDNS listening UDP %s:%d → upstream",
            cfg->bind_host, cfg->dns_port);
    for (int i = 0; i < cfg->upstream_count; i++)
        fprintf(stderr, " %s", cfg->upstreams[i]);
    fprintf(stderr, "\n");

    for (;;) {
        uint8_t buf[4096];
        struct sockaddr_in peer;
        socklen_t peerlen = sizeof(peer);
        ssize_t n = recvfrom(sock, buf, sizeof(buf), 0,
                             (struct sockaddr *)&peer, &peerlen);
        if (n < 0) {
            if (errno == EINTR) continue;
            perror("recvfrom");
            continue;
        }
        handle_packet(cfg, sock, buf, n, &peer);
    }
}

#include "shadowdns.h"

#include <arpa/inet.h>
#include <errno.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>
#include <strings.h>
#include <time.h>

static void handle_packet(const sd_config_t *cfg, int sock,
                          const uint8_t *buf, ssize_t n,
                          const struct sockaddr_in *peer) {
    sd_event_t ev;
    memset(&ev, 0, sizeof(ev));
    ev.ts = time(NULL);
    inet_ntop(AF_INET, &peer->sin_addr, ev.client_ip, sizeof(ev.client_ip));
    ev.client_port = ntohs(peer->sin_port);

    if (!sd_config_client_allowed(cfg, ev.client_ip)) {
        sd_store_bump_counter("refused_clients", 1);
        uint8_t refuse[512];
        int rlen = sd_dns_build_nxdomain(buf, (size_t)n, refuse, sizeof(refuse));
        /* REFUSED rcode=5 */
        if (rlen > 3) refuse[3] = (uint8_t)((refuse[3] & 0xF0) | 5);
        if (rlen > 0)
            sendto(sock, refuse, (size_t)rlen, 0,
                   (const struct sockaddr *)peer, sizeof(*peer));
        return;
    }

    if (sd_dns_extract_question(buf, (size_t)n, ev.qname, sizeof(ev.qname),
                                &ev.qtype, &ev.qclass) != 0)
        return;

    sd_store_note_name(ev.qname);

    if (sd_ebpf_lookup(ev.client_port, ev.process, sizeof(ev.process),
                       ev.pid, sizeof(ev.pid), ev.cgroup, sizeof(ev.cgroup),
                       ev.container, sizeof(ev.container))) {
        ev.attr_ebpf = 1;
    } else if (cfg->resolve_process) {
        sd_proc_lookup_udp(ev.client_port, ev.process, sizeof(ev.process),
                           ev.pid, sizeof(ev.pid));
        if (ev.pid[0])
            sd_proc_fill_cgroup(ev.pid, ev.cgroup, sizeof(ev.cgroup),
                                ev.container, sizeof(ev.container));
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
        resp_len = sd_upstream_query(cfg, ev.qname, buf, (size_t)n,
                                     resp, sizeof(resp), &ev.latency_ms);
        if (resp_len > 0) {
            sd_dns_set_id(resp, (size_t)resp_len, sd_dns_get_id(buf, (size_t)n));
            sd_detect_response(&ev, resp, (size_t)resp_len);
        } else {
            resp_len = sd_dns_build_nxdomain(buf, (size_t)n, resp, sizeof(resp));
            ev.rcode = 2;
            snprintf(ev.reason, sizeof(ev.reason), "upstream timeout");
            if (ev.severity < SD_SEV_LOW) ev.severity = SD_SEV_LOW;
        }
    }

    if (cfg->fluxtap_bridge) sd_fluxtap_correlate(&ev);
    sd_policy_apply(&ev);

    /* re-check block after policy */
    if (ev.action == SD_ACTION_BLOCK && cfg->block_mode && ev.rcode != 3) {
        resp_len = sd_dns_build_nxdomain(buf, (size_t)n, resp, sizeof(resp));
        ev.rcode = 3;
        ev.answer_count = 0;
    }

    if (resp_len > 0) {
        sendto(sock, resp, (size_t)resp_len, 0,
               (const struct sockaddr *)peer, sizeof(*peer));
    }

    /* Assign id before stories so last_event_id / linkage is valid */
    if (!ev.id) ev.id = sd_store_alloc_id();
    sd_story_on_event(&ev);
    sd_store_push(&ev);
    sd_jsonl_write(cfg, &ev);
    sd_notify_event(cfg, &ev);

    if (!cfg->quiet) {
        fprintf(stdout, "[%s] %-5s %-5s %-6s %s",
                sd_sev_name(ev.severity), sd_act_name(ev.action),
                sd_dns_type_name(ev.qtype),
                ev.process[0] ? ev.process : "-",
                ev.qname);
        if (ev.attr_ebpf) fputs(" [ebpf]", stdout);
        if (ev.container[0]) fprintf(stdout, " <%s>", ev.container);
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

    fprintf(stderr, "ShadowDNS listening UDP %s:%d →", cfg->bind_host, cfg->dns_port);
    for (int i = 0; i < cfg->upstream_count; i++) {
        const char *k = cfg->upstreams[i].kind == SD_UP_DOH ? "doh" :
                        cfg->upstreams[i].kind == SD_UP_DOT ? "dot" : "udp";
        fprintf(stderr, " %s:%s:%d", k, cfg->upstreams[i].host, cfg->upstreams[i].port);
    }
    fprintf(stderr, "\n");

    /* Wake recvfrom periodically so SIGINT/SIGTERM can stop cleanly */
    struct timeval tv = { .tv_sec = 1, .tv_usec = 0 };
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    for (;;) {
        if (sd_stop_requested()) break;
        uint8_t buf[4096];
        struct sockaddr_in peer;
        socklen_t peerlen = sizeof(peer);
        ssize_t n = recvfrom(sock, buf, sizeof(buf), 0,
                             (struct sockaddr *)&peer, &peerlen);
        if (n < 0) {
            if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK) continue;
            perror("recvfrom");
            continue;
        }
        handle_packet(cfg, sock, buf, n, &peer);
    }
    close(sock);
    return 0;
}

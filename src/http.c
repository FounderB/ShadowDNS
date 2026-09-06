#include "shadowdns.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>

static const sd_config_t *g_cfg;

static const char *mime_for(const char *path) {
    const char *dot = strrchr(path, '.');
    if (!dot) return "application/octet-stream";
    if (!strcmp(dot, ".html")) return "text/html; charset=utf-8";
    if (!strcmp(dot, ".css")) return "text/css; charset=utf-8";
    if (!strcmp(dot, ".js")) return "application/javascript; charset=utf-8";
    if (!strcmp(dot, ".svg")) return "image/svg+xml";
    if (!strcmp(dot, ".json")) return "application/json";
    return "application/octet-stream";
}

static void send_all(int fd, const char *data, size_t n) {
    size_t off = 0;
    while (off < n) {
        ssize_t w = write(fd, data + off, n - off);
        if (w < 0) {
            if (errno == EINTR) continue;
            return;
        }
        off += (size_t)w;
    }
}

static void http_respond(int fd, int code, const char *ctype,
                         const char *body, size_t body_len) {
    char hdr[512];
    const char *msg = code == 200 ? "OK" : code == 404 ? "Not Found" :
                      code == 204 ? "No Content" : "Error";
    int n = snprintf(hdr, sizeof(hdr),
                     "HTTP/1.1 %d %s\r\nContent-Type: %s\r\nContent-Length: %zu\r\n"
                     "Access-Control-Allow-Origin: *\r\nCache-Control: no-store\r\n"
                     "Connection: close\r\n\r\n",
                     code, msg, ctype, body_len);
    send_all(fd, hdr, (size_t)n);
    if (body && body_len) send_all(fd, body, body_len);
}

static void handle_api_stats(int fd) {
    sd_stats_t st;
    sd_store_stats(&st);
    char body[768];
    int n = snprintf(body, sizeof(body),
        "{\"version\":\"%s\",\"queries\":%llu,\"blocked\":%llu,\"alerts\":%llu,"
        "\"tunnels\":%llu,\"telemetry\":%llu,\"nxdomain\":%llu,\"unique\":%llu,"
        "\"dga\":%llu,\"fastflux\":%llu,\"doh_bypass\":%llu,\"stories\":%llu,"
        "\"ebpf_hits\":%llu,\"newly_seen\":%llu,\"block_mode\":%s,\"ebpf\":%s}",
        SD_VERSION,
        (unsigned long long)st.queries, (unsigned long long)st.blocked,
        (unsigned long long)st.alerts, (unsigned long long)st.tunnels,
        (unsigned long long)st.telemetry, (unsigned long long)st.nxdomain,
        (unsigned long long)st.unique_names, (unsigned long long)st.dga,
        (unsigned long long)st.fastflux, (unsigned long long)st.doh_bypass,
        (unsigned long long)st.stories, (unsigned long long)st.ebpf_hits,
        (unsigned long long)st.newly_seen,
        g_cfg->block_mode ? "true" : "false",
        sd_ebpf_active() ? "true" : "false");
    http_respond(fd, 200, "application/json", body, (size_t)n);
}

static void handle_api_events(int fd, uint64_t after) {
    sd_event_t evs[256];
    size_t n = sd_store_snapshot(evs, 256, after);
    size_t cap = 256 * 1200 + 32;
    char *body = malloc(cap);
    if (!body) { http_respond(fd, 500, "text/plain", "oom", 3); return; }
    size_t o = 0;
    body[o++] = '[';
    for (size_t i = 0; i < n; i++) {
        char one[1200];
        int m = sd_event_to_json(&evs[i], one, sizeof(one));
        if (m < 0) continue;
        if (o + (size_t)m + 2 >= cap) break;
        if (i) body[o++] = ',';
        memcpy(body + o, one, (size_t)m);
        o += (size_t)m;
    }
    body[o++] = ']';
    http_respond(fd, 200, "application/json", body, o);
    free(body);
}

static void handle_api_stories(int fd, uint64_t after) {
    sd_story_t sts[64];
    size_t n = sd_story_snapshot(sts, 64, after);
    char *body = malloc(64 * 900 + 32);
    if (!body) { http_respond(fd, 500, "text/plain", "oom", 3); return; }
    size_t o = 0;
    body[o++] = '[';
    for (size_t i = 0; i < n; i++) {
        char one[900];
        int m = sd_story_to_json(&sts[i], one, sizeof(one));
        if (m < 0) continue;
        if (i) body[o++] = ',';
        memcpy(body + o, one, (size_t)m);
        o += (size_t)m;
    }
    body[o++] = ']';
    http_respond(fd, 200, "application/json", body, o);
    free(body);
}

static void handle_api_stream(int fd) {
    const char *hdr =
        "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\n"
        "Cache-Control: no-cache\r\nAccess-Control-Allow-Origin: *\r\n"
        "Connection: keep-alive\r\n\r\n";
    send_all(fd, hdr, strlen(hdr));
    uint64_t after = 0, story_after = 0;
    for (;;) {
        sd_event_t evs[64];
        size_t n = sd_store_snapshot(evs, 64, after);
        for (size_t i = 0; i < n; i++) {
            char one[1200];
            int m = sd_event_to_json(&evs[i], one, sizeof(one));
            if (m < 0) continue;
            char frame[1400];
            int f = snprintf(frame, sizeof(frame), "event: dns\ndata: %s\n\n", one);
            if (write(fd, frame, (size_t)f) < 0) return;
            after = evs[i].id;
        }
        sd_story_t sts[16];
        size_t ns = sd_story_snapshot(sts, 16, story_after);
        for (size_t i = 0; i < ns; i++) {
            char one[900];
            int m = sd_story_to_json(&sts[i], one, sizeof(one));
            if (m < 0) continue;
            char frame[1100];
            int f = snprintf(frame, sizeof(frame), "event: story\ndata: %s\n\n", one);
            if (write(fd, frame, (size_t)f) < 0) return;
            story_after = sts[i].id;
        }
        if (n == 0 && ns == 0) {
            if (write(fd, ": ping\n\n", 8) < 0) return;
        }
        usleep(200000);
    }
}

static void handle_api_block(int fd, const char *body) {
    const char *p = strstr(body ? body : "", "\"domain\"");
    char domain[256] = {0};
    if (p) {
        p = strchr(p + 8, '"');
        if (p) {
            p++;
            size_t i = 0;
            while (*p && *p != '"' && i + 1 < sizeof(domain)) domain[i++] = *p++;
            domain[i] = '\0';
        }
    }
    if (!domain[0] || sd_rules_add_block(domain) != 0) {
        http_respond(fd, 400, "application/json", "{\"ok\":false}", 12);
        return;
    }
    http_respond(fd, 200, "application/json", "{\"ok\":true}", 11);
}

static void handle_fluxtap(int fd, const char *body) {
    /* {"sni":"...","process":"...","ja3":"..."} */
    char sni[256] = {0}, process[128] = {0}, ja3[128] = {0};
    const char *p;
    if ((p = strstr(body ? body : "", "\"sni\""))) {
        p = strchr(p + 5, '"'); if (p) { p++; size_t i=0; while(*p&&*p!='"'&&i+1<sizeof(sni)) sni[i++]=*p++; sni[i]=0; }
    }
    if ((p = strstr(body ? body : "", "\"process\""))) {
        p = strchr(p + 9, '"'); if (p) { p++; size_t i=0; while(*p&&*p!='"'&&i+1<sizeof(process)) process[i++]=*p++; process[i]=0; }
    }
    if ((p = strstr(body ? body : "", "\"ja3\""))) {
        p = strchr(p + 5, '"'); if (p) { p++; size_t i=0; while(*p&&*p!='"'&&i+1<sizeof(ja3)) ja3[i++]=*p++; ja3[i]=0; }
    }
    if (!sni[0]) {
        http_respond(fd, 400, "application/json", "{\"ok\":false}", 12);
        return;
    }
    sd_fluxtap_note_sni(sni, process, ja3);
    http_respond(fd, 200, "application/json", "{\"ok\":true}", 11);
}

static int safe_join(const char *root, const char *rel, char *out, size_t out_sz) {
    if (strstr(rel, "..")) return -1;
    while (*rel == '/') rel++;
    if (!*rel) rel = "index.html";
    int n = snprintf(out, out_sz, "%s/%s", root, rel);
    return (n < 0 || (size_t)n >= out_sz) ? -1 : 0;
}

static void handle_static(int fd, const char *url_path) {
    char path[1024];
    if (safe_join(g_cfg->web_root, url_path, path, sizeof(path)) != 0) {
        http_respond(fd, 400, "text/plain", "bad path", 8);
        return;
    }
    int sfd = open(path, O_RDONLY);
    if (sfd < 0 && (strcmp(url_path, "/") == 0 || !url_path[0])) {
        snprintf(path, sizeof(path), "%s/index.html", g_cfg->web_root);
        sfd = open(path, O_RDONLY);
    }
    if (sfd < 0) { http_respond(fd, 404, "text/plain", "not found", 9); return; }
    struct stat st;
    if (fstat(sfd, &st) != 0 || !S_ISREG(st.st_mode)) {
        close(sfd); http_respond(fd, 404, "text/plain", "not found", 9); return;
    }
    char *body = malloc((size_t)st.st_size);
    if (!body) { close(sfd); http_respond(fd, 500, "text/plain", "oom", 3); return; }
    size_t got = 0;
    while (got < (size_t)st.st_size) {
        ssize_t r = read(sfd, body + got, (size_t)st.st_size - got);
        if (r <= 0) break;
        got += (size_t)r;
    }
    close(sfd);
    http_respond(fd, 200, mime_for(path), body, got);
    free(body);
}

static void handle_client(int cfd) {
    char req[16384];
    ssize_t n = read(cfd, req, sizeof(req) - 1);
    if (n <= 0) { close(cfd); return; }
    req[n] = '\0';
    char method[16], path[1024];
    if (sscanf(req, "%15s %1023s", method, path) != 2) {
        http_respond(cfd, 400, "text/plain", "bad request", 11);
        close(cfd); return;
    }
    char *q = strchr(path, '?');
    char query[256] = {0};
    if (q) { *q = '\0'; snprintf(query, sizeof(query), "%s", q + 1); }
    char *body = strstr(req, "\r\n\r\n");
    if (body) body += 4;

    if (!strcmp(method, "OPTIONS")) {
        http_respond(cfd, 204, "text/plain", "", 0);
        close(cfd); return;
    }

    if (!strcmp(path, "/api/stats")) handle_api_stats(cfd);
    else if (!strcmp(path, "/api/events")) {
        uint64_t after = 0;
        const char *a = strstr(query, "after=");
        if (a) after = strtoull(a + 6, NULL, 10);
        handle_api_events(cfd, after);
    } else if (!strcmp(path, "/api/stories")) {
        uint64_t after = 0;
        const char *a = strstr(query, "after=");
        if (a) after = strtoull(a + 6, NULL, 10);
        handle_api_stories(cfd, after);
    } else if (!strcmp(path, "/api/stream")) {
        handle_api_stream(cfd); close(cfd); return;
    } else if (!strcmp(path, "/api/rules")) {
        char *buf = malloc(256 * 1024);
        if (!buf) http_respond(cfd, 500, "text/plain", "oom", 3);
        else {
            int m = sd_rules_json(buf, 256 * 1024);
            http_respond(cfd, 200, "application/json", buf, m > 0 ? (size_t)m : 0);
            free(buf);
        }
    } else if (!strcmp(path, "/api/policy")) {
        char *buf = malloc(128 * 1024);
        if (!buf) http_respond(cfd, 500, "text/plain", "oom", 3);
        else {
            int m = sd_policy_json(buf, 128 * 1024);
            http_respond(cfd, 200, "application/json", buf, m > 0 ? (size_t)m : 0);
            free(buf);
        }
    } else if (!strcmp(path, "/api/block") && !strcmp(method, "POST"))
        handle_api_block(cfd, body ? body : "");
    else if (!strcmp(path, "/api/fluxtap") && !strcmp(method, "POST"))
        handle_fluxtap(cfd, body ? body : "");
    else if (!strcmp(path, "/api/sarif")) {
        char *buf = malloc(2 * 1024 * 1024);
        if (!buf) http_respond(cfd, 500, "text/plain", "oom", 3);
        else {
            int m = sd_sarif_export(buf, 2 * 1024 * 1024);
            http_respond(cfd, 200, "application/sarif+json", buf, m > 0 ? (size_t)m : 0);
            free(buf);
        }
    } else if (!strcmp(path, "/metrics")) {
        char buf[4096];
        int m = sd_metrics_render(buf, sizeof(buf));
        http_respond(cfd, 200, "text/plain; version=0.0.4", buf, m > 0 ? (size_t)m : 0);
    } else if (!strcmp(path, "/api/health"))
        http_respond(cfd, 200, "application/json", "{\"ok\":true}", 11);
    else handle_static(cfd, path);
    close(cfd);
}

static void *client_thread(void *arg) {
    handle_client((int)(intptr_t)arg);
    return NULL;
}

int sd_http_run(const sd_config_t *cfg) {
    g_cfg = cfg;
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) { perror("http socket"); return -1; }
    int yes = 1;
    setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons((uint16_t)cfg->http_port);
    inet_pton(AF_INET, cfg->bind_host, &addr.sin_addr);
    if (bind(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("bind http"); close(sock); return -1;
    }
    if (listen(sock, 128) < 0) { perror("listen"); close(sock); return -1; }
    fprintf(stderr, "ShadowDNS dashboard http://%s:%d\n",
            strcmp(cfg->bind_host, "0.0.0.0") == 0 ? "127.0.0.1" : cfg->bind_host,
            cfg->http_port);
    for (;;) {
        int cfd = accept(sock, NULL, NULL);
        if (cfd < 0) { if (errno == EINTR) continue; perror("accept"); continue; }
        pthread_t th;
        pthread_attr_t attr;
        pthread_attr_init(&attr);
        pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
        if (pthread_create(&th, &attr, client_thread, (void *)(intptr_t)cfd) != 0)
            close(cfd);
        pthread_attr_destroy(&attr);
    }
}

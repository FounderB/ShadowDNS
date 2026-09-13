#include "shadowdns.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdatomic.h>
#include <time.h>

static const sd_config_t *g_cfg;
static volatile int g_http_listening;
static atomic_int g_http_conn;

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
    char hdr[640];
    const char *msg = code == 200 ? "OK" : code == 401 ? "Unauthorized" :
                      code == 404 ? "Not Found" : code == 204 ? "No Content" :
                      code == 429 ? "Too Many Requests" : "Error";
    int n = snprintf(hdr, sizeof(hdr),
                     "HTTP/1.1 %d %s\r\nContent-Type: %s\r\nContent-Length: %zu\r\n"
                     "Cache-Control: no-store\r\n"
                     "X-Content-Type-Options: nosniff\r\n"
                     "X-Frame-Options: DENY\r\n"
                     "Referrer-Policy: no-referrer\r\n"
                     "Content-Security-Policy: default-src 'self'; style-src 'self' https://fonts.googleapis.com; font-src https://fonts.gstatic.com; img-src 'self' data:; connect-src 'self'\r\n"
                     "Connection: close\r\n\r\n",
                     code, msg, ctype, body_len);
    if (n > 0 && (size_t)n < sizeof(hdr)) send_all(fd, hdr, (size_t)n);
    if (body && body_len) send_all(fd, body, body_len);
}

static int extract_token(const char *req, const char *query, char *out, size_t out_sz) {
    out[0] = '\0';
    const char *h = strcasestr(req, "\nX-ShadowDNS-Token:");
    if (!h) h = strcasestr(req, "\nAuthorization:");
    if (h) {
        h = strchr(h, ':');
        if (h) {
            h++;
            while (*h == ' ') h++;
            if (!strncasecmp(h, "Bearer ", 7)) h += 7;
            size_t i = 0;
            while (h[i] && h[i] != '\r' && h[i] != '\n' && i + 1 < out_sz) {
                out[i] = h[i];
                i++;
            }
            out[i] = '\0';
            return out[0] != '\0';
        }
    }
    const char *q = strstr(query ? query : "", "token=");
    if (q) {
        q += 6;
        size_t i = 0;
        while (q[i] && q[i] != '&' && i + 1 < out_sz) {
            out[i] = q[i];
            i++;
        }
        out[i] = '\0';
        return out[0] != '\0';
    }
    return 0;
}

static int require_auth(int fd, const char *req, const char *query) {
    if (!g_cfg->api_token[0]) return 1; /* open mode if no token configured */
    char tok[160];
    if (!extract_token(req, query, tok, sizeof(tok)) || !sd_token_eq(tok, g_cfg->api_token)) {
        sd_store_bump_counter("auth_fail", 1);
        http_respond(fd, 401, "application/json",
                     "{\"ok\":false,\"error\":\"unauthorized\"}", 40);
        return 0;
    }
    return 1;
}

static void handle_api_stats(int fd) {
    sd_stats_t st;
    sd_store_stats(&st);
    char body[900];
    int n = snprintf(body, sizeof(body),
        "{\"version\":\"%s\",\"queries\":%llu,\"blocked\":%llu,\"alerts\":%llu,"
        "\"tunnels\":%llu,\"telemetry\":%llu,\"nxdomain\":%llu,\"unique\":%llu,"
        "\"dga\":%llu,\"fastflux\":%llu,\"doh_bypass\":%llu,\"stories\":%llu,"
        "\"ebpf_hits\":%llu,\"newly_seen\":%llu,\"auth_fail\":%llu,"
        "\"refused_clients\":%llu,\"block_mode\":%s,\"ebpf\":%s,\"auth_required\":%s}",
        SD_VERSION,
        (unsigned long long)st.queries, (unsigned long long)st.blocked,
        (unsigned long long)st.alerts, (unsigned long long)st.tunnels,
        (unsigned long long)st.telemetry, (unsigned long long)st.nxdomain,
        (unsigned long long)st.unique_names, (unsigned long long)st.dga,
        (unsigned long long)st.fastflux, (unsigned long long)st.doh_bypass,
        (unsigned long long)st.stories, (unsigned long long)st.ebpf_hits,
        (unsigned long long)st.newly_seen, (unsigned long long)st.auth_fail,
        (unsigned long long)st.refused_clients,
        g_cfg->block_mode ? "true" : "false",
        sd_ebpf_active() ? "true" : "false",
        g_cfg->api_token[0] ? "true" : "false");
    size_t len = sd_snprintf_copy(body, sizeof(body), n);
    http_respond(fd, 200, "application/json", body, len);
}

static void handle_api_events(int fd, uint64_t after) {
    sd_event_t evs[256];
    size_t n = sd_store_snapshot(evs, 256, after);
    size_t cap = 256 * 1200 + 32;
    char *body = malloc(cap);
    if (!body) { http_respond(fd, 500, "text/plain", "oom", 3); return; }
    size_t o = 0;
    body[o++] = '[';
    int first = 1;
    for (size_t i = 0; i < n; i++) {
        char one[1200];
        int m = sd_event_to_json(&evs[i], one, sizeof(one));
        size_t clen = sd_snprintf_copy(one, sizeof(one), m);
        if (!clen) continue;
        if (o + clen + 2 >= cap) break;
        if (!first) body[o++] = ',';
        first = 0;
        memcpy(body + o, one, clen);
        o += clen;
    }
    body[o++] = ']';
    http_respond(fd, 200, "application/json", body, o);
    free(body);
}

static void handle_api_stories(int fd, uint64_t after) {
    sd_story_t sts[64];
    size_t n = sd_story_snapshot(sts, 64, after);
    size_t cap = 64 * 900 + 32;
    char *body = malloc(cap);
    if (!body) { http_respond(fd, 500, "text/plain", "oom", 3); return; }
    size_t o = 0;
    body[o++] = '[';
    int first = 1;
    for (size_t i = 0; i < n; i++) {
        char one[900];
        int m = sd_story_to_json(&sts[i], one, sizeof(one));
        size_t clen = sd_snprintf_copy(one, sizeof(one), m);
        if (!clen) continue;
        if (o + clen + 2 >= cap) break;
        if (!first) body[o++] = ',';
        first = 0;
        memcpy(body + o, one, clen);
        o += clen;
    }
    body[o++] = ']';
    http_respond(fd, 200, "application/json", body, o);
    free(body);
}

static void handle_api_stream(int fd) {
    const char *hdr =
        "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\n"
        "Cache-Control: no-cache\r\n"
        "X-Content-Type-Options: nosniff\r\n"
        "Connection: keep-alive\r\n\r\n";
    send_all(fd, hdr, strlen(hdr));
    uint64_t after = 0, story_after = 0;
    time_t start = time(NULL);
    for (;;) {
        if (time(NULL) - start > SD_SSE_MAX_SEC) {
            send_all(fd, "event: bye\ndata: {\"reason\":\"timeout\"}\n\n", 42);
            return;
        }
        sd_event_t evs[64];
        size_t n = sd_store_snapshot(evs, 64, after);
        for (size_t i = 0; i < n; i++) {
            char one[1200];
            int m = sd_event_to_json(&evs[i], one, sizeof(one));
            size_t clen = sd_snprintf_copy(one, sizeof(one), m);
            if (!clen) continue;
            char frame[1400];
            int f = snprintf(frame, sizeof(frame), "event: dns\ndata: %s\n\n", one);
            size_t fl = sd_snprintf_copy(frame, sizeof(frame), f);
            if (write(fd, frame, fl) < 0) return;
            after = evs[i].id;
        }
        sd_story_t sts[16];
        size_t ns = sd_story_snapshot(sts, 16, story_after);
        for (size_t i = 0; i < ns; i++) {
            char one[900];
            int m = sd_story_to_json(&sts[i], one, sizeof(one));
            size_t clen = sd_snprintf_copy(one, sizeof(one), m);
            if (!clen) continue;
            char frame[1100];
            int f = snprintf(frame, sizeof(frame), "event: story\ndata: %s\n\n", one);
            size_t fl = sd_snprintf_copy(frame, sizeof(frame), f);
            if (write(fd, frame, fl) < 0) return;
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
    if (!domain[0] || strchr(domain, '\n') || strchr(domain, '\r') ||
        sd_rules_add_block(domain) != 0) {
        http_respond(fd, 400, "application/json", "{\"ok\":false}", 12);
        return;
    }
    http_respond(fd, 200, "application/json", "{\"ok\":true}", 11);
}

static void handle_fluxtap(int fd, const char *body) {
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
    if (!sni[0] || strchr(sni, '\n') || strchr(sni, '\r')) {
        http_respond(fd, 400, "application/json", "{\"ok\":false}", 12);
        return;
    }
    sd_fluxtap_note_sni(sni, process, ja3);
    http_respond(fd, 200, "application/json", "{\"ok\":true}", 11);
}

static int path_under_root(const char *root, const char *candidate) {
    char rreal[PATH_MAX], creal[PATH_MAX];
    if (!realpath(root, rreal)) return 0;
    if (!realpath(candidate, creal)) return 0;
    size_t rl = strlen(rreal);
    if (strncmp(creal, rreal, rl) != 0) return 0;
    return creal[rl] == '\0' || creal[rl] == '/';
}

static void handle_static(int fd, const char *url_path) {
    if (strstr(url_path, "..") || strchr(url_path, '\\')) {
        http_respond(fd, 400, "text/plain", "bad path", 8);
        return;
    }
    while (*url_path == '/') url_path++;
    if (!*url_path) url_path = "index.html";

    char path[PATH_MAX];
    if (snprintf(path, sizeof(path), "%s/%s", g_cfg->web_root, url_path) >= (int)sizeof(path)) {
        http_respond(fd, 400, "text/plain", "bad path", 8);
        return;
    }
    if (!path_under_root(g_cfg->web_root, path)) {
        /* try index fallback for missing realpath on new files — check exists */
        struct stat st0;
        if (stat(path, &st0) != 0) {
            http_respond(fd, 404, "text/plain", "not found", 9);
            return;
        }
        http_respond(fd, 400, "text/plain", "bad path", 8);
        return;
    }

    int sfd = open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    if (sfd < 0) {
        http_respond(fd, 404, "text/plain", "not found", 9);
        return;
    }
    struct stat st;
    if (fstat(sfd, &st) != 0 || !S_ISREG(st.st_mode) || st.st_size < 0 ||
        (size_t)st.st_size > SD_MAX_STATIC_BYTES) {
        close(sfd);
        http_respond(fd, 404, "text/plain", "not found", 9);
        return;
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

    /* static UI assets without auth; APIs require token when configured */
    int is_api = !strncmp(path, "/api/", 5) || !strcmp(path, "/metrics");
    if (is_api && strcmp(path, "/api/health") != 0) {
        if (!require_auth(cfd, req, query)) { close(cfd); return; }
    }

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
            size_t len = sd_snprintf_copy(buf, 256 * 1024, m);
            http_respond(cfd, 200, "application/json", buf, len);
            free(buf);
        }
    } else if (!strcmp(path, "/api/policy")) {
        char *buf = malloc(128 * 1024);
        if (!buf) http_respond(cfd, 500, "text/plain", "oom", 3);
        else {
            int m = sd_policy_json(buf, 128 * 1024);
            size_t len = sd_snprintf_copy(buf, 128 * 1024, m);
            http_respond(cfd, 200, "application/json", buf, len);
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
            size_t len = m > 0 ? (size_t)m : 0;
            if (len >= 2 * 1024 * 1024) len = 2 * 1024 * 1024 - 1;
            http_respond(cfd, 200, "application/sarif+json", buf, len);
            free(buf);
        }
    } else if (!strcmp(path, "/metrics")) {
        char buf[4096];
        int m = sd_metrics_render(buf, sizeof(buf));
        size_t len = sd_snprintf_copy(buf, sizeof(buf), m);
        http_respond(cfd, 200, "text/plain; version=0.0.4", buf, len);
    } else if (!strcmp(path, "/api/health"))
        http_respond(cfd, 200, "application/json", "{\"ok\":true}", 11);
    else handle_static(cfd, path);
    close(cfd);
}

static void *client_thread(void *arg) {
    int fd = (int)(intptr_t)arg;
    handle_client(fd);
    atomic_fetch_sub(&g_http_conn, 1);
    return NULL;
}

int sd_http_listening(void) { return g_http_listening; }

int sd_http_run(const sd_config_t *cfg) {
    g_cfg = cfg;
    g_http_listening = 0;
    atomic_store(&g_http_conn, 0);
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
        fprintf(stderr,
                "bind http %s:%d failed: %s\n"
                "  Tip: port busy — try --http-port 8089\n",
                cfg->bind_host, cfg->http_port, strerror(errno));
        close(sock);
        return -1;
    }
    if (listen(sock, 128) < 0) { perror("listen"); close(sock); return -1; }
    fprintf(stderr, "ShadowDNS dashboard http://%s:%d%s\n",
            cfg->bind_host, cfg->http_port,
            cfg->api_token[0] ? " (auth required)" : "");
    g_http_listening = 1;
    for (;;) {
        int cfd = accept(sock, NULL, NULL);
        if (cfd < 0) { if (errno == EINTR) continue; perror("accept"); continue; }
        if (atomic_load(&g_http_conn) >= SD_MAX_HTTP_CONN) {
            http_respond(cfd, 429, "text/plain", "busy", 4);
            close(cfd);
            continue;
        }
        atomic_fetch_add(&g_http_conn, 1);
        pthread_t th;
        pthread_attr_t attr;
        pthread_attr_init(&attr);
        pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
        if (pthread_create(&th, &attr, client_thread, (void *)(intptr_t)cfd) != 0) {
            atomic_fetch_sub(&g_http_conn, 1);
            close(cfd);
        }
        pthread_attr_destroy(&attr);
    }
}

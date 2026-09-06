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
    if (!strcmp(dot, ".png")) return "image/png";
    if (!strcmp(dot, ".ico")) return "image/x-icon";
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
                     "HTTP/1.1 %d %s\r\n"
                     "Content-Type: %s\r\n"
                     "Content-Length: %zu\r\n"
                     "Access-Control-Allow-Origin: *\r\n"
                     "Cache-Control: no-store\r\n"
                     "Connection: close\r\n\r\n",
                     code, msg, ctype, body_len);
    send_all(fd, hdr, (size_t)n);
    if (body && body_len) send_all(fd, body, body_len);
}

static int event_to_json(const sd_event_t *ev, char *buf, size_t buflen) {
    char qn[512], reason[256], tags[320], proc[256], cip[128];
    char tbuf[40];
    sd_json_escape(ev->qname, qn, sizeof(qn));
    sd_json_escape(ev->reason, reason, sizeof(reason));
    sd_json_escape(ev->tags, tags, sizeof(tags));
    sd_json_escape(ev->process, proc, sizeof(proc));
    sd_json_escape(ev->client_ip, cip, sizeof(cip));
    sd_iso_time(ev->ts, tbuf, sizeof(tbuf));
    const char *sev[] = {"info", "low", "med", "high", "crit"};
    const char *act[] = {"allow", "alert", "block"};
    return snprintf(buf, buflen,
        "{\"id\":%llu,\"ts\":\"%s\",\"qname\":\"%s\",\"qtype\":\"%s\","
        "\"qtype_id\":%u,\"client\":\"%s\",\"port\":%u,\"process\":\"%s\","
        "\"pid\":\"%s\",\"severity\":\"%s\",\"action\":\"%s\",\"reason\":\"%s\","
        "\"tags\":\"%s\",\"entropy\":%.3f,\"answers\":%d,\"rcode\":%d,"
        "\"latency_ms\":%d}",
        (unsigned long long)ev->id, tbuf, qn, sd_dns_type_name(ev->qtype),
        ev->qtype, cip, ev->client_port, proc, ev->pid,
        sev[ev->severity], act[ev->action], reason, tags,
        ev->entropy, ev->answer_count, ev->rcode, ev->latency_ms);
}

static void handle_api_stats(int fd) {
    sd_stats_t st;
    sd_store_stats(&st);
    char body[512];
    int n = snprintf(body, sizeof(body),
        "{\"version\":\"%s\",\"queries\":%llu,\"blocked\":%llu,\"alerts\":%llu,"
        "\"tunnels\":%llu,\"telemetry\":%llu,\"nxdomain\":%llu,\"unique\":%llu,"
        "\"block_mode\":%s}",
        SD_VERSION,
        (unsigned long long)st.queries,
        (unsigned long long)st.blocked,
        (unsigned long long)st.alerts,
        (unsigned long long)st.tunnels,
        (unsigned long long)st.telemetry,
        (unsigned long long)st.nxdomain,
        (unsigned long long)st.unique_names,
        g_cfg->block_mode ? "true" : "false");
    http_respond(fd, 200, "application/json", body, (size_t)n);
}

static void handle_api_events(int fd, uint64_t after) {
    sd_event_t evs[256];
    size_t n = sd_store_snapshot(evs, 256, after);
    size_t cap = 256 * 900 + 32;
    char *body = malloc(cap);
    if (!body) {
        http_respond(fd, 500, "text/plain", "oom", 3);
        return;
    }
    size_t o = 0;
    body[o++] = '[';
    for (size_t i = 0; i < n; i++) {
        char one[900];
        int m = event_to_json(&evs[i], one, sizeof(one));
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

static void handle_api_stream(int fd) {
    const char *hdr =
        "HTTP/1.1 200 OK\r\n"
        "Content-Type: text/event-stream\r\n"
        "Cache-Control: no-cache\r\n"
        "Access-Control-Allow-Origin: *\r\n"
        "Connection: keep-alive\r\n\r\n";
    send_all(fd, hdr, strlen(hdr));

    uint64_t after = 0;
    for (;;) {
        sd_event_t evs[64];
        size_t n = sd_store_snapshot(evs, 64, after);
        for (size_t i = 0; i < n; i++) {
            char one[900];
            int m = event_to_json(&evs[i], one, sizeof(one));
            if (m < 0) continue;
            char frame[1024];
            int f = snprintf(frame, sizeof(frame), "data: %s\n\n", one);
            if (write(fd, frame, (size_t)f) < 0) return;
            after = evs[i].id;
        }
        /* heartbeat */
        if (n == 0) {
            if (write(fd, ": ping\n\n", 8) < 0) return;
        }
        usleep(200000);
    }
}

static void handle_api_rules(int fd) {
    char *buf = malloc(256 * 1024);
    if (!buf) {
        http_respond(fd, 500, "text/plain", "oom", 3);
        return;
    }
    int n = sd_rules_json(buf, 256 * 1024);
    if (n < 0) n = 0;
    http_respond(fd, 200, "application/json", buf, (size_t)n);
    free(buf);
}

static void handle_api_block(int fd, const char *body) {
    /* expect {"domain":"evil.com"} */
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
    if (!domain[0]) {
        http_respond(fd, 400, "application/json", "{\"ok\":false}", 12);
        return;
    }
    if (sd_rules_add_block(domain) != 0) {
        http_respond(fd, 500, "application/json", "{\"ok\":false}", 12);
        return;
    }
    http_respond(fd, 200, "application/json", "{\"ok\":true}", 11);
}

static int safe_join(const char *root, const char *rel, char *out, size_t out_sz) {
    if (strstr(rel, "..")) return -1;
    while (*rel == '/') rel++;
    if (!*rel) rel = "index.html";
    int n = snprintf(out, out_sz, "%s/%s", root, rel);
    if (n < 0 || (size_t)n >= out_sz) return -1;
    return 0;
}

static void handle_static(int fd, const char *url_path) {
    char path[1024];
    if (safe_join(g_cfg->web_root, url_path, path, sizeof(path)) != 0) {
        http_respond(fd, 400, "text/plain", "bad path", 8);
        return;
    }
    int sfd = open(path, O_RDONLY);
    if (sfd < 0) {
        /* try index.html for / */
        if (strcmp(url_path, "/") == 0 || url_path[0] == '\0') {
            snprintf(path, sizeof(path), "%s/index.html", g_cfg->web_root);
            sfd = open(path, O_RDONLY);
        }
    }
    if (sfd < 0) {
        http_respond(fd, 404, "text/plain", "not found", 9);
        return;
    }
    struct stat st;
    if (fstat(sfd, &st) != 0 || !S_ISREG(st.st_mode)) {
        close(sfd);
        http_respond(fd, 404, "text/plain", "not found", 9);
        return;
    }
    char *body = malloc((size_t)st.st_size);
    if (!body) {
        close(sfd);
        http_respond(fd, 500, "text/plain", "oom", 3);
        return;
    }
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
    char req[8192];
    ssize_t n = read(cfd, req, sizeof(req) - 1);
    if (n <= 0) { close(cfd); return; }
    req[n] = '\0';

    char method[16], path[1024];
    if (sscanf(req, "%15s %1023s", method, path) != 2) {
        http_respond(cfd, 400, "text/plain", "bad request", 11);
        close(cfd);
        return;
    }

    char *q = strchr(path, '?');
    char query[256] = {0};
    if (q) {
        *q = '\0';
        snprintf(query, sizeof(query), "%s", q + 1);
    }

    if (strcmp(method, "OPTIONS") == 0) {
        http_respond(cfd, 204, "text/plain", "", 0);
        close(cfd);
        return;
    }

    if (strcmp(path, "/api/stats") == 0) {
        handle_api_stats(cfd);
    } else if (strcmp(path, "/api/events") == 0) {
        uint64_t after = 0;
        const char *a = strstr(query, "after=");
        if (a) after = strtoull(a + 6, NULL, 10);
        handle_api_events(cfd, after);
    } else if (strcmp(path, "/api/stream") == 0) {
        handle_api_stream(cfd);
        close(cfd);
        return;
    } else if (strcmp(path, "/api/rules") == 0) {
        handle_api_rules(cfd);
    } else if (strcmp(path, "/api/block") == 0 && strcmp(method, "POST") == 0) {
        char *body = strstr(req, "\r\n\r\n");
        handle_api_block(cfd, body ? body + 4 : "");
    } else if (strcmp(path, "/api/health") == 0) {
        http_respond(cfd, 200, "application/json", "{\"ok\":true}", 11);
    } else {
        handle_static(cfd, path);
    }
    close(cfd);
}

static void *client_thread(void *arg) {
    int fd = (int)(intptr_t)arg;
    handle_client(fd);
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
        perror("bind http");
        close(sock);
        return -1;
    }
    if (listen(sock, 64) < 0) {
        perror("listen");
        close(sock);
        return -1;
    }

    fprintf(stderr, "ShadowDNS dashboard http://%s:%d\n",
            strcmp(cfg->bind_host, "0.0.0.0") == 0 ? "127.0.0.1" : cfg->bind_host,
            cfg->http_port);

    for (;;) {
        int cfd = accept(sock, NULL, NULL);
        if (cfd < 0) {
            if (errno == EINTR) continue;
            perror("accept");
            continue;
        }
        pthread_t th;
        pthread_attr_t attr;
        pthread_attr_init(&attr);
        pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
        if (pthread_create(&th, &attr, client_thread, (void *)(intptr_t)cfd) != 0) {
            close(cfd);
        }
        pthread_attr_destroy(&attr);
    }
}

#include "shadowdns.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

static int is_blocked_ssrf_addr(const struct sockaddr *sa) {
    if (sa->sa_family == AF_INET) {
        const struct sockaddr_in *in = (const struct sockaddr_in *)sa;
        uint32_t ip = ntohl(in->sin_addr.s_addr);
        if ((ip >> 24) == 127) return 1;                 /* 127.0.0.0/8 */
        if ((ip >> 24) == 10) return 1;                  /* 10/8 */
        if ((ip >> 20) == 0xac1) return 1;               /* 172.16/12 */
        if ((ip >> 16) == 0xc0a8) return 1;              /* 192.168/16 */
        if ((ip >> 16) == 0xa9fe) return 1;              /* 169.254/16 link-local/IMDS */
        if ((ip >> 24) == 0) return 1;                   /* 0/8 */
        if ((ip >> 28) == 0xe) return 1;                 /* multicast */
    }
    if (sa->sa_family == AF_INET6) {
        const struct sockaddr_in6 *in6 = (const struct sockaddr_in6 *)sa;
        const uint8_t *b = in6->sin6_addr.s6_addr;
        /* ::1 and fc00::/7 unique local and fe80::/10 */
        int loop = 1;
        for (int i = 0; i < 15; i++) if (b[i]) loop = 0;
        if (loop && b[15] == 1) return 1;
        if ((b[0] & 0xfe) == 0xfc) return 1;
        if (b[0] == 0xfe && (b[1] & 0xc0) == 0x80) return 1;
    }
    return 0;
}

static void http_post_raw(const char *url, const char *body, const char *ctype, int insecure) {
    if (!url || !url[0] || !body) return;
    const char *p = url;
    int tls = 0;
    if (!strncmp(p, "https://", 8)) { tls = 1; p += 8; }
    else if (!strncmp(p, "http://", 7)) { p += 7; }
    else return;
    if (strchr(p, '\r') || strchr(p, '\n')) return;

    char host[256], path[512];
    snprintf(host, sizeof(host), "%s", p);
    char *slash = strchr(host, '/');
    if (slash) {
        snprintf(path, sizeof(path), "%s", slash);
        *slash = '\0';
    } else {
        snprintf(path, sizeof(path), "/");
    }
    int port = tls ? 443 : 80;
    char *colon = strrchr(host, ':');
    if (colon && strchr(host, ':') == colon) {
        *colon = '\0';
        port = atoi(colon + 1);
    }

    char portstr[16];
    snprintf(portstr, sizeof(portstr), "%d", port);
    struct addrinfo hints, *res = NULL, *rp;
    memset(&hints, 0, sizeof(hints));
    hints.ai_socktype = SOCK_STREAM;
    if (getaddrinfo(host, portstr, &hints, &res) != 0 || !res) return;

    int fd = -1;
    for (rp = res; rp; rp = rp->ai_next) {
        if (is_blocked_ssrf_addr(rp->ai_addr)) continue; /* SSRF harden */
        fd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (fd < 0) continue;
        if (connect(fd, rp->ai_addr, rp->ai_addrlen) == 0) break;
        close(fd);
        fd = -1;
    }
    freeaddrinfo(res);
    if (fd < 0) return;

    char hdr[1024];
    int hl = snprintf(hdr, sizeof(hdr),
                      "POST %s HTTP/1.1\r\nHost: %s\r\nContent-Type: %s\r\n"
                      "Content-Length: %zu\r\nConnection: close\r\n\r\n",
                      path, host, ctype ? ctype : "application/json", strlen(body));
    if (hl < 0 || (size_t)hl >= sizeof(hdr)) { close(fd); return; }

    if (tls) {
        SSL_library_init();
        SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
        if (!ctx) { close(fd); return; }
        SSL_CTX_set_default_verify_paths(ctx);
        SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
        if (!insecure) SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
        else SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);
        SSL *ssl = SSL_new(ctx);
        SSL_set_tlsext_host_name(ssl, host);
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
        if (!insecure) SSL_set1_host(ssl, host);
#endif
        SSL_set_fd(ssl, fd);
        int ok = (SSL_connect(ssl) == 1);
        if (ok && !insecure && SSL_get_verify_result(ssl) != X509_V_OK) ok = 0;
        if (ok) {
            SSL_write(ssl, hdr, hl);
            SSL_write(ssl, body, (int)strlen(body));
            SSL_shutdown(ssl);
        }
        SSL_free(ssl);
        SSL_CTX_free(ctx);
    } else {
        /* plaintext webhook only if explicitly insecure */
        if (!insecure) { close(fd); return; }
        send(fd, hdr, (size_t)hl, 0);
        send(fd, body, strlen(body), 0);
    }
    close(fd);
}

typedef struct {
    char url[512];
    char token[256];
    char chat[64];
    char body[1200];
    int insecure;
} notify_job_t;

static void *notify_thr(void *arg) {
    notify_job_t *j = arg;
    if (j->url[0]) http_post_raw(j->url, j->body, "application/json", j->insecure);
    if (j->token[0] && j->chat[0]) {
        char url[640];
        snprintf(url, sizeof(url),
                 "https://api.telegram.org/bot%s/sendMessage", j->token);
        char chat_esc[128], text_esc[1000];
        sd_json_escape(j->chat, chat_esc, sizeof(chat_esc));
        /* short summary only — avoid dumping full JSON with token risk in logs */
        char text[256];
        snprintf(text, sizeof(text), "%.200s", j->body);
        sd_json_escape(text, text_esc, sizeof(text_esc));
        char payload[1400];
        snprintf(payload, sizeof(payload),
                 "{\"chat_id\":\"%s\",\"text\":\"ShadowDNS HIGH/CRIT\\n%s\"}",
                 chat_esc, text_esc);
        http_post_raw(url, payload, "application/json", j->insecure);
    }
    /* scrub token from memory */
    memset(j->token, 0, sizeof(j->token));
    free(j);
    return NULL;
}

void sd_notify_event(const sd_config_t *cfg, const sd_event_t *ev) {
    if (!cfg || !ev) return;
    if (ev->severity < SD_SEV_HIGH) return;
    if (!cfg->webhook_url[0] && !(cfg->telegram_token[0] && cfg->telegram_chat[0]))
        return;
    notify_job_t *j = calloc(1, sizeof(*j));
    if (!j) return;
    snprintf(j->url, sizeof(j->url), "%s", cfg->webhook_url);
    snprintf(j->token, sizeof(j->token), "%s", cfg->telegram_token);
    snprintf(j->chat, sizeof(j->chat), "%s", cfg->telegram_chat);
    j->insecure = cfg->tls_insecure;
    sd_event_to_json(ev, j->body, sizeof(j->body));
    pthread_t th;
    pthread_attr_t attr;
    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
    if (pthread_create(&th, &attr, notify_thr, j) != 0) {
        memset(j->token, 0, sizeof(j->token));
        free(j);
    }
    pthread_attr_destroy(&attr);
}

void sd_jsonl_write(const sd_config_t *cfg, const sd_event_t *ev) {
    if (!cfg || !cfg->jsonl_path[0] || !ev) return;
    int fd = open(cfg->jsonl_path, O_WRONLY | O_CREAT | O_APPEND, 0600);
    if (fd < 0) return;
    (void)fchmod(fd, 0600);
    char line[1600];
    int n = sd_event_to_json(ev, line, sizeof(line));
    size_t len = sd_snprintf_copy(line, sizeof(line), n);
    if (len) {
        write(fd, line, len);
        write(fd, "\n", 1);
    }
    close(fd);
}

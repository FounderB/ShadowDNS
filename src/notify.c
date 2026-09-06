#include "shadowdns.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <sys/socket.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

static void http_post_raw(const char *url, const char *body, const char *ctype) {
    if (!url || !url[0] || !body) return;
    const char *p = url;
    int tls = 0;
    if (!strncmp(p, "https://", 8)) { tls = 1; p += 8; }
    else if (!strncmp(p, "http://", 7)) { p += 7; }
    else return;
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
    struct addrinfo hints, *res = NULL;
    memset(&hints, 0, sizeof(hints));
    hints.ai_socktype = SOCK_STREAM;
    if (getaddrinfo(host, portstr, &hints, &res) != 0 || !res) return;
    int fd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (fd < 0) { freeaddrinfo(res); return; }
    if (connect(fd, res->ai_addr, res->ai_addrlen) != 0) {
        close(fd); freeaddrinfo(res); return;
    }
    freeaddrinfo(res);

    char hdr[1024];
    int hl = snprintf(hdr, sizeof(hdr),
                      "POST %s HTTP/1.1\r\nHost: %s\r\nContent-Type: %s\r\n"
                      "Content-Length: %zu\r\nConnection: close\r\n\r\n",
                      path, host, ctype ? ctype : "application/json", strlen(body));

    if (tls) {
        SSL_library_init();
        SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
        if (!ctx) { close(fd); return; }
        SSL *ssl = SSL_new(ctx);
        SSL_set_tlsext_host_name(ssl, host);
        SSL_set_fd(ssl, fd);
        if (SSL_connect(ssl) == 1) {
            SSL_write(ssl, hdr, hl);
            SSL_write(ssl, body, (int)strlen(body));
            SSL_shutdown(ssl);
        }
        SSL_free(ssl);
        SSL_CTX_free(ctx);
    } else {
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
} notify_job_t;

static void *notify_thr(void *arg) {
    notify_job_t *j = arg;
    if (j->url[0]) http_post_raw(j->url, j->body, "application/json");
    if (j->token[0] && j->chat[0]) {
        char url[640];
        snprintf(url, sizeof(url),
                 "https://api.telegram.org/bot%s/sendMessage", j->token);
        char payload[1600];
        char text[900];
        /* body already json event; send compact text */
        snprintf(text, sizeof(text), "%s", j->body);
        char esc[1000];
        sd_json_escape(text, esc, sizeof(esc));
        snprintf(payload, sizeof(payload),
                 "{\"chat_id\":\"%s\",\"text\":\"ShadowDNS CRIT\\n%s\"}",
                 j->chat, esc);
        http_post_raw(url, payload, "application/json");
    }
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
    sd_event_to_json(ev, j->body, sizeof(j->body));
    pthread_t th;
    pthread_attr_t attr;
    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
    if (pthread_create(&th, &attr, notify_thr, j) != 0) free(j);
    pthread_attr_destroy(&attr);
}

void sd_jsonl_write(const sd_config_t *cfg, const sd_event_t *ev) {
    if (!cfg || !cfg->jsonl_path[0] || !ev) return;
    FILE *f = fopen(cfg->jsonl_path, "a");
    if (!f) return;
    char line[1600];
    int n = sd_event_to_json(ev, line, sizeof(line));
    if (n > 0) {
        fwrite(line, 1, (size_t)n, f);
        fputc('\n', f);
    }
    fclose(f);
}

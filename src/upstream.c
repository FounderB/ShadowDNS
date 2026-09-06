#include "shadowdns.h"

#include <arpa/inet.h>
#include <errno.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

static int udp_query(const sd_upstream_t *up, const uint8_t *req, size_t req_len,
                     uint8_t *resp, size_t resp_sz) {
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) return -1;
    struct timeval tv = {.tv_sec = 2, .tv_usec = 0};
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons((uint16_t)up->port);
    if (inet_pton(AF_INET, up->host, &addr.sin_addr) != 1) {
        /* resolve hostname */
        struct addrinfo hints, *res = NULL;
        memset(&hints, 0, sizeof(hints));
        hints.ai_family = AF_INET;
        hints.ai_socktype = SOCK_DGRAM;
        if (getaddrinfo(up->host, NULL, &hints, &res) != 0 || !res) {
            close(fd);
            return -1;
        }
        addr.sin_addr = ((struct sockaddr_in *)res->ai_addr)->sin_addr;
        freeaddrinfo(res);
    }
    if (sendto(fd, req, req_len, 0, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        close(fd);
        return -1;
    }
    ssize_t n = recvfrom(fd, resp, resp_sz, 0, NULL, NULL);
    close(fd);
    return n > 0 ? (int)n : -1;
}

static int tcp_connect_host(const char *host, int port) {
    char portstr[16];
    snprintf(portstr, sizeof(portstr), "%d", port);
    struct addrinfo hints, *res = NULL, *rp;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    if (getaddrinfo(host, portstr, &hints, &res) != 0) return -1;
    int fd = -1;
    for (rp = res; rp; rp = rp->ai_next) {
        fd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (fd < 0) continue;
        struct timeval tv = {.tv_sec = 3, .tv_usec = 0};
        setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
        setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
        if (connect(fd, rp->ai_addr, rp->ai_addrlen) == 0) break;
        close(fd);
        fd = -1;
    }
    freeaddrinfo(res);
    return fd;
}

static SSL_CTX *ssl_ctx(void) {
    static SSL_CTX *ctx;
    static int init;
    if (!init) {
        SSL_library_init();
        OpenSSL_add_all_algorithms();
        SSL_load_error_strings();
        ctx = SSL_CTX_new(TLS_client_method());
        if (ctx) SSL_CTX_set_default_verify_paths(ctx);
        init = 1;
    }
    return ctx;
}

static int dot_query(const sd_upstream_t *up, const uint8_t *req, size_t req_len,
                     uint8_t *resp, size_t resp_sz) {
    if (req_len > 65535) return -1;
    int fd = tcp_connect_host(up->host, up->port ? up->port : 853);
    if (fd < 0) return -1;
    SSL_CTX *ctx = ssl_ctx();
    if (!ctx) { close(fd); return -1; }
    SSL *ssl = SSL_new(ctx);
    SSL_set_tlsext_host_name(ssl, up->host);
    SSL_set_fd(ssl, fd);
    if (SSL_connect(ssl) != 1) {
        SSL_free(ssl);
        close(fd);
        return -1;
    }
    uint8_t hdr[2] = {(uint8_t)(req_len >> 8), (uint8_t)(req_len & 0xff)};
    if (SSL_write(ssl, hdr, 2) != 2 || SSL_write(ssl, req, (int)req_len) != (int)req_len) {
        SSL_free(ssl);
        close(fd);
        return -1;
    }
    uint8_t rh[2];
    if (SSL_read(ssl, rh, 2) != 2) {
        SSL_free(ssl);
        close(fd);
        return -1;
    }
    size_t rlen = ((size_t)rh[0] << 8) | rh[1];
    if (rlen > resp_sz) rlen = resp_sz;
    size_t got = 0;
    while (got < rlen) {
        int n = SSL_read(ssl, resp + got, (int)(rlen - got));
        if (n <= 0) break;
        got += (size_t)n;
    }
    SSL_shutdown(ssl);
    SSL_free(ssl);
    close(fd);
    return got > 0 ? (int)got : -1;
}

static int b64url(const uint8_t *in, size_t in_len, char *out, size_t out_sz) {
    static const char *t =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    size_t o = 0;
    for (size_t i = 0; i < in_len; i += 3) {
        unsigned v = in[i] << 16;
        if (i + 1 < in_len) v |= in[i + 1] << 8;
        if (i + 2 < in_len) v |= in[i + 2];
        char c[4];
        c[0] = t[(v >> 18) & 63];
        c[1] = t[(v >> 12) & 63];
        c[2] = (i + 1 < in_len) ? t[(v >> 6) & 63] : '=';
        c[3] = (i + 2 < in_len) ? t[v & 63] : '=';
        for (int j = 0; j < 4; j++) {
            char ch = c[j];
            if (ch == '+') ch = '-';
            else if (ch == '/') ch = '_';
            else if (ch == '=') continue;
            if (o + 1 >= out_sz) return -1;
            out[o++] = ch;
        }
    }
    out[o] = '\0';
    return (int)o;
}

static int doh_query(const sd_upstream_t *up, const uint8_t *req, size_t req_len,
                     uint8_t *resp, size_t resp_sz) {
    char b64[1024];
    if (b64url(req, req_len, b64, sizeof(b64)) < 0) return -1;
    int fd = tcp_connect_host(up->host, up->port ? up->port : 443);
    if (fd < 0) return -1;
    SSL_CTX *ctx = ssl_ctx();
    if (!ctx) { close(fd); return -1; }
    SSL *ssl = SSL_new(ctx);
    SSL_set_tlsext_host_name(ssl, up->host);
    SSL_set_fd(ssl, fd);
    if (SSL_connect(ssl) != 1) {
        SSL_free(ssl);
        close(fd);
        return -1;
    }
    char reqhttp[1600];
    int n = snprintf(reqhttp, sizeof(reqhttp),
                     "GET %s?dns=%s HTTP/1.1\r\n"
                     "Host: %s\r\n"
                     "Accept: application/dns-message\r\n"
                     "Connection: close\r\n\r\n",
                     up->doh_path[0] ? up->doh_path : "/dns-query", b64, up->host);
    if (SSL_write(ssl, reqhttp, n) != n) {
        SSL_free(ssl);
        close(fd);
        return -1;
    }
    char buf[8192];
    size_t got = 0;
    while (got + 1 < sizeof(buf)) {
        int r = SSL_read(ssl, buf + got, (int)(sizeof(buf) - 1 - got));
        if (r <= 0) break;
        got += (size_t)r;
    }
    buf[got] = '\0';
    SSL_shutdown(ssl);
    SSL_free(ssl);
    close(fd);

    char *body = strstr(buf, "\r\n\r\n");
    if (!body) return -1;
    body += 4;
    /* handle simple chunked or content-length raw body; prefer content-length */
    const char *cl = strcasestr(buf, "Content-Length:");
    size_t blen = got - (size_t)(body - buf);
    if (cl) {
        blen = (size_t)strtoul(cl + 15, NULL, 10);
        if (blen > got - (size_t)(body - buf))
            blen = got - (size_t)(body - buf);
    }
    if (blen > resp_sz) blen = resp_sz;
    memcpy(resp, body, blen);
    return blen > 12 ? (int)blen : -1;
}

static int query_one(const sd_upstream_t *up, const uint8_t *req, size_t req_len,
                     uint8_t *resp, size_t resp_sz) {
    switch (up->kind) {
        case SD_UP_DOT: return dot_query(up, req, req_len, resp, resp_sz);
        case SD_UP_DOH: return doh_query(up, req, req_len, resp, resp_sz);
        case SD_UP_UDP:
        default: return udp_query(up, req, req_len, resp, resp_sz);
    }
}

int sd_upstream_query(const sd_config_t *cfg, const char *qname,
                      const uint8_t *req, size_t req_len,
                      uint8_t *resp, size_t resp_sz, int *latency_ms) {
    uint64_t t0 = sd_now_ms();
    sd_upstream_t split;
    if (sd_split_lookup(qname, &split)) {
        int n = query_one(&split, req, req_len, resp, resp_sz);
        *latency_ms = (int)(sd_now_ms() - t0);
        if (n > 0) return n;
    }
    for (int i = 0; i < cfg->upstream_count; i++) {
        int n = query_one(&cfg->upstreams[i], req, req_len, resp, resp_sz);
        if (n > 0) {
            *latency_ms = (int)(sd_now_ms() - t0);
            return n;
        }
    }
    *latency_ms = (int)(sd_now_ms() - t0);
    return -1;
}

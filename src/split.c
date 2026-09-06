#include "shadowdns.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <ctype.h>
#include <pthread.h>

typedef struct {
    char pattern[128];
    sd_upstream_t up;
} sd_split_t;

static sd_split_t splits[SD_MAX_SPLIT];
static int split_n;
static pthread_mutex_t mu = PTHREAD_MUTEX_INITIALIZER;

static void trim(char *s) {
    char *p = s;
    while (*p && isspace((unsigned char)*p)) p++;
    if (p != s) memmove(s, p, strlen(p) + 1);
    size_t n = strlen(s);
    while (n && isspace((unsigned char)s[n - 1])) s[--n] = '\0';
}

static int parse_up(const char *spec, sd_upstream_t *u) {
    memset(u, 0, sizeof(*u));
    snprintf(u->doh_path, sizeof(u->doh_path), "/dns-query");
    if (!strncmp(spec, "udp:", 4)) { u->kind = SD_UP_UDP; spec += 4; u->port = 53; }
    else if (!strncmp(spec, "dot:", 4)) { u->kind = SD_UP_DOT; spec += 4; u->port = 853; }
    else if (!strncmp(spec, "doh:", 4)) { u->kind = SD_UP_DOH; spec += 4; u->port = 443; }
    else { u->kind = SD_UP_UDP; u->port = 53; }
    char tmp[160];
    snprintf(tmp, sizeof(tmp), "%s", spec);
    char *slash = strchr(tmp, '/');
    if (slash && u->kind == SD_UP_DOH) {
        *slash = '\0';
        snprintf(u->doh_path, sizeof(u->doh_path), "/%s", slash + 1);
    }
    char *colon = strrchr(tmp, ':');
    if (colon && strchr(tmp, ':') == colon) {
        *colon = '\0';
        u->port = atoi(colon + 1);
    }
    snprintf(u->host, sizeof(u->host), "%s", tmp);
    return 0;
}

static int domain_match(const char *qname, const char *pat) {
    if (pat[0] == '*' && pat[1] == '.') {
        size_t qn = strlen(qname), pn = strlen(pat + 1);
        if (qn >= pn && strcasecmp(qname + qn - pn, pat + 1) == 0) return 1;
        return strcasecmp(qname, pat + 2) == 0;
    }
    return strcasecmp(qname, pat) == 0 ||
           (strlen(qname) > strlen(pat) &&
            qname[strlen(qname) - strlen(pat) - 1] == '.' &&
            strcasecmp(qname + strlen(qname) - strlen(pat), pat) == 0);
}

int sd_split_load(const char *path) {
    pthread_mutex_lock(&mu);
    split_n = 0;
    pthread_mutex_unlock(&mu);
    if (!path || !path[0]) return 0;
    FILE *f = fopen(path, "r");
    if (!f) return 0;
    char line[512];
    int n = 0;
    while (fgets(line, sizeof(line), f)) {
        trim(line);
        if (!line[0] || line[0] == '#') continue;
        char *eq = strchr(line, '=');
        if (!eq) continue;
        *eq = '\0';
        trim(line);
        trim(eq + 1);
        sd_split_t s;
        memset(&s, 0, sizeof(s));
        snprintf(s.pattern, sizeof(s.pattern), "%s", line);
        parse_up(eq + 1, &s.up);
        pthread_mutex_lock(&mu);
        if (split_n < SD_MAX_SPLIT) {
            splits[split_n++] = s;
            n++;
        }
        pthread_mutex_unlock(&mu);
    }
    fclose(f);
    return n;
}

int sd_split_lookup(const char *qname, sd_upstream_t *out) {
    pthread_mutex_lock(&mu);
    for (int i = 0; i < split_n; i++) {
        if (domain_match(qname, splits[i].pattern)) {
            *out = splits[i].up;
            pthread_mutex_unlock(&mu);
            return 1;
        }
    }
    pthread_mutex_unlock(&mu);
    return 0;
}

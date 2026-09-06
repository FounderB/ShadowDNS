#include "shadowdns.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <ctype.h>
#include <pthread.h>

typedef struct {
    char *pat;
    int kind; /* 0 block 1 allow 2 telemetry */
} sd_rule_t;

static sd_rule_t rules[SD_MAX_RULES];
static int rule_n;
static pthread_mutex_t mu = PTHREAD_MUTEX_INITIALIZER;

static void trim(char *s) {
    char *p = s;
    while (*p && isspace((unsigned char)*p)) p++;
    if (p != s) memmove(s, p, strlen(p) + 1);
    size_t n = strlen(s);
    while (n && isspace((unsigned char)s[n - 1])) s[--n] = '\0';
}

static int domain_match(const char *qname, const char *pat) {
    if (!qname || !pat || !*pat) return 0;
    if (pat[0] == '*' && pat[1] == '.') {
        const char *suf = pat + 1; /* ".example.com" */
        size_t qn = strlen(qname), sn = strlen(suf);
        if (qn < sn) return 0;
        if (strcasecmp(qname + qn - sn, suf) == 0) return 1;
        return strcasecmp(qname, pat + 2) == 0;
    }
    if (strcasecmp(qname, pat) == 0) return 1;
    size_t qn = strlen(qname), pn = strlen(pat);
    if (qn > pn + 1 && qname[qn - pn - 1] == '.' &&
        strcasecmp(qname + qn - pn, pat) == 0)
        return 1;
    return 0;
}

static int load_file(const char *path, int kind) {
    if (!path || !*path) return 0;
    FILE *f = fopen(path, "r");
    if (!f) return 0;
    char line[512];
    int added = 0;
    while (fgets(line, sizeof(line), f)) {
        trim(line);
        if (!line[0] || line[0] == '#') continue;
        if (rule_n >= SD_MAX_RULES) break;
        rules[rule_n].pat = strdup(line);
        rules[rule_n].kind = kind;
        if (rules[rule_n].pat) {
            rule_n++;
            added++;
        }
    }
    fclose(f);
    return added;
}

int sd_rules_load(const sd_config_t *cfg) {
    pthread_mutex_lock(&mu);
    for (int i = 0; i < rule_n; i++) free(rules[i].pat);
    rule_n = 0;
    load_file(cfg->blocklist_path, 0);
    load_file(cfg->allowlist_path, 1);
    load_file(cfg->telemetry_path, 2);
    /* built-in high-signal telemetry / phone-home hints */
    const char *builtin_tel[] = {
        "google-analytics.com",
        "api2.amplitude.com",
        "api.segment.io",
        "sentry.io",
        "ingest.sentry.io",
        "telemetry.mozilla.org",
        "stats.grafana.org",
        "browser-intake.googleapis.com",
        "app-measurement.com",
        "crashlytics.com",
        "firebaselogging-pa.googleapis.com",
        NULL
    };
    for (int i = 0; builtin_tel[i] && rule_n < SD_MAX_RULES; i++) {
        rules[rule_n].pat = strdup(builtin_tel[i]);
        rules[rule_n].kind = 2;
        if (rules[rule_n].pat) rule_n++;
    }
    int n = rule_n;
    pthread_mutex_unlock(&mu);
    return n;
}

static int match_kind(const char *qname, int kind) {
    pthread_mutex_lock(&mu);
    int hit = 0;
    for (int i = 0; i < rule_n; i++) {
        if (rules[i].kind != kind) continue;
        if (domain_match(qname, rules[i].pat)) { hit = 1; break; }
    }
    pthread_mutex_unlock(&mu);
    return hit;
}

int sd_rules_is_blocked(const char *qname) { return match_kind(qname, 0); }
int sd_rules_is_allowed(const char *qname) { return match_kind(qname, 1); }
int sd_rules_is_telemetry(const char *qname) { return match_kind(qname, 2); }

int sd_rules_add_block(const char *pattern) {
    if (!pattern || !*pattern) return -1;
    pthread_mutex_lock(&mu);
    if (rule_n >= SD_MAX_RULES) {
        pthread_mutex_unlock(&mu);
        return -1;
    }
    rules[rule_n].pat = strdup(pattern);
    rules[rule_n].kind = 0;
    if (!rules[rule_n].pat) {
        pthread_mutex_unlock(&mu);
        return -1;
    }
    rule_n++;
    pthread_mutex_unlock(&mu);
    return 0;
}

int sd_rules_json(char *buf, size_t buflen) {
    pthread_mutex_lock(&mu);
    size_t o = 0;
    int n = snprintf(buf + o, buflen - o, "{\"rules\":[");
    if (n < 0 || (size_t)n >= buflen - o) { pthread_mutex_unlock(&mu); return -1; }
    o += (size_t)n;
    for (int i = 0; i < rule_n; i++) {
        char esc[512];
        sd_json_escape(rules[i].pat, esc, sizeof(esc));
        const char *k = rules[i].kind == 0 ? "block" :
                        rules[i].kind == 1 ? "allow" : "telemetry";
        n = snprintf(buf + o, buflen - o, "%s{\"pattern\":\"%s\",\"kind\":\"%s\"}",
                     i ? "," : "", esc, k);
        if (n < 0 || (size_t)n >= buflen - o) break;
        o += (size_t)n;
    }
    n = snprintf(buf + o, buflen - o, "]}");
    if (n > 0 && (size_t)n < buflen - o) o += (size_t)n;
    pthread_mutex_unlock(&mu);
    return (int)o;
}

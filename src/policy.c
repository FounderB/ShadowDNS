#include "shadowdns.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <ctype.h>
#include <pthread.h>

typedef struct {
    char *raw;
    char process[64];
    char tag[64];
    char qname[128];
    char egress[128];
    int sev_min; /* -1 none */
    sd_action_t action;
} sd_pol_t;

static sd_pol_t pols[SD_MAX_POLICY];
static int pol_n;
static pthread_mutex_t mu = PTHREAD_MUTEX_INITIALIZER;

static void trim(char *s) {
    char *p = s;
    while (*p && isspace((unsigned char)*p)) p++;
    if (p != s) memmove(s, p, strlen(p) + 1);
    size_t n = strlen(s);
    while (n && isspace((unsigned char)s[n - 1])) s[--n] = '\0';
}

static int match_pat(const char *val, const char *pat) {
    if (!pat[0]) return 1;
    if (pat[0] == '*' && pat[1] == '\0') return 1;
    if (pat[0] == '*' && pat[1] == '.') {
        size_t vn = strlen(val), pn = strlen(pat + 1);
        if (vn >= pn && strcasecmp(val + vn - pn, pat + 1) == 0) return 1;
        return strcasecmp(val, pat + 2) == 0;
    }
    return strcasecmp(val, pat) == 0 ||
           (strlen(val) > strlen(pat) && val[strlen(val) - strlen(pat) - 1] == '.' &&
            strcasecmp(val + strlen(val) - strlen(pat), pat) == 0);
}

static sd_action_t parse_action(const char *s) {
    if (!strcasecmp(s, "block") || !strcasecmp(s, "deny")) return SD_ACTION_BLOCK;
    if (!strcasecmp(s, "alert")) return SD_ACTION_ALERT;
    return SD_ACTION_ALLOW;
}

static int parse_sev(const char *s) {
    if (!strcasecmp(s, "info")) return SD_SEV_INFO;
    if (!strcasecmp(s, "low")) return SD_SEV_LOW;
    if (!strcasecmp(s, "med") || !strcasecmp(s, "medium")) return SD_SEV_MED;
    if (!strcasecmp(s, "high")) return SD_SEV_HIGH;
    if (!strcasecmp(s, "crit") || !strcasecmp(s, "critical")) return SD_SEV_CRIT;
    return -1;
}

static int parse_line(char *line, sd_pol_t *p) {
    memset(p, 0, sizeof(*p));
    p->sev_min = -1;
    p->action = SD_ACTION_ALERT;
    p->raw = strdup(line);
    char *save = NULL;
    for (char *tok = strtok_r(line, " \t", &save); tok; tok = strtok_r(NULL, " \t", &save)) {
        char *eq = strchr(tok, '=');
        if (!eq) continue;
        *eq = '\0';
        const char *k = tok;
        const char *v = eq + 1;
        if (!strcasecmp(k, "process")) snprintf(p->process, sizeof(p->process), "%s", v);
        else if (!strcasecmp(k, "tag")) snprintf(p->tag, sizeof(p->tag), "%s", v);
        else if (!strcasecmp(k, "qname") || !strcasecmp(k, "domain"))
            snprintf(p->qname, sizeof(p->qname), "%s", v);
        else if (!strcasecmp(k, "egress")) snprintf(p->egress, sizeof(p->egress), "%s", v);
        else if (!strcasecmp(k, "action")) p->action = parse_action(v);
        else if (!strcasecmp(k, "severity") || !strcasecmp(k, "severity>=") || !strcasecmp(k, "sev"))
            p->sev_min = parse_sev(v);
    }
    return p->raw != NULL;
}

int sd_policy_load(const char *path) {
    pthread_mutex_lock(&mu);
    for (int i = 0; i < pol_n; i++) free(pols[i].raw);
    pol_n = 0;
    pthread_mutex_unlock(&mu);
    if (!path || !path[0]) return 0;
    FILE *f = fopen(path, "r");
    if (!f) return 0;
    char line[512];
    int n = 0;
    while (fgets(line, sizeof(line), f)) {
        trim(line);
        if (!line[0] || line[0] == '#') continue;
        char copy[512];
        snprintf(copy, sizeof(copy), "%s", line);
        sd_pol_t p;
        if (!parse_line(copy, &p)) continue;
        pthread_mutex_lock(&mu);
        if (pol_n < SD_MAX_POLICY) {
            pols[pol_n++] = p;
            n++;
        } else {
            free(p.raw);
        }
        pthread_mutex_unlock(&mu);
    }
    fclose(f);
    return n;
}

void sd_policy_apply(sd_event_t *ev) {
    pthread_mutex_lock(&mu);
    for (int i = 0; i < pol_n; i++) {
        sd_pol_t *p = &pols[i];
        if (p->process[0] && !match_pat(ev->process, p->process)) continue;
        if (p->tag[0] && !strstr(ev->tags, p->tag)) continue;
        if (p->qname[0] && !match_pat(ev->qname, p->qname)) continue;
        if (p->sev_min >= 0 && (int)ev->severity < p->sev_min) continue;
        /* egress matched via tag doh-bypass / fluxtap */
        if (p->egress[0]) {
            int ok = 0;
            if (strstr(ev->tags, "doh-bypass") || strstr(ev->tags, "dot-bypass")) ok = 1;
            if (strstr(ev->tags, "fluxtap")) ok = 1;
            if (!ok && !match_pat(ev->qname, p->egress)) continue;
        }
        if (p->action == SD_ACTION_BLOCK) {
            ev->action = SD_ACTION_BLOCK;
            if (ev->severity < SD_SEV_HIGH) ev->severity = SD_SEV_HIGH;
        } else if (p->action == SD_ACTION_ALERT) {
            if (ev->action == SD_ACTION_ALLOW) ev->action = SD_ACTION_ALERT;
            if (ev->severity < SD_SEV_MED) ev->severity = SD_SEV_MED;
        } else {
            ev->action = SD_ACTION_ALLOW;
        }
        char note[96];
        snprintf(note, sizeof(note), "policy:%s", p->raw ? p->raw : "match");
        if (!strstr(ev->reason, "policy:"))
            snprintf(ev->reason, sizeof(ev->reason), "%s", note);
        if (!strstr(ev->tags, "policy")) {
            size_t n = strlen(ev->tags);
            if (n == 0) snprintf(ev->tags, sizeof(ev->tags), "policy");
            else if (n + 8 < sizeof(ev->tags)) snprintf(ev->tags + n, sizeof(ev->tags) - n, ",policy");
        }
    }
    pthread_mutex_unlock(&mu);
}

int sd_policy_json(char *buf, size_t buflen) {
    pthread_mutex_lock(&mu);
    size_t o = 0;
    int n = snprintf(buf + o, buflen - o, "{\"policy\":[");
    if (n < 0) { pthread_mutex_unlock(&mu); return -1; }
    o += (size_t)n;
    for (int i = 0; i < pol_n; i++) {
        char esc[512];
        sd_json_escape(pols[i].raw ? pols[i].raw : "", esc, sizeof(esc));
        n = snprintf(buf + o, buflen - o, "%s{\"rule\":\"%s\",\"action\":\"%s\"}",
                     i ? "," : "", esc, sd_act_name(pols[i].action));
        if (n < 0 || (size_t)n >= buflen - o) break;
        o += (size_t)n;
    }
    n = snprintf(buf + o, buflen - o, "]}");
    if (n > 0 && (size_t)n < buflen - o) o += (size_t)n;
    pthread_mutex_unlock(&mu);
    return (int)o;
}

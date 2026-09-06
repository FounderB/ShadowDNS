#include "shadowdns.h"

#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <ctype.h>
#include <stdlib.h>
#include <pthread.h>

typedef struct {
    char key[160]; /* process or qname */
    int nx;
    time_t window_start;
} nx_buck_t;

typedef struct {
    char qname[SD_MAX_NAME];
    char addrs[512];
    int unique;
    time_t window_start;
} flux_buck_t;

static nx_buck_t nxb[256];
static flux_buck_t flux[128];
static pthread_mutex_t mu = PTHREAD_MUTEX_INITIALIZER;

static void add_tag(sd_event_t *ev, const char *tag) {
    if (!tag || !*tag) return;
    if (strstr(ev->tags, tag)) return;
    size_t n = strlen(ev->tags), tl = strlen(tag);
    if (n == 0) {
        if (tl + 1 <= sizeof(ev->tags)) memcpy(ev->tags, tag, tl + 1);
    } else if (n + 1 + tl + 1 <= sizeof(ev->tags)) {
        ev->tags[n] = ',';
        memcpy(ev->tags + n + 1, tag, tl + 1);
    }
}

static void bump(sd_event_t *ev, sd_severity_t sev, const char *reason) {
    if (sev > ev->severity) {
        ev->severity = sev;
        snprintf(ev->reason, sizeof(ev->reason), "%s", reason);
    } else if (!ev->reason[0] || !strcmp(ev->reason, "clean")) {
        snprintf(ev->reason, sizeof(ev->reason), "%s", reason);
    }
}

static void first_label(const char *qname, char *out, size_t out_sz) {
    size_t i = 0;
    while (qname[i] && qname[i] != '.' && i + 1 < out_sz) {
        out[i] = qname[i];
        i++;
    }
    out[i] = '\0';
}

int sd_name_looks_dga(const char *qname, double entropy) {
    char lab[SD_MAX_NAME];
    first_label(qname, lab, sizeof(lab));
    size_t n = strlen(lab);
    if (n < 10) return 0;
    int vowels = 0, consonants = 0, digits = 0;
    for (size_t i = 0; i < n; i++) {
        char c = (char)tolower((unsigned char)lab[i]);
        if (c >= '0' && c <= '9') digits++;
        else if (strchr("aeiou", c)) vowels++;
        else if (c >= 'a' && c <= 'z') consonants++;
    }
    if (entropy >= 3.6 && n >= 12 && vowels * 3 < consonants) return 1;
    if (digits > 0 && consonants > 8 && entropy >= 3.3) return 1;
    if (sd_name_is_hexish(lab) && n >= 16) return 1;
    return 0;
}

static void note_nx(sd_event_t *ev) {
    if (ev->rcode != 3) return;
    char key[160];
    if (ev->process[0]) snprintf(key, sizeof(key), "p:%s", ev->process);
    else snprintf(key, sizeof(key), "c:%s", ev->client_ip);
    time_t now = ev->ts ? ev->ts : time(NULL);
    pthread_mutex_lock(&mu);
    nx_buck_t *b = NULL;
    for (int i = 0; i < 256; i++) {
        if (nxb[i].key[0] && !strcmp(nxb[i].key, key)) { b = &nxb[i]; break; }
    }
    if (!b) {
        for (int i = 0; i < 256; i++) if (!nxb[i].key[0]) { b = &nxb[i]; break; }
    }
    if (!b) b = &nxb[0];
    if (!b->key[0] || strcmp(b->key, key) != 0 || now - b->window_start > 60) {
        snprintf(b->key, sizeof(b->key), "%s", key);
        b->nx = 0;
        b->window_start = now;
    }
    b->nx++;
    int spike = b->nx >= 8;
    pthread_mutex_unlock(&mu);
    if (spike) {
        add_tag(ev, "nx-spike");
        bump(ev, SD_SEV_HIGH, "NXDOMAIN spike for process/client");
        if (ev->action == SD_ACTION_ALLOW) ev->action = SD_ACTION_ALERT;
    }
}

void sd_detect(sd_event_t *ev) {
    ev->severity = SD_SEV_INFO;
    ev->action = SD_ACTION_ALLOW;
    if (!ev->reason[0]) ev->reason[0] = '\0';
    ev->tags[0] = '\0';
    ev->entropy = sd_name_entropy(ev->qname);

    if (sd_rules_is_allowed(ev->qname)) {
        add_tag(ev, "allow");
        bump(ev, SD_SEV_INFO, "allowlisted");
        return;
    }

    if (sd_rules_is_blocked(ev->qname)) {
        add_tag(ev, "blocklist");
        bump(ev, SD_SEV_HIGH, "matched blocklist");
        ev->action = SD_ACTION_BLOCK;
    }

    if (sd_rules_is_telemetry(ev->qname)) {
        add_tag(ev, "telemetry");
        bump(ev, SD_SEV_MED, "telemetry / phone-home domain");
        if (ev->action == SD_ACTION_ALLOW) ev->action = SD_ACTION_ALERT;
    }

    int age = sd_store_name_age_sec(ev->qname, ev->ts ? ev->ts : time(NULL));
    if (age >= 0 && age < 30) {
        add_tag(ev, "newly-seen");
        bump(ev, SD_SEV_LOW, "newly seen domain");
    }

    int max_lab = sd_name_max_label(ev->qname);
    int labels = sd_name_label_count(ev->qname);
    char lab0[SD_MAX_NAME];
    first_label(ev->qname, lab0, sizeof(lab0));

    if (max_lab >= 40 || (max_lab >= 24 && ev->entropy >= 3.5)) {
        add_tag(ev, "tunnel");
        bump(ev, SD_SEV_CRIT, "long high-entropy label (tunnel-like)");
        if (ev->action != SD_ACTION_BLOCK) ev->action = SD_ACTION_ALERT;
    } else if (sd_name_is_hexish(lab0) && strlen(lab0) >= 20) {
        add_tag(ev, "tunnel");
        bump(ev, SD_SEV_HIGH, "hex-dense subdomain (possible encoding)");
        if (ev->action != SD_ACTION_BLOCK) ev->action = SD_ACTION_ALERT;
    } else if (labels >= 6 && max_lab >= 18) {
        add_tag(ev, "tunnel");
        bump(ev, SD_SEV_MED, "deep nested labels");
        if (ev->action == SD_ACTION_ALLOW) ev->action = SD_ACTION_ALERT;
    }

    if (sd_name_looks_dga(ev->qname, ev->entropy)) {
        add_tag(ev, "dga");
        bump(ev, SD_SEV_HIGH, "DGA-like label heuristics");
        if (ev->action == SD_ACTION_ALLOW) ev->action = SD_ACTION_ALERT;
    }

    if (ev->qtype == 16 || ev->qtype == 10) {
        add_tag(ev, "txt");
        if (ev->severity < SD_SEV_LOW)
            bump(ev, SD_SEV_LOW, "TXT/NULL query (tunnel-friendly)");
    }

    const char *bad_tld[] = {".zip", ".mov", ".country", ".gq", ".tk", ".ml", ".cf", ".ga", ".onion", NULL};
    size_t qn = strlen(ev->qname);
    for (int i = 0; bad_tld[i]; i++) {
        size_t tn = strlen(bad_tld[i]);
        if (qn >= tn && strcasecmp(ev->qname + qn - tn, bad_tld[i]) == 0) {
            add_tag(ev, strcmp(bad_tld[i], ".onion") == 0 ? "onion" : "risky-tld");
            bump(ev, SD_SEV_MED, "risky / special TLD");
            if (ev->action == SD_ACTION_ALLOW) ev->action = SD_ACTION_ALERT;
            break;
        }
    }

    if (!ev->reason[0]) snprintf(ev->reason, sizeof(ev->reason), "clean");
}

void sd_detect_response(sd_event_t *ev, const uint8_t *pkt, size_t len) {
    int ac = 0;
    char addrs[256];
    addrs[0] = '\0';
    sd_dns_collect_a(pkt, len, addrs, sizeof(addrs), &ac);
    snprintf(ev->answers, sizeof(ev->answers), "%s", addrs);
    ev->answer_count = sd_dns_answer_count(pkt, len);
    ev->rcode = sd_dns_rcode(pkt, len);
    note_nx(ev);

    if (ac >= 4) {
        time_t now = ev->ts ? ev->ts : time(NULL);
        pthread_mutex_lock(&mu);
        flux_buck_t *b = NULL;
        for (int i = 0; i < 128; i++) {
            if (flux[i].qname[0] && !strcasecmp(flux[i].qname, ev->qname)) {
                b = &flux[i];
                break;
            }
        }
        if (!b) {
            for (int i = 0; i < 128; i++) if (!flux[i].qname[0]) { b = &flux[i]; break; }
        }
        if (!b) b = &flux[0];
        if (!b->qname[0] || strcasecmp(b->qname, ev->qname) != 0 || now - b->window_start > 120) {
            snprintf(b->qname, sizeof(b->qname), "%s", ev->qname);
            b->addrs[0] = '\0';
            b->unique = 0;
            b->window_start = now;
        }
        /* crude unique count: if new addr tokens appear */
        char *save = NULL;
        char tmp[256];
        snprintf(tmp, sizeof(tmp), "%s", addrs);
        for (char *t = strtok_r(tmp, ",", &save); t; t = strtok_r(NULL, ",", &save)) {
            if (!strstr(b->addrs, t)) {
                size_t n = strlen(b->addrs);
                if (n + strlen(t) + 2 < sizeof(b->addrs)) {
                    if (n) strcat(b->addrs, ",");
                    strcat(b->addrs, t);
                    b->unique++;
                }
            }
        }
        int ff = b->unique >= 6;
        pthread_mutex_unlock(&mu);
        if (ff) {
            add_tag(ev, "fastflux");
            bump(ev, SD_SEV_HIGH, "fast-flux: many A/AAAA in short window");
            if (ev->action == SD_ACTION_ALLOW) ev->action = SD_ACTION_ALERT;
        }
    }

    if (ev->rcode == 3 && !strstr(ev->tags, "nxdomain"))
        add_tag(ev, "nxdomain");
}

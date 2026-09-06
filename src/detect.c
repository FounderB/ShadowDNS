#include "shadowdns.h"

#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <ctype.h>

static void add_tag(sd_event_t *ev, const char *tag) {
    if (!tag || !*tag) return;
    if (strstr(ev->tags, tag)) return;
    size_t n = strlen(ev->tags);
    if (n == 0) {
        snprintf(ev->tags, sizeof(ev->tags), "%s", tag);
    } else if (n + 1 + strlen(tag) < sizeof(ev->tags)) {
        snprintf(ev->tags + n, sizeof(ev->tags) - n, ",%s", tag);
    }
}

static void bump(sd_event_t *ev, sd_severity_t sev, const char *reason) {
    if (sev > ev->severity) {
        ev->severity = sev;
        snprintf(ev->reason, sizeof(ev->reason), "%s", reason);
    } else if (!ev->reason[0]) {
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

void sd_detect(sd_event_t *ev) {
    ev->severity = SD_SEV_INFO;
    ev->action = SD_ACTION_ALLOW;
    ev->reason[0] = '\0';
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

    int max_lab = sd_name_max_label(ev->qname);
    int labels = sd_name_label_count(ev->qname);
    char lab0[SD_MAX_NAME];
    first_label(ev->qname, lab0, sizeof(lab0));

    /* DNS tunnel / beacon heuristics */
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

    if (ev->qtype == 16 /* TXT */ || ev->qtype == 10 /* NULL */) {
        add_tag(ev, "txt");
        if (ev->severity < SD_SEV_LOW) {
            bump(ev, SD_SEV_LOW, "TXT/NULL query (tunnel-friendly)");
        }
    }

    /* suspicious TLDs often used in staging / malware kits */
    const char *bad_tld[] = {".zip", ".mov", ".country", ".gq", ".tk", ".ml", ".cf", ".ga", NULL};
    size_t qn = strlen(ev->qname);
    for (int i = 0; bad_tld[i]; i++) {
        size_t tn = strlen(bad_tld[i]);
        if (qn >= tn && strcasecmp(ev->qname + qn - tn, bad_tld[i]) == 0) {
            add_tag(ev, "risky-tld");
            bump(ev, SD_SEV_MED, "risky / abused TLD");
            if (ev->action == SD_ACTION_ALLOW) ev->action = SD_ACTION_ALERT;
            break;
        }
    }

    /* numeric-only host labels (C2 style) */
    int all_num = lab0[0] != '\0';
    for (char *p = lab0; *p; p++) {
        if (!isdigit((unsigned char)*p) && *p != '-') { all_num = 0; break; }
    }
    if (all_num && strlen(lab0) >= 6) {
        add_tag(ev, "numeric");
        bump(ev, SD_SEV_LOW, "numeric subdomain");
    }

    if (!ev->reason[0]) {
        snprintf(ev->reason, sizeof(ev->reason), "clean");
    }
}

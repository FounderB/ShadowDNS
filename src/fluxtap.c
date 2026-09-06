#include "shadowdns.h"

#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <time.h>

typedef struct {
    char sni[256];
    char process[128];
    char ja3[128];
    time_t ts;
} sni_note_t;

static sni_note_t notes[256];
static int note_i;
static pthread_mutex_t mu = PTHREAD_MUTEX_INITIALIZER;

void sd_fluxtap_note_sni(const char *sni, const char *process, const char *ja3) {
    if (!sni || !sni[0]) return;
    pthread_mutex_lock(&mu);
    sni_note_t *n = &notes[note_i++ % 256];
    memset(n, 0, sizeof(*n));
    snprintf(n->sni, sizeof(n->sni), "%s", sni);
    if (process) snprintf(n->process, sizeof(n->process), "%s", process);
    if (ja3) snprintf(n->ja3, sizeof(n->ja3), "%s", ja3);
    n->ts = time(NULL);
    pthread_mutex_unlock(&mu);
}

int sd_fluxtap_correlate(sd_event_t *ev) {
    if (!ev || !ev->qname[0]) return 0;
    time_t now = time(NULL);
    pthread_mutex_lock(&mu);
    int hit = 0;
    for (int i = 0; i < 256; i++) {
        if (!notes[i].sni[0]) continue;
        if (now - notes[i].ts > 120) continue;
        /* DNS said X, TLS went to Y (different) */
        if (strcasecmp(notes[i].sni, ev->qname) == 0) {
            /* matching SNI — note bridge ok */
            if (!strstr(ev->tags, "fluxtap")) {
                size_t n = strlen(ev->tags);
                if (n == 0) snprintf(ev->tags, sizeof(ev->tags), "fluxtap");
                else if (n + 9 < sizeof(ev->tags))
                    snprintf(ev->tags + n, sizeof(ev->tags) - n, ",fluxtap");
            }
            hit = 1;
            continue;
        }
        /* mismatch: process resolved qname but SNI differs shortly after */
        if (ev->process[0] && notes[i].process[0] &&
            strcmp(ev->process, notes[i].process) == 0 &&
            strcasecmp(notes[i].sni, ev->qname) != 0) {
            if (!strstr(ev->tags, "sni-mismatch")) {
                size_t n = strlen(ev->tags);
                if (n == 0) snprintf(ev->tags, sizeof(ev->tags), "sni-mismatch,fluxtap");
                else if (n + 22 < sizeof(ev->tags))
                    snprintf(ev->tags + n, sizeof(ev->tags) - n, ",sni-mismatch,fluxtap");
            }
            if (ev->severity < SD_SEV_MED) {
                ev->severity = SD_SEV_MED;
                snprintf(ev->reason, sizeof(ev->reason),
                         "FluxTap bridge: DNS %s vs SNI %s", ev->qname, notes[i].sni);
            }
            if (ev->action == SD_ACTION_ALLOW) ev->action = SD_ACTION_ALERT;
            hit = 1;
        }
    }
    pthread_mutex_unlock(&mu);
    return hit;
}

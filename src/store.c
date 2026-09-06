#include "shadowdns.h"

#include <pthread.h>
#include <string.h>
#include <strings.h>
#include <stdio.h>
#include <stdlib.h>

static sd_event_t ring[SD_EVENT_RING];
static size_t head = 0;
static size_t count = 0;
static uint64_t next_id = 1;
static pthread_mutex_t mu = PTHREAD_MUTEX_INITIALIZER;
static sd_stats_t stats;
static char **seen_names;
static size_t seen_n;
static size_t seen_cap;

int sd_store_init(void) {
    memset(ring, 0, sizeof(ring));
    memset(&stats, 0, sizeof(stats));
    head = count = 0;
    next_id = 1;
    seen_names = NULL;
    seen_n = seen_cap = 0;
    return 0;
}

void sd_store_note_name(const char *name) {
    if (!name || !*name) return;
    pthread_mutex_lock(&mu);
    for (size_t i = 0; i < seen_n; i++) {
        if (strcasecmp(seen_names[i], name) == 0) {
            pthread_mutex_unlock(&mu);
            return;
        }
    }
    if (seen_n == seen_cap) {
        size_t nc = seen_cap ? seen_cap * 2 : 256;
        char **nn = realloc(seen_names, nc * sizeof(char *));
        if (!nn) { pthread_mutex_unlock(&mu); return; }
        seen_names = nn;
        seen_cap = nc;
    }
    seen_names[seen_n] = strdup(name);
    if (seen_names[seen_n]) {
        seen_n++;
        stats.unique_names = seen_n;
    }
    pthread_mutex_unlock(&mu);
}

void sd_store_push(const sd_event_t *ev) {
    pthread_mutex_lock(&mu);
    sd_event_t copy = *ev;
    copy.id = next_id++;
    ring[head] = copy;
    head = (head + 1) % SD_EVENT_RING;
    if (count < SD_EVENT_RING) count++;

    stats.queries++;
    if (copy.action == SD_ACTION_BLOCK) stats.blocked++;
    if (copy.severity >= SD_SEV_MED) stats.alerts++;
    if (strstr(copy.tags, "tunnel")) stats.tunnels++;
    if (strstr(copy.tags, "telemetry")) stats.telemetry++;
    if (copy.rcode == 3) stats.nxdomain++;
    pthread_mutex_unlock(&mu);
}

size_t sd_store_snapshot(sd_event_t *out, size_t max, uint64_t after_id) {
    pthread_mutex_lock(&mu);
    size_t n = 0;
    size_t start = (head + SD_EVENT_RING - count) % SD_EVENT_RING;
    for (size_t i = 0; i < count && n < max; i++) {
        size_t idx = (start + i) % SD_EVENT_RING;
        if (ring[idx].id <= after_id) continue;
        out[n++] = ring[idx];
    }
    pthread_mutex_unlock(&mu);
    return n;
}

void sd_store_stats(sd_stats_t *out) {
    pthread_mutex_lock(&mu);
    *out = stats;
    pthread_mutex_unlock(&mu);
}

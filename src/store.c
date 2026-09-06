#include "shadowdns.h"

#include <pthread.h>
#include <string.h>
#include <strings.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

static sd_event_t ring[SD_EVENT_RING];
static size_t head = 0;
static size_t count = 0;
static uint64_t next_id = 1;
static pthread_mutex_t mu = PTHREAD_MUTEX_INITIALIZER;
static sd_stats_t stats;

typedef struct {
    char *name;
    time_t first_seen;
} seen_t;

static seen_t *seen;
static size_t seen_n, seen_cap;

int sd_store_init(void) {
    memset(ring, 0, sizeof(ring));
    memset(&stats, 0, sizeof(stats));
    head = count = 0;
    next_id = 1;
    seen = NULL;
    seen_n = seen_cap = 0;
    return 0;
}

void sd_store_bump_counter(const char *which, uint64_t n) {
    pthread_mutex_lock(&mu);
    if (!strcmp(which, "dga")) stats.dga += n;
    else if (!strcmp(which, "fastflux")) stats.fastflux += n;
    else if (!strcmp(which, "doh_bypass")) stats.doh_bypass += n;
    else if (!strcmp(which, "stories")) stats.stories += n;
    else if (!strcmp(which, "ebpf_hits")) stats.ebpf_hits += n;
    else if (!strcmp(which, "newly_seen")) stats.newly_seen += n;
    pthread_mutex_unlock(&mu);
}

void sd_store_note_name(const char *name) {
    if (!name || !*name) return;
    time_t now = time(NULL);
    pthread_mutex_lock(&mu);
    for (size_t i = 0; i < seen_n; i++) {
        if (strcasecmp(seen[i].name, name) == 0) {
            pthread_mutex_unlock(&mu);
            return;
        }
    }
    if (seen_n == seen_cap) {
        size_t nc = seen_cap ? seen_cap * 2 : 512;
        seen_t *nn = realloc(seen, nc * sizeof(seen_t));
        if (!nn) { pthread_mutex_unlock(&mu); return; }
        seen = nn;
        seen_cap = nc;
    }
    seen[seen_n].name = strdup(name);
    seen[seen_n].first_seen = now;
    if (seen[seen_n].name) {
        seen_n++;
        stats.unique_names = seen_n;
        stats.newly_seen++;
    }
    pthread_mutex_unlock(&mu);
}

int sd_store_name_age_sec(const char *name, time_t now) {
    pthread_mutex_lock(&mu);
    for (size_t i = 0; i < seen_n; i++) {
        if (strcasecmp(seen[i].name, name) == 0) {
            int age = (int)(now - seen[i].first_seen);
            pthread_mutex_unlock(&mu);
            return age < 0 ? 0 : age;
        }
    }
    pthread_mutex_unlock(&mu);
    return -1; /* not seen yet / just noted after */
}

void sd_store_push(const sd_event_t *ev) {
    pthread_mutex_lock(&mu);
    sd_event_t copy = *ev;
    if (!copy.id) copy.id = next_id++;
    else if (copy.id >= next_id) next_id = copy.id + 1;
    ring[head] = copy;
    head = (head + 1) % SD_EVENT_RING;
    if (count < SD_EVENT_RING) count++;

    stats.queries++;
    if (copy.action == SD_ACTION_BLOCK) stats.blocked++;
    if (copy.severity >= SD_SEV_MED) stats.alerts++;
    if (strstr(copy.tags, "tunnel")) stats.tunnels++;
    if (strstr(copy.tags, "telemetry")) stats.telemetry++;
    if (copy.rcode == 3) stats.nxdomain++;
    if (strstr(copy.tags, "dga")) stats.dga++;
    if (strstr(copy.tags, "fastflux")) stats.fastflux++;
    if (strstr(copy.tags, "doh-bypass") || strstr(copy.tags, "dot-bypass"))
        stats.doh_bypass++;
    if (copy.attr_ebpf) stats.ebpf_hits++;
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

#include "shadowdns.h"

#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>

static sd_story_t stories[SD_STORY_RING];
static size_t head, count;
static uint64_t next_id = 1;
static pthread_mutex_t mu = PTHREAD_MUTEX_INITIALIZER;

static void add_stage(sd_story_t *s, const char *stage) {
    if (!stage || !*stage) return;
    if (strstr(s->stages, stage)) return;
    size_t n = strlen(s->stages), tl = strlen(stage);
    if (n == 0) snprintf(s->stages, sizeof(s->stages), "%s", stage);
    else if (n + tl + 4 < sizeof(s->stages))
        snprintf(s->stages + n, sizeof(s->stages) - n, " → %s", stage);
}

static const char *stage_from_ev(const sd_event_t *ev) {
    if (strstr(ev->tags, "doh-bypass") || strstr(ev->tags, "dot-bypass")) return "doh-bypass";
    if (strstr(ev->tags, "tunnel")) return "tunnel-like";
    if (strstr(ev->tags, "telemetry")) return "telemetry-burst";
    if (strstr(ev->tags, "dga")) return "dga";
    if (strstr(ev->tags, "fastflux")) return "fast-flux";
    if (strstr(ev->tags, "newly-seen")) return "new-domain";
    if (strstr(ev->tags, "nx-spike")) return "nx-spike";
    if (ev->action == SD_ACTION_BLOCK) return "block";
    if (ev->severity >= SD_SEV_HIGH) return "high-signal";
    return NULL;
}

void sd_story_on_event(sd_event_t *ev) {
    if (ev->severity < SD_SEV_LOW && ev->action == SD_ACTION_ALLOW &&
        !strstr(ev->tags, "newly-seen") && !strstr(ev->tags, "telemetry"))
        return;

    const char *stage = stage_from_ev(ev);
    if (!stage && ev->action == SD_ACTION_ALLOW && ev->severity < SD_SEV_MED)
        return;

    time_t now = ev->ts ? ev->ts : time(NULL);
    pthread_mutex_lock(&mu);

    sd_story_t *s = NULL;
    size_t start = (head + SD_STORY_RING - count) % SD_STORY_RING;
    for (size_t i = 0; i < count; i++) {
        size_t idx = (start + count - 1 - i) % SD_STORY_RING;
        sd_story_t *cand = &stories[idx];
        if (now - cand->updated > 180) continue;
        if (ev->process[0] && cand->process[0] &&
            strcmp(ev->process, cand->process) == 0) {
            s = cand;
            break;
        }
        if (!ev->process[0] && !strcmp(cand->title, ev->client_ip)) {
            s = cand;
            break;
        }
    }

    if (!s) {
        s = &stories[head];
        memset(s, 0, sizeof(*s));
        s->id = next_id++;
        s->ts = now;
        head = (head + 1) % SD_STORY_RING;
        if (count < SD_STORY_RING) count++;
        sd_store_bump_counter("stories", 1);
        if (ev->process[0]) {
            snprintf(s->process, sizeof(s->process), "%s", ev->process);
            snprintf(s->title, sizeof(s->title), "Story · %s", ev->process);
        } else {
            snprintf(s->title, sizeof(s->title), "%s", ev->client_ip);
        }
    }

    s->updated = now;
    s->event_count++;
    s->last_event_id = ev->id;
    if (ev->severity > s->severity) s->severity = ev->severity;
    if (stage) add_stage(s, stage);
    if (ev->action == SD_ACTION_BLOCK) add_stage(s, "block");

    snprintf(s->summary, sizeof(s->summary),
             "%d events · last %s (%s) · %s",
             s->event_count, ev->qname, sd_sev_name(ev->severity),
             s->stages[0] ? s->stages : "signal");

    ev->story_id = s->id;
    pthread_mutex_unlock(&mu);
}

size_t sd_story_snapshot(sd_story_t *out, size_t max, uint64_t after_id) {
    pthread_mutex_lock(&mu);
    size_t n = 0;
    size_t start = (head + SD_STORY_RING - count) % SD_STORY_RING;
    for (size_t i = 0; i < count && n < max; i++) {
        size_t idx = (start + i) % SD_STORY_RING;
        if (stories[idx].id <= after_id) continue;
        out[n++] = stories[idx];
    }
    pthread_mutex_unlock(&mu);
    return n;
}

int sd_story_to_json(const sd_story_t *s, char *buf, size_t buflen) {
    char title[320], sum[640], proc[256], stages[512], t0[40], t1[40];
    sd_json_escape(s->title, title, sizeof(title));
    sd_json_escape(s->summary, sum, sizeof(sum));
    sd_json_escape(s->process, proc, sizeof(proc));
    sd_json_escape(s->stages, stages, sizeof(stages));
    sd_iso_time(s->ts, t0, sizeof(t0));
    sd_iso_time(s->updated, t1, sizeof(t1));
    return snprintf(buf, buflen,
        "{\"id\":%llu,\"ts\":\"%s\",\"updated\":\"%s\",\"title\":\"%s\","
        "\"summary\":\"%s\",\"process\":\"%s\",\"severity\":\"%s\","
        "\"stages\":\"%s\",\"events\":%d,\"last_event\":%llu}",
        (unsigned long long)s->id, t0, t1, title, sum, proc,
        sd_sev_name(s->severity), stages, s->event_count,
        (unsigned long long)s->last_event_id);
}

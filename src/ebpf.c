#include "shadowdns.h"

#include <arpa/inet.h>
#include <errno.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#ifdef SD_HAS_EBPF
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "../bpf/shadow_attr.h"
#include "shadow_attr.skel.h"
#endif

static int g_active;
static pthread_t g_thr;
static volatile int g_stop;

#ifdef SD_HAS_EBPF
static struct shadow_attr_bpf *g_skel;
static struct ring_buffer *g_rb;

static void seed_doh_ips(int map_fd) {
    const char *ips[] = {
        "1.1.1.1", "1.0.0.1", "8.8.8.8", "8.8.4.4",
        "9.9.9.9", "149.112.112.112", "8.26.56.26",
        "208.67.222.222", "208.67.220.220",
        "94.140.14.14", "94.140.15.15",
        NULL
    };
    for (int i = 0; ips[i]; i++) {
        struct in_addr a;
        if (inet_pton(AF_INET, ips[i], &a) != 1) continue;
        __u32 key = a.s_addr;
        __u8 one = 1;
        bpf_map_update_elem(map_fd, &key, &one, BPF_ANY);
    }
}

static int on_bypass(void *ctx, void *data, size_t len) {
    (void)ctx;
    if (len < sizeof(struct sd_bypass_evt)) return 0;
    const struct sd_bypass_evt *e = data;
    sd_event_t ev;
    memset(&ev, 0, sizeof(ev));
    ev.ts = time(NULL);
    snprintf(ev.process, sizeof(ev.process), "%s", e->comm);
    snprintf(ev.pid, sizeof(ev.pid), "%u", e->pid);
    struct in_addr a = {.s_addr = e->daddr};
    inet_ntop(AF_INET, &a, ev.client_ip, sizeof(ev.client_ip));
    snprintf(ev.qname, sizeof(ev.qname), "%s:%u", ev.client_ip, e->dport);
    ev.severity = SD_SEV_CRIT;
    ev.action = SD_ACTION_ALERT;
    if (e->kind == SD_BYPASS_DOH) {
        snprintf(ev.tags, sizeof(ev.tags), "doh-bypass");
        snprintf(ev.reason, sizeof(ev.reason), "DoH bypass to known resolver");
    } else {
        snprintf(ev.tags, sizeof(ev.tags), "dot-bypass");
        snprintf(ev.reason, sizeof(ev.reason), "DoT bypass (tcp/853)");
    }
    snprintf(ev.cgroup, sizeof(ev.cgroup), "cg:%llu",
             (unsigned long long)e->cgroup_id);
    ev.attr_ebpf = 1;
    sd_story_on_event(&ev);
    if (sd_runtime_cfg) {
        sd_jsonl_write(sd_runtime_cfg, &ev);
        sd_notify_event(sd_runtime_cfg, &ev);
    }
    sd_store_push(&ev);
    return 0;
}

static void *rb_thread(void *arg) {
    (void)arg;
    while (!g_stop && g_rb) {
        int err = ring_buffer__poll(g_rb, 200);
        if (err < 0 && err != -EINTR) break;
    }
    return NULL;
}
#endif

int sd_ebpf_active(void) { return g_active; }

int sd_ebpf_start(const sd_config_t *cfg) {
    if (!cfg->enable_ebpf) return 0;
#ifdef SD_HAS_EBPF
    libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
    g_skel = shadow_attr_bpf__open();
    if (!g_skel) {
        fprintf(stderr, "eBPF: open failed (need CAP_BPF / root?)\n");
        return -1;
    }
    if (shadow_attr_bpf__load(g_skel)) {
        fprintf(stderr, "eBPF: load failed\n");
        shadow_attr_bpf__destroy(g_skel);
        g_skel = NULL;
        return -1;
    }
    seed_doh_ips(bpf_map__fd(g_skel->maps.doh_ips));
    if (shadow_attr_bpf__attach(g_skel)) {
        fprintf(stderr, "eBPF: attach failed\n");
        shadow_attr_bpf__destroy(g_skel);
        g_skel = NULL;
        return -1;
    }
    g_rb = ring_buffer__new(bpf_map__fd(g_skel->maps.bypass_rb), on_bypass, NULL, NULL);
    if (!g_rb) {
        fprintf(stderr, "eBPF: ringbuf failed\n");
        shadow_attr_bpf__destroy(g_skel);
        g_skel = NULL;
        return -1;
    }
    g_stop = 0;
    g_active = 1;
    pthread_create(&g_thr, NULL, rb_thread, NULL);
    fprintf(stderr, "eBPF: process truth + DoH/DoT bypass armed\n");
    return 0;
#else
    (void)cfg;
    fprintf(stderr, "eBPF: built without SD_HAS_EBPF\n");
    return -1;
#endif
}

void sd_ebpf_stop(void) {
#ifdef SD_HAS_EBPF
    g_stop = 1;
    if (g_active) pthread_join(g_thr, NULL);
    if (g_rb) { ring_buffer__free(g_rb); g_rb = NULL; }
    if (g_skel) { shadow_attr_bpf__destroy(g_skel); g_skel = NULL; }
#endif
    g_active = 0;
}

int sd_ebpf_lookup(uint16_t sport, char *proc, size_t proc_sz,
                   char *pid, size_t pid_sz, char *cgroup, size_t cg_sz,
                   char *container, size_t ct_sz) {
    proc[0] = pid[0] = cgroup[0] = container[0] = '\0';
#ifdef SD_HAS_EBPF
    if (!g_active || !g_skel) return 0;
    struct sd_attr_key key = {.sport = sport};
    struct sd_attr_val val;
    if (bpf_map_lookup_elem(bpf_map__fd(g_skel->maps.sport_attr), &key, &val) != 0)
        return 0;
    snprintf(proc, proc_sz, "%s", val.comm);
    snprintf(pid, pid_sz, "%u", val.pid);
    snprintf(cgroup, cg_sz, "cg:%llu", (unsigned long long)val.cgroup_id);
    sd_proc_fill_cgroup(pid, cgroup, cg_sz, container, ct_sz);
    return 1;
#else
    (void)sport; (void)proc_sz; (void)pid_sz; (void)cg_sz; (void)ct_sz;
    return 0;
#endif
}

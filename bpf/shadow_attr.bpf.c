// SPDX-License-Identifier: MIT
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include "shadow_attr.h"

#ifndef AF_INET
#define AF_INET 2
#endif
#ifndef AF_INET6
#define AF_INET6 10
#endif

char LICENSE[] SEC("license") = "Dual MIT/GPL";

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 65536);
    __type(key, struct sd_attr_key);
    __type(value, struct sd_attr_val);
} sport_attr SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 20);
} bypass_rb SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 256);
    __type(key, __u32);   /* IPv4 network order */
    __type(value, __u8);  /* 1 = DoH endpoint */
} doh_ips SEC(".maps");

static __always_inline void fill_attr(struct sd_attr_val *v)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    v->pid = pid_tgid >> 32;
    v->tgid = (__u32)pid_tgid;
    v->cgroup_id = bpf_get_current_cgroup_id();
    bpf_get_current_comm(v->comm, sizeof(v->comm));
    v->ts_ns = bpf_ktime_get_ns();
}

SEC("kprobe/udp_sendmsg")
int BPF_KPROBE(sd_udp_sendmsg, struct sock *sk)
{
    __u16 sport = 0, dport = 0;
    __u16 family = 0;

    family = BPF_CORE_READ(sk, __sk_common.skc_family);
    if (family != 2 && family != 10) /* AF_INET / AF_INET6 */
        return 0;

    sport = bpf_ntohs(BPF_CORE_READ(sk, __sk_common.skc_num));
    dport = bpf_ntohs(BPF_CORE_READ(sk, __sk_common.skc_dport));

    /* Track DNS (53) and common ShadowDNS lab ports */
    if (dport != 53 && dport != 5353 && dport != 18553 && dport != 8053)
        return 0;
    if (sport == 0)
        return 0;

    struct sd_attr_key key = {.sport = sport};
    struct sd_attr_val val = {};
    fill_attr(&val);
    bpf_map_update_elem(&sport_attr, &key, &val, BPF_ANY);
    return 0;
}

SEC("kprobe/tcp_connect")
int BPF_KPROBE(sd_tcp_connect, struct sock *sk)
{
    __u16 family = BPF_CORE_READ(sk, __sk_common.skc_family);
    if (family != 2) /* AF_INET */
        return 0;

    __u16 dport = bpf_ntohs(BPF_CORE_READ(sk, __sk_common.skc_dport));
    __u32 daddr = BPF_CORE_READ(sk, __sk_common.skc_daddr);

    __u8 kind = 0;
    if (dport == 853) {
        kind = SD_BYPASS_DOT;
    } else if (dport == 443) {
        __u8 *hit = bpf_map_lookup_elem(&doh_ips, &daddr);
        if (!hit)
            return 0;
        kind = SD_BYPASS_DOH;
    } else {
        return 0;
    }

    struct sd_bypass_evt *e = bpf_ringbuf_reserve(&bypass_rb, sizeof(*e), 0);
    if (!e)
        return 0;
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    e->pid = pid_tgid >> 32;
    e->tgid = (__u32)pid_tgid;
    e->daddr = daddr;
    e->dport = dport;
    e->kind = kind;
    e->cgroup_id = bpf_get_current_cgroup_id();
    e->ts_ns = bpf_ktime_get_ns();
    bpf_get_current_comm(e->comm, sizeof(e->comm));
    bpf_ringbuf_submit(e, 0);
    return 0;
}

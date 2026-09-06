/* SPDX-License-Identifier: MIT */
#ifndef SHADOW_ATTR_H
#define SHADOW_ATTR_H

#define SD_COMM_LEN 16
#define SD_CGROUP_LEN 128

struct sd_attr_key {
    __u16 sport; /* host byte order */
    __u16 pad;
};

struct sd_attr_val {
    __u32 pid;
    __u32 tgid;
    __u64 cgroup_id;
    char comm[SD_COMM_LEN];
    __u64 ts_ns;
};

enum sd_bypass_kind {
    SD_BYPASS_DOH = 1,
    SD_BYPASS_DOT = 2,
};

struct sd_bypass_evt {
    __u32 pid;
    __u32 tgid;
    __u32 daddr; /* IPv4 network order */
    __u16 dport; /* host order */
    __u16 kind;
    char comm[SD_COMM_LEN];
    __u64 cgroup_id;
    __u64 ts_ns;
};

#endif

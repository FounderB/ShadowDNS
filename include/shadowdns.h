#ifndef SHADOWDNS_H
#define SHADOWDNS_H

#include <stdint.h>
#include <stddef.h>
#include <time.h>
#include <netinet/in.h>

#define SD_VERSION "0.2.0"
#define SD_MAX_NAME 256
#define SD_MAX_LABEL 64
#define SD_EVENT_RING 8192
#define SD_STORY_RING 512
#define SD_MAX_UPSTREAMS 8
#define SD_MAX_RULES 8192
#define SD_MAX_POLICY 1024
#define SD_MAX_SPLIT 256

typedef enum {
    SD_SEV_INFO = 0,
    SD_SEV_LOW = 1,
    SD_SEV_MED = 2,
    SD_SEV_HIGH = 3,
    SD_SEV_CRIT = 4
} sd_severity_t;

typedef enum {
    SD_ACTION_ALLOW = 0,
    SD_ACTION_ALERT = 1,
    SD_ACTION_BLOCK = 2,
    SD_ACTION_DENY = 2
} sd_action_t;

typedef enum {
    SD_UP_UDP = 0,
    SD_UP_DOT = 1,
    SD_UP_DOH = 2
} sd_upstream_kind_t;

typedef struct {
    sd_upstream_kind_t kind;
    char host[128];
    int port;
    char doh_path[64];
} sd_upstream_t;

typedef struct {
    char qname[SD_MAX_NAME];
    uint16_t qtype;
    uint16_t qclass;
    char client_ip[64];
    uint16_t client_port;
    char process[128];
    char pid[16];
    char cgroup[160];
    char container[64];
    int attr_ebpf; /* 1 if eBPF attributed */
    sd_severity_t severity;
    sd_action_t action;
    char reason[160];
    char tags[192];
    double entropy;
    int answer_count;
    int rcode;
    int latency_ms;
    char answers[256]; /* compact A/AAAA summary */
    time_t ts;
    uint64_t id;
    uint64_t story_id;
} sd_event_t;

typedef struct {
    uint64_t id;
    time_t ts;
    time_t updated;
    char title[160];
    char summary[320];
    char process[128];
    sd_severity_t severity;
    char stages[256];
    int event_count;
    uint64_t last_event_id;
} sd_story_t;

typedef struct {
    char bind_host[64];
    int dns_port;
    int http_port;
    sd_upstream_t upstreams[SD_MAX_UPSTREAMS];
    int upstream_count;
    char web_root[512];
    char blocklist_path[512];
    char telemetry_path[512];
    char allowlist_path[512];
    char policy_path[512];
    char split_path[512];
    char jsonl_path[512];
    char webhook_url[512];
    char telegram_token[256];
    char telegram_chat[64];
    int block_mode;
    int resolve_process;
    int enable_ebpf;
    int enable_tui;
    int quiet;
    int fluxtap_bridge;
} sd_config_t;

typedef struct {
    uint64_t queries;
    uint64_t blocked;
    uint64_t alerts;
    uint64_t tunnels;
    uint64_t telemetry;
    uint64_t nxdomain;
    uint64_t unique_names;
    uint64_t dga;
    uint64_t fastflux;
    uint64_t doh_bypass;
    uint64_t stories;
    uint64_t ebpf_hits;
    uint64_t newly_seen;
} sd_stats_t;

void sd_config_defaults(sd_config_t *cfg);
int  sd_config_load_args(sd_config_t *cfg, int argc, char **argv);

int  sd_store_init(void);
void sd_store_push(const sd_event_t *ev);
size_t sd_store_snapshot(sd_event_t *out, size_t max, uint64_t after_id);
void sd_store_stats(sd_stats_t *out);
void sd_store_note_name(const char *name);
int  sd_store_name_age_sec(const char *name, time_t now);
void sd_store_bump_counter(const char *which, uint64_t n);

int  sd_rules_load(const sd_config_t *cfg);
int  sd_rules_is_blocked(const char *qname);
int  sd_rules_is_allowed(const char *qname);
int  sd_rules_is_telemetry(const char *qname);
int  sd_rules_add_block(const char *pattern);
int  sd_rules_json(char *buf, size_t buflen);

int  sd_policy_load(const char *path);
void sd_policy_apply(sd_event_t *ev);
int  sd_policy_json(char *buf, size_t buflen);

int  sd_split_load(const char *path);
int  sd_split_lookup(const char *qname, sd_upstream_t *out);

void sd_detect(sd_event_t *ev);
void sd_detect_response(sd_event_t *ev, const uint8_t *pkt, size_t len);

void sd_story_on_event(sd_event_t *ev);
size_t sd_story_snapshot(sd_story_t *out, size_t max, uint64_t after_id);
int  sd_story_to_json(const sd_story_t *s, char *buf, size_t buflen);

int  sd_dns_extract_question(const uint8_t *pkt, size_t len,
                             char *qname, size_t qname_sz,
                             uint16_t *qtype, uint16_t *qclass);
int  sd_dns_build_nxdomain(const uint8_t *req, size_t req_len,
                           uint8_t *out, size_t out_sz);
int  sd_dns_set_id(uint8_t *pkt, size_t len, uint16_t id);
uint16_t sd_dns_get_id(const uint8_t *pkt, size_t len);
const char *sd_dns_type_name(uint16_t t);
int  sd_dns_answer_count(const uint8_t *pkt, size_t len);
int  sd_dns_rcode(const uint8_t *pkt, size_t len);
int  sd_dns_collect_a(const uint8_t *pkt, size_t len, char *out, size_t out_sz,
                      int *a_count);

int  sd_upstream_query(const sd_config_t *cfg, const char *qname,
                       const uint8_t *req, size_t req_len,
                       uint8_t *resp, size_t resp_sz, int *latency_ms);

int  sd_proxy_run(const sd_config_t *cfg);
/* Exported for main readiness check */
int sd_http_listening(void);
int  sd_tui_run(const sd_config_t *cfg);

int  sd_ebpf_start(const sd_config_t *cfg);
void sd_ebpf_stop(void);
int  sd_ebpf_lookup(uint16_t sport, char *proc, size_t proc_sz,
                    char *pid, size_t pid_sz, char *cgroup, size_t cg_sz,
                    char *container, size_t ct_sz);
int  sd_ebpf_active(void);

void sd_proc_lookup_udp(uint16_t local_port, char *proc, size_t proc_sz,
                        char *pid, size_t pid_sz);
void sd_proc_fill_cgroup(const char *pid, char *cgroup, size_t cg_sz,
                         char *container, size_t ct_sz);

void sd_notify_event(const sd_config_t *cfg, const sd_event_t *ev);
void sd_jsonl_write(const sd_config_t *cfg, const sd_event_t *ev);
int  sd_sarif_export(char *buf, size_t buflen);
int  sd_metrics_render(char *buf, size_t buflen);
int  sd_event_to_json(const sd_event_t *ev, char *buf, size_t buflen);

void sd_fluxtap_note_sni(const char *sni, const char *process, const char *ja3);
int  sd_fluxtap_correlate(sd_event_t *ev);

double sd_name_entropy(const char *qname);
int    sd_name_max_label(const char *qname);
int    sd_name_label_count(const char *qname);
int    sd_name_is_hexish(const char *label);
int    sd_name_looks_dga(const char *qname, double entropy);

uint64_t sd_now_ms(void);
void     sd_iso_time(time_t t, char *buf, size_t n);
void     sd_json_escape(const char *in, char *out, size_t out_sz);
const char *sd_sev_name(sd_severity_t s);
const char *sd_act_name(sd_action_t a);

/* set by main for modules that need runtime cfg */
extern const sd_config_t *sd_runtime_cfg;

#endif

#ifndef SHADOWDNS_H
#define SHADOWDNS_H

#include <stdint.h>
#include <stddef.h>
#include <time.h>
#include <netinet/in.h>

#define SD_VERSION "0.1.0"
#define SD_MAX_NAME 256
#define SD_MAX_LABEL 64
#define SD_EVENT_RING 4096
#define SD_MAX_UPSTREAMS 4
#define SD_MAX_RULES 4096

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
    SD_ACTION_BLOCK = 2
} sd_action_t;

typedef struct {
    char qname[SD_MAX_NAME];
    uint16_t qtype;
    uint16_t qclass;
    char client_ip[64];
    uint16_t client_port;
    char process[128];
    char pid[16];
    sd_severity_t severity;
    sd_action_t action;
    char reason[128];
    char tags[160];
    double entropy;
    int answer_count;
    int rcode;
    int latency_ms;
    time_t ts;
    uint64_t id;
} sd_event_t;

typedef struct {
    char bind_host[64];
    int dns_port;
    int http_port;
    char upstreams[SD_MAX_UPSTREAMS][64];
    int upstream_count;
    char web_root[512];
    char blocklist_path[512];
    char telemetry_path[512];
    char allowlist_path[512];
    int block_mode;          /* 1 = enforce blocks, 0 = alert only */
    int resolve_process;     /* try /proc UDP owner lookup */
    int quiet;
} sd_config_t;

typedef struct {
    uint64_t queries;
    uint64_t blocked;
    uint64_t alerts;
    uint64_t tunnels;
    uint64_t telemetry;
    uint64_t nxdomain;
    uint64_t unique_names;
} sd_stats_t;

void sd_config_defaults(sd_config_t *cfg);
int  sd_config_load_args(sd_config_t *cfg, int argc, char **argv);

int  sd_store_init(void);
void sd_store_push(const sd_event_t *ev);
size_t sd_store_snapshot(sd_event_t *out, size_t max, uint64_t after_id);
void sd_store_stats(sd_stats_t *out);
void sd_store_note_name(const char *name);

int  sd_rules_load(const sd_config_t *cfg);
int  sd_rules_is_blocked(const char *qname);
int  sd_rules_is_allowed(const char *qname);
int  sd_rules_is_telemetry(const char *qname);
int  sd_rules_add_block(const char *pattern);
int  sd_rules_json(char *buf, size_t buflen);

void sd_detect(sd_event_t *ev);

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

int  sd_proxy_run(const sd_config_t *cfg);
int  sd_http_run(const sd_config_t *cfg);

void sd_proc_lookup_udp(uint16_t local_port, char *proc, size_t proc_sz,
                        char *pid, size_t pid_sz);

double sd_name_entropy(const char *qname);
int    sd_name_max_label(const char *qname);
int    sd_name_label_count(const char *qname);
int    sd_name_is_hexish(const char *label);

uint64_t sd_now_ms(void);
void     sd_iso_time(time_t t, char *buf, size_t n);
void     sd_json_escape(const char *in, char *out, size_t out_sz);

#endif

#include "shadowdns.h"

#include <stdio.h>
#include <string.h>

int sd_event_to_json(const sd_event_t *ev, char *buf, size_t buflen) {
    char qn[512], reason[320], tags[400], proc[256], cip[128];
    char cg[320], ct[128], ans[512], tbuf[40];
    sd_json_escape(ev->qname, qn, sizeof(qn));
    sd_json_escape(ev->reason, reason, sizeof(reason));
    sd_json_escape(ev->tags, tags, sizeof(tags));
    sd_json_escape(ev->process, proc, sizeof(proc));
    sd_json_escape(ev->client_ip, cip, sizeof(cip));
    sd_json_escape(ev->cgroup, cg, sizeof(cg));
    sd_json_escape(ev->container, ct, sizeof(ct));
    sd_json_escape(ev->answers, ans, sizeof(ans));
    sd_iso_time(ev->ts, tbuf, sizeof(tbuf));
    return snprintf(buf, buflen,
        "{\"id\":%llu,\"ts\":\"%s\",\"qname\":\"%s\",\"qtype\":\"%s\","
        "\"qtype_id\":%u,\"client\":\"%s\",\"port\":%u,\"process\":\"%s\","
        "\"pid\":\"%s\",\"cgroup\":\"%s\",\"container\":\"%s\",\"ebpf\":%s,"
        "\"severity\":\"%s\",\"action\":\"%s\",\"reason\":\"%s\",\"tags\":\"%s\","
        "\"entropy\":%.3f,\"answers\":%d,\"addrs\":\"%s\",\"rcode\":%d,"
        "\"latency_ms\":%d,\"story_id\":%llu}",
        (unsigned long long)ev->id, tbuf, qn, sd_dns_type_name(ev->qtype),
        ev->qtype, cip, ev->client_port, proc, ev->pid, cg, ct,
        ev->attr_ebpf ? "true" : "false",
        sd_sev_name(ev->severity), sd_act_name(ev->action), reason, tags,
        ev->entropy, ev->answer_count, ans, ev->rcode, ev->latency_ms,
        (unsigned long long)ev->story_id);
}

int sd_metrics_render(char *buf, size_t buflen) {
    sd_stats_t st;
    sd_store_stats(&st);
    return snprintf(buf, buflen,
        "# HELP shadowdns_queries_total DNS queries processed\n"
        "# TYPE shadowdns_queries_total counter\n"
        "shadowdns_queries_total %llu\n"
        "# TYPE shadowdns_blocked_total counter\n"
        "shadowdns_blocked_total %llu\n"
        "# TYPE shadowdns_alerts_total counter\n"
        "shadowdns_alerts_total %llu\n"
        "# TYPE shadowdns_tunnels_total counter\n"
        "shadowdns_tunnels_total %llu\n"
        "# TYPE shadowdns_telemetry_total counter\n"
        "shadowdns_telemetry_total %llu\n"
        "# TYPE shadowdns_nxdomain_total counter\n"
        "shadowdns_nxdomain_total %llu\n"
        "# TYPE shadowdns_dga_total counter\n"
        "shadowdns_dga_total %llu\n"
        "# TYPE shadowdns_fastflux_total counter\n"
        "shadowdns_fastflux_total %llu\n"
        "# TYPE shadowdns_doh_bypass_total counter\n"
        "shadowdns_doh_bypass_total %llu\n"
        "# TYPE shadowdns_stories_total counter\n"
        "shadowdns_stories_total %llu\n"
        "# TYPE shadowdns_ebpf_hits_total counter\n"
        "shadowdns_ebpf_hits_total %llu\n"
        "# TYPE shadowdns_unique_names gauge\n"
        "shadowdns_unique_names %llu\n"
        "# TYPE shadowdns_ebpf_active gauge\n"
        "shadowdns_ebpf_active %d\n",
        (unsigned long long)st.queries,
        (unsigned long long)st.blocked,
        (unsigned long long)st.alerts,
        (unsigned long long)st.tunnels,
        (unsigned long long)st.telemetry,
        (unsigned long long)st.nxdomain,
        (unsigned long long)st.dga,
        (unsigned long long)st.fastflux,
        (unsigned long long)st.doh_bypass,
        (unsigned long long)st.stories,
        (unsigned long long)st.ebpf_hits,
        (unsigned long long)st.unique_names,
        sd_ebpf_active());
}

int sd_sarif_export(char *buf, size_t buflen) {
    sd_event_t evs[200];
    size_t n = sd_store_snapshot(evs, 200, 0);
    size_t o = 0;
    int m = snprintf(buf + o, buflen - o,
        "{\"version\":\"2.1.0\",\"$schema\":\"https://json.schemastore.org/sarif-2.1.0.json\","
        "\"runs\":[{\"tool\":{\"driver\":{\"name\":\"ShadowDNS\",\"version\":\"%s\","
        "\"informationUri\":\"https://github.com/FounderB/ShadowDNS\","
        "\"rules\":["
        "{\"id\":\"tunnel\",\"name\":\"DNSTunnel\",\"shortDescription\":{\"text\":\"Tunnel-like DNS\"}},"
        "{\"id\":\"telemetry\",\"name\":\"Telemetry\",\"shortDescription\":{\"text\":\"Phone-home DNS\"}},"
        "{\"id\":\"dga\",\"name\":\"DGA\",\"shortDescription\":{\"text\":\"DGA-like domain\"}},"
        "{\"id\":\"fastflux\",\"name\":\"FastFlux\",\"shortDescription\":{\"text\":\"Fast-flux answers\"}},"
        "{\"id\":\"doh-bypass\",\"name\":\"DoHBypass\",\"shortDescription\":{\"text\":\"DoH/DoT bypass\"}},"
        "{\"id\":\"blocklist\",\"name\":\"Blocklist\",\"shortDescription\":{\"text\":\"Blocked domain\"}}"
        "]}},\"results\":[", SD_VERSION);
    if (m < 0) return -1;
    o += (size_t)m;
    int first = 1;
    for (size_t i = 0; i < n; i++) {
        if (evs[i].severity < SD_SEV_MED && evs[i].action != SD_ACTION_BLOCK) continue;
        const char *rule = "telemetry";
        if (strstr(evs[i].tags, "tunnel")) rule = "tunnel";
        else if (strstr(evs[i].tags, "dga")) rule = "dga";
        else if (strstr(evs[i].tags, "fastflux")) rule = "fastflux";
        else if (strstr(evs[i].tags, "doh-bypass") || strstr(evs[i].tags, "dot-bypass"))
            rule = "doh-bypass";
        else if (strstr(evs[i].tags, "blocklist") || evs[i].action == SD_ACTION_BLOCK)
            rule = "blocklist";
        char qn[512], reason[320];
        sd_json_escape(evs[i].qname, qn, sizeof(qn));
        sd_json_escape(evs[i].reason, reason, sizeof(reason));
        const char *level = evs[i].severity >= SD_SEV_CRIT ? "error" :
                            evs[i].severity >= SD_SEV_HIGH ? "error" : "warning";
        m = snprintf(buf + o, buflen - o,
            "%s{\"ruleId\":\"%s\",\"level\":\"%s\",\"message\":{\"text\":\"%s: %s\"},"
            "\"locations\":[{\"logicalLocations\":[{\"fullyQualifiedName\":\"%s\"}]}]}",
            first ? "" : ",", rule, level, qn, reason, qn);
        if (m < 0 || (size_t)m >= buflen - o) break;
        o += (size_t)m;
        first = 0;
    }
    m = snprintf(buf + o, buflen - o, "]}]}");
    if (m > 0 && (size_t)m < buflen - o) o += (size_t)m;
    return (int)o;
}

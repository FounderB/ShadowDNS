#include "shadowdns.h"

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <poll.h>
#include <termios.h>
#include <stdlib.h>

static struct termios oldt;
static int raw_on;

static void tui_restore(void) {
    if (raw_on) tcsetattr(STDIN_FILENO, TCSANOW, &oldt);
    printf("\033[?25h\033[0m\n");
    fflush(stdout);
}

static void tui_raw(void) {
    tcgetattr(STDIN_FILENO, &oldt);
    struct termios t = oldt;
    t.c_lflag &= (tcflag_t)~(ICANON | ECHO);
    t.c_cc[VMIN] = 0;
    t.c_cc[VTIME] = 0;
    tcsetattr(STDIN_FILENO, TCSANOW, &t);
    raw_on = 1;
    atexit(tui_restore);
    printf("\033[?25l");
}

static const char *sev_color(sd_severity_t s) {
    switch (s) {
        case SD_SEV_CRIT: return "\033[1;35m";
        case SD_SEV_HIGH: return "\033[1;31m";
        case SD_SEV_MED: return "\033[1;33m";
        case SD_SEV_LOW: return "\033[1;36m";
        default: return "\033[0;37m";
    }
}

int sd_tui_run(const sd_config_t *cfg) {
    (void)cfg;
    if (!isatty(STDOUT_FILENO)) return -1;
    tui_raw();
    uint64_t after = 0;
    for (;;) {
        sd_stats_t st;
        sd_store_stats(&st);
        printf("\033[H\033[2J");
        printf("\033[1;32mShadowDNS\033[0m v%s  eBPF:%s  q:%llu block:%llu alert:%llu tunnel:%llu bypass:%llu stories:%llu\n",
               SD_VERSION, sd_ebpf_active() ? "on" : "off",
               (unsigned long long)st.queries,
               (unsigned long long)st.blocked,
               (unsigned long long)st.alerts,
               (unsigned long long)st.tunnels,
               (unsigned long long)st.doh_bypass,
               (unsigned long long)st.stories);
        printf("───────────────────────────────────────────────────────────────────────────────\n");

        sd_story_t stories[8];
        size_t ns = sd_story_snapshot(stories, 8, 0);
        if (ns) {
            printf("Attack stories:\n");
            for (size_t i = ns; i > 0 && i + 5 > ns; i--) {
                sd_story_t *s = &stories[i - 1];
                printf("  %s#%llu\033[0m %s — %s\n", sev_color(s->severity),
                       (unsigned long long)s->id, s->title, s->stages);
            }
            printf("\n");
        }

        sd_event_t evs[24];
        size_t n = sd_store_snapshot(evs, 24, after);
        if (n) after = evs[n - 1].id;
        /* show latest from full ring */
        n = sd_store_snapshot(evs, 24, 0);
        size_t start = n > 18 ? n - 18 : 0;
        for (size_t i = start; i < n; i++) {
            sd_event_t *e = &evs[i];
            printf("%s%-4s\033[0m %-5s %-6s %-12s %s\n",
                   sev_color(e->severity), sd_sev_name(e->severity),
                   sd_act_name(e->action),
                   sd_dns_type_name(e->qtype),
                   e->process[0] ? e->process : "-",
                   e->qname);
        }
        printf("\n[q] quit   dashboard :%d\n", cfg->http_port);
        fflush(stdout);

        struct pollfd pfd = {.fd = STDIN_FILENO, .events = POLLIN};
        if (poll(&pfd, 1, 400) > 0) {
            char c = 0;
            if (read(STDIN_FILENO, &c, 1) > 0 && (c == 'q' || c == 'Q')) break;
        }
    }
    tui_restore();
    return 0;
}

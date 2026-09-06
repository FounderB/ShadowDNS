#include "shadowdns.h"

#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <stdatomic.h>

static atomic_int g_http_failed;

static void *http_thread(void *arg) {
    if (sd_http_run(arg) != 0) {
        atomic_store(&g_http_failed, 1);
        fprintf(stderr, "http server failed — refusing to run DNS-only\n");
        kill(getpid(), SIGTERM);
    }
    return NULL;
}

static void *tui_thread(void *arg) {
    sd_tui_run(arg);
    return NULL;
}

static void on_sig(int sig) {
    (void)sig;
    sd_ebpf_stop();
    _exit(atomic_load(&g_http_failed) ? 1 : 0);
}

int main(int argc, char **argv) {
    sd_config_t cfg;
    if (sd_config_load_args(&cfg, argc, argv) != 0)
        return 1;
    sd_runtime_cfg = &cfg;

    signal(SIGPIPE, SIG_IGN);
    signal(SIGINT, on_sig);
    signal(SIGTERM, on_sig);

    sd_store_init();
    int rules = sd_rules_load(&cfg);
    int pols = sd_policy_load(cfg.policy_path);
    int splits = sd_split_load(cfg.split_path);

    fprintf(stderr,
        "\n"
        "  ███████╗██╗  ██╗ █████╗ ██████╗  ██████╗ ██╗    ██╗██████╗ ███╗   ██╗███████╗\n"
        "  ██╔════╝██║  ██║██╔══██╗██╔══██╗██╔═══██╗██║    ██║██╔══██╗████╗  ██║██╔════╝\n"
        "  ███████╗███████║███████║██║  ██║██║   ██║██║ █╗ ██║██║  ██║██╔██╗ ██║███████╗\n"
        "  ╚════██║██╔══██║██╔══██║██║  ██║██║   ██║██║███╗██║██║  ██║██║╚██╗██║╚════██║\n"
        "  ███████║██║  ██║██║  ██║██████╔╝╚██████╔╝╚███╔███╔╝██████╔╝██║ ╚████║███████║\n"
        "  ╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝  ╚═════╝  ╚══╝╚══╝ ╚═════╝ ╚═╝  ╚═══╝╚══════╝\n"
        "  v%s  ·  DNS leak & C2 radar  ·  lists:%d policy:%d split:%d\n\n",
        SD_VERSION, rules, pols, splits);

    if (cfg.enable_ebpf)
        (void)sd_ebpf_start(&cfg); /* soft-fail → /proc attribution */

    atomic_store(&g_http_failed, 0);
    pthread_t th;
    if (pthread_create(&th, NULL, http_thread, &cfg) != 0) {
        perror("pthread_create");
        return 1;
    }

    for (int i = 0; i < 100; i++) {
        if (atomic_load(&g_http_failed))
            return 1;
        if (sd_http_listening())
            break;
        usleep(20000);
    }
    if (atomic_load(&g_http_failed) || !sd_http_listening()) {
        fprintf(stderr, "http did not become ready on port %d\n", cfg.http_port);
        return 1;
    }

    if (cfg.enable_tui) {
        pthread_t tt;
        pthread_create(&tt, NULL, tui_thread, &cfg);
    }

    int rc = sd_proxy_run(&cfg);
    sd_ebpf_stop();
    return rc == 0 ? 0 : 1;
}

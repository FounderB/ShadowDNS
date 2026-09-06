#include "shadowdns.h"

#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>

static void *http_thread(void *arg) {
    if (sd_http_run(arg) != 0)
        fprintf(stderr, "http server failed\n");
    return NULL;
}

static void *tui_thread(void *arg) {
    sd_tui_run(arg);
    return NULL;
}

static void on_sig(int sig) {
    (void)sig;
    sd_ebpf_stop();
    _exit(0);
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
        sd_ebpf_start(&cfg);

    pthread_t th;
    if (pthread_create(&th, NULL, http_thread, &cfg) != 0) {
        perror("pthread_create");
        return 1;
    }

    if (cfg.enable_tui) {
        pthread_t tt;
        pthread_create(&tt, NULL, tui_thread, &cfg);
    }

    usleep(100000);
    int rc = sd_proxy_run(&cfg);
    sd_ebpf_stop();
    return rc == 0 ? 0 : 1;
}

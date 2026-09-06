#include "shadowdns.h"

#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <strings.h>

static void *http_thread(void *arg) {
    const sd_config_t *cfg = arg;
    if (sd_http_run(cfg) != 0)
        fprintf(stderr, "http server failed\n");
    return NULL;
}

int main(int argc, char **argv) {
    sd_config_t cfg;
    if (sd_config_load_args(&cfg, argc, argv) != 0)
        return 1;

    signal(SIGPIPE, SIG_IGN);

    sd_store_init();
    int rules = sd_rules_load(&cfg);

    fprintf(stderr,
        "\n"
        "  ███████╗██╗  ██╗ █████╗ ██████╗  ██████╗ ██╗    ██╗██████╗ ███╗   ██╗███████╗\n"
        "  ██╔════╝██║  ██║██╔══██╗██╔══██╗██╔═══██╗██║    ██║██╔══██╗████╗  ██║██╔════╝\n"
        "  ███████╗███████║███████║██║  ██║██║   ██║██║ █╗ ██║██║  ██║██╔██╗ ██║███████╗\n"
        "  ╚════██║██╔══██║██╔══██║██║  ██║██║   ██║██║███╗██║██║  ██║██║╚██╗██║╚════██║\n"
        "  ███████║██║  ██║██║  ██║██████╔╝╚██████╔╝╚███╔███╔╝██████╔╝██║ ╚████║███████║\n"
        "  ╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝  ╚═════╝  ╚══╝╚══╝ ╚═════╝ ╚═╝  ╚═══╝╚══════╝\n"
        "  v%s  ·  DNS leak & C2 radar  ·  %d rules loaded\n\n",
        SD_VERSION, rules);

    pthread_t th;
    if (pthread_create(&th, NULL, http_thread, &cfg) != 0) {
        perror("pthread_create");
        return 1;
    }

    /* small delay so dashboard URL prints first-ish */
    usleep(100000);
    int rc = sd_proxy_run(&cfg);
    return rc == 0 ? 0 : 1;
}

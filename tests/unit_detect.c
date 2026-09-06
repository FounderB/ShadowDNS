#include "shadowdns.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

int main(void) {
    sd_store_init();
    sd_rules_load(&(sd_config_t){0}); /* empty paths ok */

    sd_event_t ev;
    memset(&ev, 0, sizeof(ev));
    snprintf(ev.qname, sizeof(ev.qname), "%s", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.evil.test");
    ev.qtype = 1;
    ev.ts = time(NULL);
    sd_detect(&ev);
    assert(strstr(ev.tags, "tunnel") != NULL);
    assert(ev.severity >= SD_SEV_HIGH);

    memset(&ev, 0, sizeof(ev));
    snprintf(ev.qname, sizeof(ev.qname), "%s", "xqztmnvbplkjhgfdsawertyuio.com");
    ev.entropy = sd_name_entropy(ev.qname);
    assert(sd_name_looks_dga(ev.qname, ev.entropy) || ev.entropy > 3.0);

    memset(&ev, 0, sizeof(ev));
    snprintf(ev.qname, sizeof(ev.qname), "%s", "example.com");
    sd_detect(&ev);
    assert(!strstr(ev.tags, "tunnel"));

    puts("unit_detect ok");
    return 0;
}

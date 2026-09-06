#include "shadowdns.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

/* Lightweight DNS packet fuzzer — random bytes into parsers must not crash */
int main(void) {
    uint8_t buf[512];
    char name[SD_MAX_NAME];
    uint16_t qt, qc;
    unsigned seed = 0xC0FFEE;
    for (int i = 0; i < 20000; i++) {
        size_t len = (size_t)(seed % 512);
        seed = seed * 1103515245 + 12345;
        for (size_t j = 0; j < len; j++) {
            seed = seed * 1103515245 + 12345;
            buf[j] = (uint8_t)(seed >> 16);
        }
        sd_dns_extract_question(buf, len, name, sizeof(name), &qt, &qc);
        sd_dns_answer_count(buf, len);
        sd_dns_rcode(buf, len);
        char addrs[128];
        int ac = 0;
        sd_dns_collect_a(buf, len, addrs, sizeof(addrs), &ac);
        uint8_t out[512];
        if (len >= 12) sd_dns_build_nxdomain(buf, len, out, sizeof(out));
    }
    puts("fuzz_dns ok");
    return 0;
}

#include "shadowdns.h"

#include <string.h>
#include <stdio.h>

static int parse_name(const uint8_t *pkt, size_t len, size_t *offset,
                      char *out, size_t out_sz) {
    size_t i = *offset;
    size_t out_i = 0;
    int jumps = 0;
    size_t end = 0;
    int first = 1;

    if (i >= len) return -1;

    while (i < len) {
        uint8_t lab = pkt[i];
        if (lab == 0) {
            i++;
            if (!end) end = i;
            break;
        }
        if ((lab & 0xC0) == 0xC0) {
            if (i + 1 >= len) return -1;
            size_t ptr = ((lab & 0x3F) << 8) | pkt[i + 1];
            if (!end) end = i + 2;
            i = ptr;
            if (++jumps > 16) return -1;
            continue;
        }
        i++;
        if (i + lab > len || out_i + lab + 2 >= out_sz) return -1;
        if (!first) out[out_i++] = '.';
        first = 0;
        memcpy(out + out_i, pkt + i, lab);
        out_i += lab;
        i += lab;
    }
    out[out_i] = '\0';
    if (!end) return -1;
    *offset = end;
    return 0;
}

int sd_dns_extract_question(const uint8_t *pkt, size_t len,
                            char *qname, size_t qname_sz,
                            uint16_t *qtype, uint16_t *qclass) {
    if (len < 12) return -1;
    uint16_t qdcount = (uint16_t)((pkt[4] << 8) | pkt[5]);
    if (qdcount < 1) return -1;
    size_t off = 12;
    if (parse_name(pkt, len, &off, qname, qname_sz) != 0) return -1;
    if (off + 4 > len) return -1;
    *qtype = (uint16_t)((pkt[off] << 8) | pkt[off + 1]);
    *qclass = (uint16_t)((pkt[off + 2] << 8) | pkt[off + 3]);
    return 0;
}

uint16_t sd_dns_get_id(const uint8_t *pkt, size_t len) {
    if (len < 2) return 0;
    return (uint16_t)((pkt[0] << 8) | pkt[1]);
}

int sd_dns_set_id(uint8_t *pkt, size_t len, uint16_t id) {
    if (len < 2) return -1;
    pkt[0] = (uint8_t)(id >> 8);
    pkt[1] = (uint8_t)(id & 0xFF);
    return 0;
}

int sd_dns_answer_count(const uint8_t *pkt, size_t len) {
    if (len < 12) return 0;
    return (pkt[6] << 8) | pkt[7];
}

int sd_dns_rcode(const uint8_t *pkt, size_t len) {
    if (len < 4) return -1;
    return pkt[3] & 0x0F;
}

int sd_dns_build_nxdomain(const uint8_t *req, size_t req_len,
                          uint8_t *out, size_t out_sz) {
    if (req_len < 12 || out_sz < req_len) return -1;
    memcpy(out, req, req_len);
    /* QR=1, AA=0, RCODE=NXDOMAIN(3); clear TC/RA bits carefully */
    out[2] = (uint8_t)(0x80 | (req[2] & 0x79)); /* QR + copy opcode/AA/TC/RD */
    out[3] = (uint8_t)((req[3] & 0x70) | 0x80 | 0x03); /* RA + NXDOMAIN */
    out[6] = out[7] = 0; /* ANCOUNT */
    out[8] = out[9] = 0; /* NSCOUNT */
    out[10] = out[11] = 0; /* ARCOUNT */
    /* Keep question section; strip any extra sections by truncating after Q */
    size_t off = 12;
    char tmp[SD_MAX_NAME];
    uint16_t qt, qc;
    if (sd_dns_extract_question(req, req_len, tmp, sizeof(tmp), &qt, &qc) != 0)
        return (int)req_len;
    /* recompute end of question */
    off = 12;
    while (off < req_len) {
        uint8_t lab = req[off];
        if (lab == 0) { off++; break; }
        if ((lab & 0xC0) == 0xC0) { off += 2; break; }
        off += 1 + lab;
    }
    if (off + 4 > req_len) return (int)req_len;
    off += 4;
    return (int)off;
}

const char *sd_dns_type_name(uint16_t t) {
    switch (t) {
        case 1: return "A";
        case 2: return "NS";
        case 5: return "CNAME";
        case 6: return "SOA";
        case 12: return "PTR";
        case 15: return "MX";
        case 16: return "TXT";
        case 28: return "AAAA";
        case 33: return "SRV";
        case 41: return "OPT";
        case 255: return "ANY";
        case 65: return "HTTPS";
        case 64: return "SVCB";
        default: return "OTHER";
    }
}

static int skip_name(const uint8_t *pkt, size_t len, size_t *offset) {
    char tmp[SD_MAX_NAME];
    return parse_name(pkt, len, offset, tmp, sizeof(tmp));
}

int sd_dns_collect_a(const uint8_t *pkt, size_t len, char *out, size_t out_sz,
                     int *a_count) {
    out[0] = '\0';
    if (a_count) *a_count = 0;
    if (len < 12) return -1;
    uint16_t qd = (uint16_t)((pkt[4] << 8) | pkt[5]);
    uint16_t an = (uint16_t)((pkt[6] << 8) | pkt[7]);
    size_t off = 12;
    for (uint16_t i = 0; i < qd; i++) {
        if (skip_name(pkt, len, &off) != 0) return -1;
        if (off + 4 > len) return -1;
        off += 4;
    }
    int found = 0;
    size_t o = 0;
    for (uint16_t i = 0; i < an; i++) {
        if (skip_name(pkt, len, &off) != 0) break;
        if (off + 10 > len) break;
        uint16_t typ = (uint16_t)((pkt[off] << 8) | pkt[off + 1]);
        uint16_t rdlen = (uint16_t)((pkt[off + 8] << 8) | pkt[off + 9]);
        off += 10;
        if (off + rdlen > len) break;
        if ((typ == 1 && rdlen == 4) || (typ == 28 && rdlen == 16)) {
            char ip[64];
            if (typ == 1) {
                snprintf(ip, sizeof(ip), "%u.%u.%u.%u",
                         pkt[off], pkt[off + 1], pkt[off + 2], pkt[off + 3]);
            } else {
                /* compact IPv6 hex */
                snprintf(ip, sizeof(ip),
                         "%02x%02x:%02x%02x:%02x%02x:%02x%02x",
                         pkt[off], pkt[off+1], pkt[off+2], pkt[off+3],
                         pkt[off+4], pkt[off+5], pkt[off+6], pkt[off+7]);
            }
            size_t il = strlen(ip);
            if (o && o + 1 < out_sz) out[o++] = ',';
            if (o + il < out_sz) {
                memcpy(out + o, ip, il);
                o += il;
                out[o] = '\0';
                found++;
            }
        }
        off += rdlen;
    }
    if (a_count) *a_count = found;
    return found;
}

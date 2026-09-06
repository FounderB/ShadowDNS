#include "shadowdns.h"

#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <math.h>
#include <sys/time.h>
#include <time.h>
#include <dirent.h>
#include <unistd.h>
#include <stdlib.h>

uint64_t sd_now_ms(void) {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (uint64_t)tv.tv_sec * 1000ull + (uint64_t)tv.tv_usec / 1000ull;
}

void sd_iso_time(time_t t, char *buf, size_t n) {
    struct tm tm;
    gmtime_r(&t, &tm);
    strftime(buf, n, "%Y-%m-%dT%H:%M:%SZ", &tm);
}

void sd_json_escape(const char *in, char *out, size_t out_sz) {
    size_t j = 0;
    if (!in || out_sz == 0) {
        if (out_sz) out[0] = '\0';
        return;
    }
    for (size_t i = 0; in[i] && j + 2 < out_sz; i++) {
        unsigned char c = (unsigned char)in[i];
        if (c == '"' || c == '\\') {
            if (j + 3 >= out_sz) break;
            out[j++] = '\\';
            out[j++] = (char)c;
        } else if (c < 0x20) {
            if (j + 7 >= out_sz) break;
            j += (size_t)snprintf(out + j, out_sz - j, "\\u%04x", c);
        } else {
            out[j++] = (char)c;
        }
    }
    out[j] = '\0';
}

double sd_name_entropy(const char *qname) {
    if (!qname || !*qname) return 0.0;
    int freq[256] = {0};
    int n = 0;
    for (const char *p = qname; *p; p++) {
        if (*p == '.') continue;
        freq[(unsigned char)tolower((unsigned char)*p)]++;
        n++;
    }
    if (n == 0) return 0.0;
    double ent = 0.0;
    for (int i = 0; i < 256; i++) {
        if (!freq[i]) continue;
        double p = (double)freq[i] / (double)n;
        ent -= p * log2(p);
    }
    return ent;
}

int sd_name_max_label(const char *qname) {
    int best = 0, cur = 0;
    for (const char *p = qname; ; p++) {
        if (*p == '.' || *p == '\0') {
            if (cur > best) best = cur;
            cur = 0;
            if (*p == '\0') break;
        } else {
            cur++;
        }
    }
    return best;
}

int sd_name_label_count(const char *qname) {
    if (!qname || !*qname) return 0;
    int n = 1;
    for (const char *p = qname; *p; p++) if (*p == '.') n++;
    return n;
}

int sd_name_is_hexish(const char *label) {
    size_t len = strlen(label);
    if (len < 16) return 0;
    size_t hex = 0;
    for (size_t i = 0; i < len; i++) {
        char c = (char)tolower((unsigned char)label[i]);
        if ((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) hex++;
    }
    return (hex * 100 / len) >= 85;
}

static int read_comm(const char *pid, char *out, size_t out_sz) {
    char path[64];
    snprintf(path, sizeof(path), "/proc/%s/comm", pid);
    FILE *f = fopen(path, "r");
    if (!f) return -1;
    if (!fgets(out, (int)out_sz, f)) {
        fclose(f);
        return -1;
    }
    fclose(f);
    size_t n = strlen(out);
    while (n && (out[n - 1] == '\n' || out[n - 1] == '\r')) out[--n] = '\0';
    return 0;
}

/* Best-effort: map local UDP sport -> owning process via /proc/net/udp + /proc/pid/fd */
void sd_proc_lookup_udp(uint16_t local_port, char *proc, size_t proc_sz,
                        char *pid_out, size_t pid_sz) {
    proc[0] = '\0';
    pid_out[0] = '\0';
    if (local_port == 0) return;

    FILE *f = fopen("/proc/net/udp", "r");
    if (!f) return;

    char line[512];
    if (!fgets(line, sizeof(line), f)) { fclose(f); return; } /* header */

    unsigned long inode = 0;
    int found = 0;
    while (fgets(line, sizeof(line), f)) {
        unsigned local_address = 0;
        unsigned local_p = 0;
        unsigned long ino = 0;
        /* sl local_address rem_address st tx_queue rx_queue ... inode */
        if (sscanf(line, "%*d: %x:%x %*x:%*x %*x %*x:%*x %*x:%*x %*x %*d %*d %lu",
                   &local_address, &local_p, &ino) >= 3) {
            if ((uint16_t)local_p == local_port && ino != 0) {
                inode = ino;
                found = 1;
                break;
            }
        }
    }
    fclose(f);
    if (!found) return;

    DIR *procdir = opendir("/proc");
    if (!procdir) return;
    struct dirent *de;
    char needle[64];
    snprintf(needle, sizeof(needle), "socket:[%lu]", inode);

    while ((de = readdir(procdir)) != NULL) {
        if (de->d_name[0] < '1' || de->d_name[0] > '9') continue;
        char fdpath[288];
        snprintf(fdpath, sizeof(fdpath), "/proc/%s/fd", de->d_name);
        DIR *fd = opendir(fdpath);
        if (!fd) continue;
        struct dirent *fe;
        int hit = 0;
        while ((fe = readdir(fd)) != NULL) {
            if (fe->d_name[0] < '0' || fe->d_name[0] > '9') continue;
            char linkpath[384], target[256];
            snprintf(linkpath, sizeof(linkpath), "%s/%s", fdpath, fe->d_name);
            ssize_t n = readlink(linkpath, target, sizeof(target) - 1);
            if (n < 0) continue;
            target[n] = '\0';
            if (strcmp(target, needle) == 0) {
                hit = 1;
                break;
            }
        }
        closedir(fd);
        if (hit) {
            snprintf(pid_out, pid_sz, "%s", de->d_name);
            read_comm(de->d_name, proc, proc_sz);
            break;
        }
    }
    closedir(procdir);
}

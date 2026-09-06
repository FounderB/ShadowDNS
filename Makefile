CC       ?= gcc
CLANG    ?= clang
BPFTOOL  ?= bpftool
CFLAGS   ?= -O2 -Wall -Wextra -std=c11 -D_GNU_SOURCE -Iinclude
LDFLAGS  ?= -lpthread -lm -lssl -lcrypto

LIBBPF_DIR := third_party/libbpf-install
LIBBPF_A   := $(LIBBPF_DIR)/lib64/libbpf.a
BPF_CFLAGS := -O2 -g -target bpf -D__TARGET_ARCH_x86 -Ibpf -I$(LIBBPF_DIR)/include

SRC = \
	src/main.c \
	src/config.c \
	src/util.c \
	src/dns.c \
	src/detect.c \
	src/rules.c \
	src/store.c \
	src/proxy.c \
	src/http.c \
	src/policy.c \
	src/split.c \
	src/story.c \
	src/upstream.c \
	src/ebpf.c \
	src/notify.c \
	src/export.c \
	src/fluxtap.c \
	src/tui.c

OBJ = $(SRC:.c=.o)
BIN = shadowdns

BPF_OBJ = bpf/shadow_attr.bpf.o
BPF_SKEL = src/shadow_attr.skel.h

.PHONY: all clean install run test fuzz unit bpf libbpf

all: $(BIN)

libbpf: $(LIBBPF_A)

$(LIBBPF_A):
	@./scripts/fetch-libbpf.sh

bpf/vmlinux.h:
	$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > $@

$(BPF_OBJ): bpf/shadow_attr.bpf.c bpf/shadow_attr.h bpf/vmlinux.h $(LIBBPF_A)
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@

$(BPF_SKEL): $(BPF_OBJ)
	$(BPFTOOL) gen skeleton $< > $@

bpf: $(BPF_SKEL)

# Prefer eBPF build; fall back automatically if skeleton/libbpf unavailable
$(BIN): $(SRC) include/shadowdns.h
	@if [ -f "$(LIBBPF_A)" ] && $(CLANG) -target bpf -c -x c /dev/null -o /tmp/sd_bpf_probe.o 2>/dev/null; then \
	  $(MAKE) $(BPF_SKEL) && \
	  $(CC) $(CFLAGS) -DSD_HAS_EBPF -I$(LIBBPF_DIR)/include -Ibpf -Isrc \
	    $(SRC) -o $@ $(LDFLAGS) $(LIBBPF_A) -lelf -lz ; \
	else \
	  echo "NOTE: building without eBPF (libbpf/clang-bpf missing)" ; \
	  $(CC) $(CFLAGS) $(SRC) -o $@ $(LDFLAGS) ; \
	fi

src/%.o: src/%.c include/shadowdns.h
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJ) $(BIN) $(BPF_OBJ) $(BPF_SKEL) bpf/vmlinux.h
	rm -f tests/unit_detect tests/fuzz_dns

install: $(BIN)
	./scripts/install.sh

run: $(BIN)
	./$(BIN) --dns-port 5353 --http-port 8088

test: $(BIN)
	@./tests/smoke.sh
	@./tests/unit_detect.sh

unit: tests/unit_detect
	./tests/unit_detect

tests/unit_detect: tests/unit_detect.c src/detect.c src/util.c src/dns.c src/store.c src/rules.c src/policy.c src/story.c src/fluxtap.c src/config.c
	$(CC) $(CFLAGS) -Iinclude -DSD_UNIT_TEST tests/unit_detect.c src/detect.c src/util.c src/dns.c src/store.c src/rules.c src/policy.c src/story.c src/fluxtap.c src/config.c -o $@ -lpthread -lm

fuzz: tests/fuzz_dns
	./tests/fuzz_dns

tests/fuzz_dns: tests/fuzz_dns.c src/dns.c
	$(CC) $(CFLAGS) -Iinclude tests/fuzz_dns.c src/dns.c -o $@

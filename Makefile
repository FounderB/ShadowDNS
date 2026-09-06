CC      ?= gcc
CFLAGS ?= -O2 -Wall -Wextra -Wpedantic -std=c11 -D_GNU_SOURCE -Iinclude
LDFLAGS ?= -lpthread -lm

SRC = \
	src/main.c \
	src/config.c \
	src/util.c \
	src/dns.c \
	src/detect.c \
	src/rules.c \
	src/store.c \
	src/proxy.c \
	src/http.c

OBJ = $(SRC:.c=.o)
BIN = shadowdns

.PHONY: all clean install run test

all: $(BIN)

$(BIN): $(OBJ)
	$(CC) $(OBJ) -o $@ $(LDFLAGS)

src/%.o: src/%.c include/shadowdns.h
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJ) $(BIN)

install: $(BIN)
	install -d $(DESTDIR)/usr/local/bin
	install -m 755 $(BIN) $(DESTDIR)/usr/local/bin/shadowdns

run: $(BIN)
	./$(BIN) --dns-port 5353 --http-port 8088

test: $(BIN)
	@./tests/smoke.sh

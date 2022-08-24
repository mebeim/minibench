CFLAGS  := -std=c99 -O3 -Wall -Wextra -pedantic -pedantic-errors
LDFLAGS := -lm

# ld has no -z option on macOS
ifneq ($(shell uname -s),Darwin)
	LDFLAGS += -Wl,-z,relro,-z,now
endif

.PHONY: clean install uninstall

bench: bench.c
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)
	strip $@

install: bench
	install $< $$HOME/.local/bin

uninstall:
	rm -f $$HOME/.local/bin/bench

clean:
	rm -f bench

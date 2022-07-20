CFLAGS  := -std=c99 -O3 -march=native -Wall -Wextra -pedantic -pedantic-errors
LDFLAGS := -Wl,-z,relro,-z,now -lm

.PHONY: clean install uninstall

bench: bench.c
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)
	strip -R.comment $@

install: bench
	install bench $$HOME/.local/bin

uninstall:
	rm -f $$HOME/.local/bin/bench

clean:
	rm -f bench

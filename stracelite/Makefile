CC      ?= gcc
CFLAGS  ?= -O2 -Wall -Wextra -g
TESTS   := tests/t_files tests/t_fork tests/t_signal tests/t_mem tests/t_threads

all: stracelite $(TESTS)

stracelite: stracelite.c
	$(CC) $(CFLAGS) -o $@ $<

tests/t_threads: tests/t_threads.c
	$(CC) $(CFLAGS) -pthread -o $@ $<
tests/%: tests/%.c
	$(CC) $(CFLAGS) -o $@ $<

demo: all
	./stracelite -- tests/t_files
clean:
	rm -f stracelite $(TESTS)
.PHONY: all demo clean

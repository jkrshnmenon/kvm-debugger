CC = gcc
CFLAGS = -g -Wall

.PHONY: all clean debugger

all: debugger

debugger: main.c kvm_utils.c
	$(CC) $(CFLAGS) -o $@ $^

clean:
	rm debugger

CC      ?= cc
CFLAGS  ?= -std=c11 -O2 -Wall -Wextra -Wpedantic
LDLIBS  := -lmicrohttpd -lsqlite3 -lcrypto -lcrypt

SRC     := $(wildcard src/*.c)
OBJ     := $(SRC:.c=.o)
BIN     := toolshed

.PHONY: all clean

all: $(BIN)

$(BIN): $(OBJ)
	$(CC) $(CFLAGS) -o $@ $(OBJ) $(LDLIBS)

src/%.o: src/%.c
	$(CC) $(CFLAGS) -c -o $@ $<

clean:
	rm -f $(OBJ) $(BIN)

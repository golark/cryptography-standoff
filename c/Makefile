CC      ?= cc
CFLAGS  ?= -O2 -Wall -Wextra -std=c11
LDFLAGS ?=

SRC_DIR := src
INC_DIR := include
BUILD   := build
BIN     := rust-vs-c

SRCS := $(wildcard $(SRC_DIR)/*.c)
OBJS := $(SRCS:.c=.o)

.PHONY: all clean test bench

all: $(BUILD)/$(BIN)

$(BUILD)/$(BIN): $(OBJS)
	@mkdir -p $(BUILD)
	$(CC) $(CFLAGS) -o $@ $(OBJS) $(LDFLAGS)

%.o: %.c
	$(CC) $(CFLAGS) -I$(INC_DIR) -c $< -o $@

test: $(BUILD)/$(BIN)
	./$(BUILD)/$(BIN) --selftest

bench: $(BUILD)/$(BIN)
	./$(BUILD)/$(BIN) --bench

clean:
	rm -rf $(BUILD) $(OBJS)

CC ?= gcc
SAN ?=
BUILD ?= build

CFLAGS  := -std=c11 -O2 -g -Wall -Wextra -Wshadow -Werror -D_GNU_SOURCE -pthread -MMD -MP \
           $(if $(SAN),-fsanitize=$(SAN) -fno-omit-frame-pointer)
LDFLAGS := -pthread $(if $(SAN),-fsanitize=$(SAN))

CORE  := parse ipset queue detect pool
COREOBJS := $(CORE:%=$(BUILD)/%.o)
TESTS := test_parse test_ipset test_queue test_detect

.PHONY: all test asan tsan clean
all: $(BUILD)/idsniff

$(BUILD)/idsniff: $(COREOBJS) $(BUILD)/sniff.o $(BUILD)/main.o
	$(CC) -o $@ $^ $(LDFLAGS) -lpcap

$(BUILD)/%.o: src/%.c
	@mkdir -p $(BUILD)
	$(CC) $(CFLAGS) -Isrc -c -o $@ $<

$(BUILD)/tests/%: tests/%.c $(COREOBJS)
	@mkdir -p $(BUILD)/tests
	$(CC) $(CFLAGS) -Isrc -Itests -o $@ $^ $(LDFLAGS)

test: $(TESTS:%=$(BUILD)/tests/%)
	@for t in $(TESTS); do echo "== $$t"; $(BUILD)/tests/$$t || exit 1; done
	@echo "all tests passed"

asan:
	$(MAKE) test SAN=address,undefined BUILD=build/asan
tsan:
	$(MAKE) test SAN=thread BUILD=build/tsan

clean:
	rm -rf build

-include $(wildcard $(BUILD)/*.d)

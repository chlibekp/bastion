# Bastion build. Run through ./dev (Linux container); see README.md.
BUILD ?= debug
T ?=
K ?=
VERSION := 0.1.0

ARCH := $(shell uname -m)
LIBC := $(shell ldd --version 2>&1 | grep -qi musl && echo musl || echo glibc)
DEPS := build/deps/$(ARCH)-$(LIBC)
OUT := build/$(BUILD)

CC ?= clang
PC := PKG_CONFIG_LIBDIR=$(CURDIR)/$(DEPS)/lib/pkgconfig pkg-config --static
DEP_PKGS := openssl

WARN := -Wall -Wextra -Wshadow -Wconversion -Wformat=2 -Werror
CFLAGS_COMMON := -std=gnu17 $(WARN) -MMD -MP -D_GNU_SOURCE -DBST_VERSION='"$(VERSION)"' -Isrc \
	$(shell $(PC) --cflags $(DEP_PKGS) 2>/dev/null)
LIBS := $(shell $(PC) --libs $(DEP_PKGS) 2>/dev/null)

ifeq ($(BUILD),debug)
CFLAGS_BUILD := -O0 -g3
else ifeq ($(BUILD),asan)
CFLAGS_BUILD := -O1 -g -fno-omit-frame-pointer -fsanitize=address,undefined -fno-sanitize-recover=undefined
LDFLAGS_BUILD := -fsanitize=address,undefined
else ifeq ($(BUILD),tsan)
CFLAGS_BUILD := -O1 -g -fno-omit-frame-pointer -fsanitize=thread
LDFLAGS_BUILD := -fsanitize=thread
else ifeq ($(BUILD),release)
CFLAGS_BUILD := -O2 -g -DNDEBUG
LDFLAGS_BUILD := -static
else
$(error BUILD must be debug, asan, tsan or release)
endif

# Test-only hooks (BST_TEST) are compiled into every build except release.
CFLAGS_TEST := $(if $(filter release,$(BUILD)),,-DBST_TEST)
CFLAGS := $(CFLAGS_COMMON) $(CFLAGS_BUILD) $(CFLAGS_TEST)
LDFLAGS := $(LDFLAGS_BUILD)

# Tests run under ASan and UBSan unless BUILD is given explicitly.
TEST_BUILD := $(if $(filter command line,$(origin BUILD)),$(BUILD),asan)

LIB_SRCS := $(filter-out src/main.c,$(shell find src -name '*.c'))
LIB_OBJS := $(LIB_SRCS:%.c=$(OUT)/obj/%.o)
MAIN_OBJ := $(OUT)/obj/src/main.o
UNIT_SRCS := $(if $(T),tests/unit/test_$(T).c,$(wildcard tests/unit/test_*.c))
UNIT_BINS := $(UNIT_SRCS:tests/unit/%.c=$(OUT)/unit/%)

.PHONY: all deps test-unit test-int test-vm fuzz-smoke conformance clean
.DEFAULT_GOAL := all

# Flags come from pkg-config, so deps must exist before the real build is parsed: recurse.
all: deps
	$(MAKE) $(OUT)/bastion

# The dependency prefix is rebuilt only when the pins or the script change.
$(DEPS)/.built: deps/versions.env scripts/build-deps.sh
	scripts/build-deps.sh $(DEPS)
	touch $@

deps: $(DEPS)/.built

$(OUT)/bastion: $(MAIN_OBJ) $(LIB_OBJS)
	@mkdir -p $(@D)
	$(CC) $(LDFLAGS) -o $@ $^ $(LIBS)

$(OUT)/obj/%.o: %.c
	@mkdir -p $(@D)
	$(CC) $(CFLAGS) -c -o $@ $<

$(OUT)/unit/%: tests/unit/%.c $(LIB_OBJS) tests/unit/tap.h
	@mkdir -p $(@D)
	$(CC) $(CFLAGS) -Itests/unit $(LDFLAGS) -o $@ $< $(LIB_OBJS) $(LIBS)

test-unit: deps
	@test -n "$(UNIT_SRCS)" && ls $(UNIT_SRCS) >/dev/null
	$(MAKE) BUILD=$(TEST_BUILD) run-unit

.PHONY: run-unit
run-unit: $(UNIT_BINS)
	@set -e; for t in $(UNIT_BINS); do echo "# $$t"; ./$$t; done

test-int: deps
	$(MAKE) BUILD=$(TEST_BUILD) build/$(TEST_BUILD)/bastion
	BASTION_BIN=$(CURDIR)/build/$(TEST_BUILD)/bastion python3 -m pytest tests/integration -q $(if $(K),-k '$(K)')

# Boots a stock Debian kernel in QEMU and runs pytest in the guest. KERNEL is floor (6.1) or current.
KERNEL ?= current
test-vm:
	KERNEL=$(KERNEL) scripts/vm-run.sh python3 -m pytest tests/vm -q $(if $(K),-k '$(K)')

fuzz-smoke conformance:
	@echo "$@: not implemented yet" >&2
	@exit 2

clean:
	rm -rf build/debug build/asan build/tsan build/release

-include $(shell find $(OUT) -name '*.d' 2>/dev/null)

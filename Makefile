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
# PKG_CONFIG_PATH, not _LIBDIR: libbpf's .pc requires the system libelf and zlib. Our prefix
# is searched first, and the .built guard below makes a missing dependency an error.
PC := PKG_CONFIG_PATH=$(CURDIR)/$(DEPS)/lib/pkgconfig pkg-config --static
DEP_PKGS := openssl

WARN := -Wall -Wextra -Wshadow -Wconversion -Wformat=2 -Werror
# Until the deps exist (first run) flags are empty; the recursive build re-reads them. Once
# .built exists, a pkg-config failure stops the build with its message.
PC_CFLAGS :=
LIBS :=
ifneq ($(wildcard $(DEPS)/.built),)
PC_CFLAGS := $(shell $(PC) --cflags $(DEP_PKGS) 2>&1)
ifneq ($(.SHELLSTATUS),0)
$(error pkg-config --cflags $(DEP_PKGS) failed: $(PC_CFLAGS))
endif
LIBS := $(shell $(PC) --libs $(DEP_PKGS) 2>&1)
ifneq ($(.SHELLSTATUS),0)
$(error pkg-config --libs $(DEP_PKGS) failed: $(LIBS))
endif
endif
CFLAGS_COMMON := -std=gnu17 $(WARN) -MMD -MP -D_GNU_SOURCE -DBST_VERSION='"$(VERSION)"' -Isrc \
	$(PC_CFLAGS)

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
else ifeq ($(BUILD),musltest)
# Core tests on musl (Alpine image, selected by ./dev): plain build, test hooks on.
CFLAGS_BUILD := -O1 -g
ifneq ($(LIBC),musl)
$(error BUILD=musltest needs a musl system, found $(LIBC): run it through ./dev, which selects the Alpine image)
endif
else
$(error BUILD must be debug, asan, tsan, musltest or release)
endif

# Test-only hooks (BST_TEST) are compiled into every build except release.
CFLAGS_TEST := $(if $(filter release,$(BUILD)),,-DBST_TEST)
EXTRA_CFLAGS ?=
CFLAGS := $(CFLAGS_COMMON) $(CFLAGS_BUILD) $(CFLAGS_TEST) $(EXTRA_CFLAGS)
LDFLAGS := $(LDFLAGS_BUILD)

# Every object depends on the exact compiler, flags and version: change any and it rebuilds.
shq = '$(subst ','\'',$(1))'
FLAGS_SIG = $(CC) $(CFLAGS) | $(LDFLAGS)
$(OUT)/.flags: FORCE
	@mkdir -p $(@D)
	@printf '%s\n' $(call shq,$(FLAGS_SIG)) | cmp -s - $@ || printf '%s\n' $(call shq,$(FLAGS_SIG)) >$@
.PHONY: FORCE
FORCE:

# Tests run under ASan and UBSan unless BUILD is given explicitly.
TEST_BUILD := $(if $(filter command line,$(origin BUILD)),$(BUILD),asan)

LIB_SRCS := $(filter-out src/main.c,$(shell find src -name '*.c'))
LIB_OBJS := $(LIB_SRCS:%.c=$(OUT)/obj/%.o)
MAIN_OBJ := $(OUT)/obj/src/main.o
UNIT_SRCS := $(if $(T),tests/unit/test_$(T).c,$(wildcard tests/unit/test_*.c))
UNIT_BINS := $(UNIT_SRCS:tests/unit/%.c=$(OUT)/unit/%)

.PHONY: check-release all deps test-unit test-tsan test-deps test-int test-vm fuzz fuzz-smoke conformance clean
.DEFAULT_GOAL := all

# Flags come from pkg-config, so deps must exist before the real build is parsed: recurse.
all: deps
	$(MAKE) $(OUT)/bastion

# The script runs on every `make deps`: it decides by per-dep stamps (version, hash and
# recipe), so a pin or recipe edit rebuilds exactly that dep whatever the file mtimes say,
# and an up-to-date prefix costs only a few hashes. It takes a lock on the shared prefix.
$(DEPS)/.built: FORCE
	scripts/build-deps.sh $(DEPS)
	touch $@

deps: $(DEPS)/.built

$(OUT)/bastion: $(MAIN_OBJ) $(LIB_OBJS) $(OUT)/.flags
	@mkdir -p $(@D)
	$(CC) $(LDFLAGS) -o $@ $(MAIN_OBJ) $(LIB_OBJS) $(LIBS)

$(OUT)/obj/%.o: %.c $(OUT)/.flags
	@mkdir -p $(@D)
	$(CC) $(CFLAGS) -c -o $@ $<

$(OUT)/unit/%: tests/unit/%.c $(LIB_OBJS) tests/unit/tap.h $(OUT)/.flags
	@mkdir -p $(@D)
	$(CC) $(CFLAGS) -Itests/unit $(LDFLAGS) -o $@ $< $(LIB_OBJS) $(LIBS)

# The zero-table proof links the directive schema and its dependencies only, so tables that
# real src/ objects register (core directives) can never reach it.
SCHEMA_ONLY_OBJS := $(addprefix $(OUT)/obj/src/,config/schema.o config/values.o \
	config/parser.o config/lexer.o core/arena.o core/err.o core/cidr.o core/str.o core/addr.o)
$(OUT)/unit/test_cfg_schema_empty: tests/unit/test_cfg_schema_empty.c $(SCHEMA_ONLY_OBJS) tests/unit/tap.h $(OUT)/.flags
	@mkdir -p $(@D)
	$(CC) $(CFLAGS) -Itests/unit $(LDFLAGS) -o $@ $< $(SCHEMA_ONLY_OBJS) -pthread

ifeq ($(BUILD),release)
RELEASE_UNIT_MSG := BUILD=release has no test hooks (BST_TEST is off): use BUILD=musltest for core tests on musl
endif

test-unit: deps
	@$(if $(and $(filter release,$(BUILD)),$(filter command line,$(origin BUILD))),echo "$(RELEASE_UNIT_MSG)" >&2; exit 2,true)
	@test -n "$(UNIT_SRCS)" && ls $(UNIT_SRCS) >/dev/null
	$(MAKE) BUILD=$(TEST_BUILD) run-unit tap-selftest

.PHONY: run-unit tap-selftest
run-unit: $(UNIT_BINS)
	@set -e; for t in $(UNIT_BINS); do echo "# $$t"; ./$$t; done

# Release verification: build the static binary and prove the directive tables survived the
# link. The table count is the number of registrations in src/ (core tables), so a binary
# that lost any fails. Run it through ./dev: ./dev make check-release BUILD=release.
CORE_TABLES := $(shell grep -rhE '^BST_DIRECTIVES[[:space:]]*[^[:alnum:]_[:space:]]' src | wc -l | tr -d ' ')
check-release: deps
	@test "$(BUILD)" = release || { echo "check-release needs BUILD=release" >&2; exit 2; }
	$(MAKE) $(OUT)/bastion
	scripts/check-directives-linked.sh $(OUT)/bastion $(CORE_TABLES)

test-tsan:
	$(MAKE) test-unit BUILD=tsan

# Checks the dependency prefix: every pinned library resolves through pkg-config and links.
test-deps: deps
	DEPS=$(DEPS) CC=$(CC) tests/deps/check.sh
	DEPS=$(DEPS) tests/deps/test_stamps.sh
	CC=$(CC) tests/deps/test_linked_check.sh

# The harness's own guarantees: exit 1 on failure or on no tests, abort on overflow, no
# duplicated lines from a forked child.
tap-selftest: $(OUT)/unit/test_smoke
	CC="$(CC)" CFLAGS="$(CFLAGS)" LDFLAGS="$(LDFLAGS)" scripts/tap-selftest.sh $(OUT)/tap-selftest ./$(OUT)/unit/test_smoke

test-int: deps
	$(MAKE) BUILD=$(TEST_BUILD) build/$(TEST_BUILD)/bastion
	BASTION_BIN=$(CURDIR)/build/$(TEST_BUILD)/bastion python3 -m pytest tests/integration -q $(if $(K),-k '$(K)')

# Boots a stock Debian kernel in QEMU and runs pytest in the guest. KERNEL is floor (6.1) or current.
KERNEL ?= current
test-vm:
	KERNEL=$(KERNEL) scripts/vm-run.sh python3 -m pytest tests/vm -q $(if $(K),-k '$(K)')

# Fuzzing: `make fuzz T=name SECS=n` runs one harness (cfg or fuzz_cfg); `make fuzz-smoke`
# runs every fuzz/fuzz_*.c for SECS each (default 60); SEED=n replays a run (default: fresh per harness, printed). See fuzz/README.md.
SECS ?= 60
SEED ?=
include fuzz/harness.mk

fuzz: deps
	@test -n "$(T)" || { echo "usage: make fuzz T=<harness> [SECS=n]" >&2; exit 2; }
	SEED=$(SEED) scripts/fuzz-smoke.sh $(SECS) $(T)

fuzz-smoke: deps
	SEED=$(SEED) scripts/fuzz-smoke.sh $(SECS)

conformance:
	@echo "$@: not implemented yet" >&2
	@exit 2

clean:
	rm -rf build/debug build/asan build/tsan build/musltest build/release build/fuzz

-include $(shell find $(OUT) -name '*.d' 2>/dev/null)

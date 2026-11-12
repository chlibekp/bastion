# Bastion build. Run through ./dev (Linux container); see README.md. `make help` lists the knobs.
BUILD ?= debug
# T selects unit tests: one name or a comma list, e.g. T='loop,io_tcp' (tests/unit/test_<name>.c).
T ?=
# BACKEND=epoll|uring picks the event-loop backend for the unit run; it is passed to tests as
# BST_TEST_BACKEND (default epoll). test_uring_only runs on io_uring whatever BACKEND says.
BACKEND ?=
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
DEP_PKGS := openssl liburing libpcre2-8 libngtcp2_crypto_ossl libngtcp2 libnghttp3 libbpf

WARN := -Wall -Wextra -Wshadow -Wconversion -Wformat=2 -Werror
# Until the deps exist (first run) flags are empty; the recursive build re-reads them. Once
# .built exists, a pkg-config failure stops the build with its message.
PC_CFLAGS :=
LIBS :=
ifneq ($(wildcard $(DEPS)/.built),)
PC_CFLAGS := $(shell $(PC) --cflags $(DEP_PKGS) mimalloc 2>&1)
ifneq ($(.SHELLSTATUS),0)
$(error pkg-config --cflags $(DEP_PKGS) mimalloc failed: $(PC_CFLAGS))
endif
LIBS := $(shell $(PC) --libs $(DEP_PKGS) 2>&1)
ifneq ($(.SHELLSTATUS),0)
$(error pkg-config --libs $(DEP_PKGS) failed: $(LIBS))
endif
endif
# mimalloc: OpenSSL allocates from it in every build, but it replaces malloc only in release and
# musltest. Overriding malloc would defeat ASan and TSan, so everything else links the build
# made with MI_OVERRIDE=OFF (scripts/build-deps.sh). It comes first, so that in a static link
# malloc resolves here and not in libc.
ifneq ($(filter release musltest,$(BUILD)),)
MI_LIB := $(DEPS)/lib/libmimalloc.a
CFLAGS_MI := -DBST_MI_OVERRIDE
else
MI_LIB := $(DEPS)/lib/libmimalloc-nooverride.a
CFLAGS_MI :=
endif
ifneq ($(wildcard $(DEPS)/.built),)
LIBS := $(MI_LIB) $(LIBS)
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
# Frame pointers: the crash handler walks them (musl has no execinfo).
CFLAGS_BUILD := -O2 -g -DNDEBUG -fno-omit-frame-pointer
LDFLAGS_BUILD := -static
else ifeq ($(BUILD),musltest)
# Core tests on musl (Alpine image, selected by ./dev): plain build, test hooks on.
CFLAGS_BUILD := -O1 -g -fno-omit-frame-pointer
ifneq ($(LIBC),musl)
$(error BUILD=musltest needs a musl system, found $(LIBC): run it through ./dev, which selects the Alpine image)
endif
else
$(error BUILD must be debug, asan, tsan, musltest or release)
endif

# Test-only hooks (BST_TEST) are compiled into every build except release.
CFLAGS_TEST := $(if $(filter release,$(BUILD)),,-DBST_TEST)
EXTRA_CFLAGS ?=
CFLAGS := $(CFLAGS_COMMON) $(CFLAGS_BUILD) $(CFLAGS_TEST) $(CFLAGS_MI) $(EXTRA_CFLAGS)
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

# *.bpf.c are BPF programs: built for the BPF target and embedded by tools/embed.mk.
LIB_SRCS := $(filter-out src/main.c %.bpf.c,$(shell find src -name '*.c'))
# The sandbox probe is a test fixture linked into every build but release.
LIB_SRCS += $(if $(filter release,$(BUILD)),,tests/fixtures/sandbox_probe.c)
include tools/embed.mk
LIB_OBJS := $(LIB_SRCS:%.c=$(OUT)/obj/%.o) $(EMBED_OBJS)
MAIN_OBJ := $(OUT)/obj/src/main.o
comma := ,
space := $(subst ,, )
UNIT_SRCS := $(if $(T),$(foreach t,$(subst $(comma),$(space),$(T)),tests/unit/test_$(t).c),$(wildcard tests/unit/test_*.c))
UNIT_BINS := $(UNIT_SRCS:tests/unit/%.c=$(OUT)/unit/%)

.PHONY: help gen-reference gen-known-headers gen-huffman check-release all deps test-unit test-tsan test-deps test-int test-int-nosan test-vm fuzz fuzz-smoke conformance clean
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
	$(CC) $(CFLAGS) -Itests/unit $(LDFLAGS) -o $@ $< $(LIB_OBJS) $(LIBS) -pthread

# The zero-table proof links the directive schema and its dependencies only, so tables that
# real src/ objects register (core directives) can never reach it.
SCHEMA_ONLY_OBJS := $(addprefix $(OUT)/obj/src/,config/schema.o config/schema_args.o config/validate.o config/registry.o config/errfmt.o config/template.o config/values.o \
	config/parser.o config/lexer.o core/arena.o core/err.o core/cidr.o core/str.o core/addr.o)
$(OUT)/unit/test_cfg_schema_empty: tests/unit/test_cfg_schema_empty.c $(SCHEMA_ONLY_OBJS) tests/unit/tap.h $(OUT)/.flags
	@mkdir -p $(@D)
	$(CC) $(CFLAGS) -Itests/unit $(LDFLAGS) -o $@ $< $(SCHEMA_ONLY_OBJS) -pthread

ifeq ($(BUILD),release)
RELEASE_UNIT_MSG := BUILD=release has no test hooks (BST_TEST is off): use BUILD=musltest for core tests on musl
endif

help:
	@echo "make test-unit [T=a,b] [BACKEND=epoll|uring] [BUILD=debug|asan|tsan|musltest]"
	@echo "  T        comma list of tests/unit/test_<name>.c (default: all)"
	@echo "  BACKEND  event-loop backend for backend-parametrised tests, sent as BST_TEST_BACKEND"
	@echo "           (default epoll); test_uring_only always runs on io_uring"
	@echo "other targets: all deps test-tsan test-deps test-int test-int-nosan test-vm fuzz fuzz-smoke clean"

test-unit: deps
	@$(if $(filter-out epoll uring,$(BACKEND)),$(if $(BACKEND),echo "BACKEND must be epoll or uring" >&2; exit 2,true),true)
	@$(if $(and $(filter release,$(BUILD)),$(filter command line,$(origin BUILD))),echo "$(RELEASE_UNIT_MSG)" >&2; exit 2,true)
	@test -n "$(UNIT_SRCS)" && ls $(UNIT_SRCS) >/dev/null
	$(MAKE) BUILD=$(TEST_BUILD) run-unit tap-selftest

.PHONY: run-unit tap-selftest
run-unit: $(UNIT_BINS)
	@set -e; for t in $(UNIT_BINS); do echo "# $$t"; BST_TEST_BACKEND=$(or $(BACKEND),epoll) ./$$t; done

# Regenerates docs/config-reference.md from the built binary's own directive tables. Run it
# after adding or changing any directive: ./dev make gen-reference
gen-reference: deps
	$(MAKE) $(OUT)/bastion
	scripts/gen-config-reference.sh $(OUT)/bastion docs/config-reference.md

# Regenerates the known-header perfect hash after an edit of src/http/known_headers.def.
gen-known-headers:
	python3 scripts/gen-known-headers.py

# Regenerates the HPACK Huffman tables (src/http/h2/huffman_table.inc) from the RFC 7541 code lengths.
gen-huffman:
	python3 scripts/gen-huffman.py

# Release verification: build the static binary and prove the directive tables survived the
# link. The table count is the number of registrations in src/ (core tables), so a binary
# that lost any fails. Run it through ./dev: ./dev make check-release BUILD=release.
CORE_TABLES := $(shell grep -rhE '^BST_DIRECTIVES[[:space:]]*[^[:alnum:]_[:space:]]' src | wc -l | tr -d ' ')
CORE_HOOKS := $(shell grep -rhE '^BST_CFG_POST[[:space:]]*[^[:alnum:]_[:space:]]' src | wc -l | tr -d ' ')
check-release: deps
	@test "$(BUILD)" = release || { echo "check-release needs BUILD=release" >&2; exit 2; }
	$(MAKE) $(OUT)/bastion
	scripts/check-directives-linked.sh $(OUT)/bastion $(CORE_TABLES) $(CORE_HOOKS)
	@test "$(CORE_HOOKS)" -gt 0 || { echo "check-release: no BST_CFG_POST hooks found in src (the count is broken)" >&2; exit 1; }
	@! nm $(OUT)/bastion | grep -q bst_test_ && ! strings $(OUT)/bastion | grep -qE 'BST_TEST_|--test-listeners|--test-accept-ms' \
		|| { echo "check-release: a test seam (BST_TEST_*, --test-listeners or bst_test_*) is in the release binary" >&2; exit 1; }
	@! strings $(OUT)/bastion | grep -q 'sandbox probe' \
		|| { echo "check-release: BST_TEST_SANDBOX_PROBE is in the release binary" >&2; exit 1; }
	$(MAKE) $(OUT)/fixtures/seccomp_list
	$(OUT)/fixtures/seccomp_list | scripts/check-release-allowlist.sh
	@nm $(OUT)/bastion | grep -q ' bst_listener_create$$' \
		|| { echo "check-release: bst_listener_create is missing: the release binary lost the listener code" >&2; exit 1; }
	scripts/check-mimalloc-linked.sh $(OUT)/bastion

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
	$(MAKE) BUILD=$(TEST_BUILD) build/$(TEST_BUILD)/bastion build/$(TEST_BUILD)/fixtures/seccomp_no_uring build/$(TEST_BUILD)/fixtures/h3client
	BASTION_BUILD=$(TEST_BUILD) BASTION_BIN=$(CURDIR)/build/$(TEST_BUILD)/bastion SECCOMP_WRAP=$(CURDIR)/build/$(TEST_BUILD)/fixtures/seccomp_no_uring \
	H3CLIENT=$(CURDIR)/build/$(TEST_BUILD)/fixtures/h3client python3 -m pytest tests/integration -q $(if $(K),-k '$(K)')

# The file-serving tests against the binary WITHOUT sanitizers, seccomp on: a sanitizer build
# allows extra syscalls, so only this run proves the filter lets the real worker serve files.
# Afterwards `dmesg | grep type=1326` must show no new kill. Set TEST_BUILD=musltest for musl.
test-int-nosan:
	$(MAKE) TEST_BUILD=$(or $(NOSAN_BUILD),debug) test-int K='file_safety or static or rewrite or tls_conn or ktls_fallback or test_sni or test_tickets or test_ocsp or test_mtls or test_ja4 or test_early_data or test_h2'

# Prints the allowlist compiled with this build's flags: `make check-release` reads the release one
# without a flag in the binary to ask it.
$(OUT)/fixtures/seccomp_list: tests/fixtures/seccomp_list.c $(OUT)/obj/src/proc/seccomp.o $(OUT)/obj/src/proc/seccomp_tables.o $(OUT)/.flags
	@mkdir -p $(@D)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $< $(OUT)/obj/src/proc/seccomp.o $(OUT)/obj/src/proc/seccomp_tables.o

# Test fixture: execs a command under a seccomp filter that refuses io_uring_setup (EPERM).
$(OUT)/fixtures/seccomp_no_uring: tests/fixtures/seccomp_no_uring.c $(OUT)/.flags
	@mkdir -p $(@D)
	$(CC) -std=gnu17 -Wall -Wextra -Werror -O1 -D_GNU_SOURCE -o $@ $<

# Test fixture: the HTTP/3 client of the QUIC tests, on the pinned ngtcp2 and nghttp3. Built
# without sanitizers and with its own warning set: it is a tool, not code under test.
$(OUT)/fixtures/h3client: tests/fixtures/h3client.c $(OUT)/.flags
	@mkdir -p $(@D)
	$(CC) -std=gnu17 -Wall -Wextra -Werror -O1 -g -D_GNU_SOURCE $(PC_CFLAGS) -o $@ $< \
		$$($(PC) --libs libngtcp2_crypto_ossl libngtcp2 libnghttp3 openssl)

# Boots a stock Debian kernel in QEMU and runs pytest in the guest. KERNEL is floor (6.1) or current.
# The io_uring unit suites (tests/vm/test_uring_vm.py) are built here first, in BUILD=debug:
# the guest only runs them.
KERNEL ?= current
VM_UNIT_BINS := $(addprefix build/debug/unit/test_,uring_only uring_net io_fair loop io_tcp udp udp_edge reuseport_bpf)
test-vm: deps
	$(MAKE) BUILD=debug $(VM_UNIT_BINS) build/debug/bastion
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

# Protocol conformance corpora (tests/conformance), run against the real binary on both backends.
# K selects by name: `make conformance K=h1`. Later phases add their corpora here.
conformance: deps
	$(MAKE) BUILD=$(TEST_BUILD) build/$(TEST_BUILD)/bastion build/$(TEST_BUILD)/fixtures/h3client
	BASTION_BUILD=$(TEST_BUILD) BASTION_BIN=$(CURDIR)/build/$(TEST_BUILD)/bastion H3CLIENT=$(CURDIR)/build/$(TEST_BUILD)/fixtures/h3client \
	python3 -m pytest tests/conformance -q $(if $(K),-k '$(K)')

clean:
	rm -rf build/debug build/asan build/tsan build/musltest build/release build/fuzz build/embed

-include $(shell find $(OUT) -name '*.d' 2>/dev/null)

# Fuzz harness build rules, included by the Makefile. Library objects are built with
# libFuzzer instrumentation disabled (fuzz-no-link) in their own tree so they are never
# mixed with objects from other BUILD values. Harness names come from FUZZ_NAMES.
FUZZ_SRC_DIR ?= fuzz
FUZZ_OUT := build/fuzz
# No -DBST_TEST: fuzz objects are built without the test hooks, like release.
FUZZ_CFLAGS := $(CFLAGS_COMMON) -O1 -g -fno-omit-frame-pointer \
	-fsanitize=address,undefined -fno-sanitize-recover=undefined
FUZZ_LIB_OBJS := $(LIB_SRCS:%.c=$(FUZZ_OUT)/obj/%.o)
FUZZ_BINS := $(FUZZ_NAMES:%=$(FUZZ_OUT)/bin/%)

FUZZ_SIG = $(CC) $(FUZZ_CFLAGS)
$(FUZZ_OUT)/.flags: FORCE
	@mkdir -p $(@D)
	@printf '%s\n' $(call shq,$(FUZZ_SIG)) | cmp -s - $@ || printf '%s\n' $(call shq,$(FUZZ_SIG)) >$@

$(FUZZ_OUT)/obj/%.o: %.c $(FUZZ_OUT)/.flags
	@mkdir -p $(@D)
	$(CC) $(FUZZ_CFLAGS) -fsanitize=fuzzer-no-link -c -o $@ $<

$(FUZZ_OUT)/bin/%: $(FUZZ_SRC_DIR)/%.c $(FUZZ_LIB_OBJS) $(FUZZ_OUT)/.flags
	@mkdir -p $(@D) $(FUZZ_OUT)/dep
	$(CC) $(FUZZ_CFLAGS) -fsanitize=fuzzer -MT $@ -MF $(FUZZ_OUT)/dep/$*.d -o $@ $< $(FUZZ_LIB_OBJS) $(LIBS)

.PHONY: fuzz-build
fuzz-build: $(FUZZ_BINS)

-include $(shell find $(FUZZ_OUT)/obj $(FUZZ_OUT)/dep -name '*.d' 2>/dev/null)

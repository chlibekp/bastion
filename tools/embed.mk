# Build artefacts embedded in the binary, included by the Makefile (Phase 8; Phase 13 reuses it).
#
# Every src/<dir>/<name>.bpf.c is a BPF program: it is compiled for the BPF target (with BTF, which
# libbpf needs for the map definitions) to build/embed/bpf/<dir>/<name>.bpf.o, and that object is
# embedded through an .incbin stub as the read-only bytes
#     extern const unsigned char bst_embed_<name>[], bst_embed_<name>_end[];
# The objects do not depend on BUILD (no sanitizer or debug flag reaches a BPF program), so every
# build, fuzz included, links the same ones from build/embed. To embed another kind of file, add
# a pattern rule that produces build/embed/<path>.bin and list it in EMBED_BINS.
EMBED_OUT := build/embed
BPF_SRCS := $(shell find src -name '*.bpf.c')
BPF_OBJS := $(BPF_SRCS:src/%.bpf.c=$(EMBED_OUT)/bpf/%.bpf.o)
EMBED_BINS ?=
EMBED_OBJS := $(BPF_SRCS:src/%.bpf.c=$(EMBED_OUT)/obj/%.o) $(EMBED_BINS:%.bin=%.o)

# Debian keeps asm/ under the multiarch directory, which -target bpf does not search.
BPF_CFLAGS := -O2 -g -target bpf -Wall -Wextra -Werror -Isrc -I$(DEPS)/include \
	-idirafter /usr/include/$(shell gcc -dumpmachine 2>/dev/null)

.SECONDARY: $(BPF_OBJS) # kept: the VM tier loads them to check the verifier
$(EMBED_OUT)/bpf/%.bpf.o: src/%.bpf.c src/http/h3/cid_wire.h
	@mkdir -p $(@D)
	$(CC) $(BPF_CFLAGS) -c -o $@ $<

# The stub names the bytes after the file, without directory or extension.
embed_sym = bst_embed_$(basename $(basename $(notdir $(1))))
define embed_stub
	@mkdir -p $(@D)
	printf '\t.section .rodata\n\t.balign 16\n\t.globl %s\n%s:\n\t.incbin "%s"\n\t.globl %s_end\n%s_end:\n\t.byte 0\n\t.section .note.GNU-stack,"",%%progbits\n' \
		$(call embed_sym,$<) $(call embed_sym,$<) $< $(call embed_sym,$<) $(call embed_sym,$<) \
		| $(CC) -c -x assembler -o $@ -
endef

$(EMBED_OUT)/obj/%.o: $(EMBED_OUT)/bpf/%.bpf.o
	$(embed_stub)

$(EMBED_OUT)/%.o: $(EMBED_OUT)/%.bin
	$(embed_stub)

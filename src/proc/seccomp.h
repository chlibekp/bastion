/* The seccomp filter as data: a table of syscalls (seccomp_tables.c) and a builder that turns it
 * into a classic BPF program for an architecture and a role (seccomp.c). Pure: nothing here needs
 * the kernel, and any host can build the program for any architecture, which is how the x86_64
 * table is tested on an arm64 host (tests/unit/test_seccomp.c).
 *
 * The program. The architecture first: anything else, the 32-bit ABIs above all, dies, in every
 * mode. On x86_64 the x32 range next, for the same reason: it reaches the kernel's own entry
 * points under numbers this table never mentions. Then one test per entry, and at the end the
 * default: SECCOMP_RET_KILL_PROCESS, or SECCOMP_RET_LOG under `seccomp log`.
 *
 * clone has no entry and so has no allowed form: thread and process creation both die, whatever
 * the flags. clone3 answers ENOSYS, because its flags sit behind a pointer that a filter cannot
 * read and a libc that gets ENOSYS falls back to clone. */
#ifndef BST_PROC_SECCOMP_H
#define BST_PROC_SECCOMP_H

#include "config/compile.h"
#include "proc/sandbox.h"

#include <linux/filter.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef enum bst_seccomp_arch { BST_ARCH_X86_64, BST_ARCH_AARCH64 } bst_seccomp_arch;

#define BST_SC_WORKER (1u << BST_SANDBOX_WORKER)
#define BST_SC_HELPER (1u << BST_SANDBOX_HELPER)
#define BST_SC_ROLES (BST_SC_WORKER | BST_SC_HELPER)

#define BST_SC_MAX_VALS 8u

/* A test on the low 32 bits of one argument. Every argument filtered here is an int or a
 * flag word in its low half, and both architectures are little endian. */
typedef enum bst_sc_test {
	BST_SC_IN,	/* (arg & mask) is one of vals */
	BST_SC_NO_BITS, /* no bit of mask is set in arg */
	BST_SC_IS_SELF, /* arg is the calling process's pid */
} bst_sc_test;

typedef struct bst_sc_cond {
	bst_sc_test test;
	uint8_t arg;
	uint32_t mask;
	uint8_t nvals;
	uint32_t vals[BST_SC_MAX_VALS];
} bst_sc_cond;

typedef struct bst_sc_entry {
	const char *name;
	int x86_64, aarch64;	  /* the numbers; -1 where the architecture has no such syscall */
	unsigned roles;		  /* BST_SC_* */
	int fail_errno;		  /* nonzero: answer this errno, nothing runs */
	const bst_sc_cond *conds; /* all must hold; NULL for none */
	unsigned nconds;
	bool sanitizer_only;	  /* compiled into sanitizer builds alone */
	const char *why;
} bst_sc_entry;

const bst_sc_entry *bst_seccomp_table(size_t *n);

typedef struct bst_seccomp_opts {
	bst_seccomp_arch arch;
	bst_sandbox_role role;
	bst_seccomp_mode mode; /* ON or LOG */
	uint32_t self_pid;     /* as getpid answers it: 1 in a PID namespace */
} bst_seccomp_opts;

/* Writes the program to out. Its length, -ENOSPC when cap is too small, or -EOVERFLOW for a table
 * no classic BPF jump can span. */
long bst_seccomp_build(const bst_seccomp_opts *o, struct sock_filter *out, size_t cap);

/* The names a role may call on an architecture, each on a line of its own, with a newline first:
 * "\nread\nwrite\n". How many bytes that took, not counting the NUL. Arguments are not shown. */
size_t bst_seccomp_list(bst_seccomp_arch arch, bst_sandbox_role role, char *buf, size_t cap);

#endif

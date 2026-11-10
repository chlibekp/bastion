/* See seccomp.h. */
#include "proc/seccomp.h"

#include <errno.h>
#include <linux/audit.h>
#include <linux/seccomp.h>
#include <stdio.h>
#include <string.h>

#ifndef AUDIT_ARCH_AARCH64
#define AUDIT_ARCH_AARCH64 0xC00000B7u
#endif
#ifndef AUDIT_ARCH_X86_64
#define AUDIT_ARCH_X86_64 0xC000003Eu
#endif
#define X32_SYSCALL_BIT 0x40000000u

typedef struct emit {
	struct sock_filter *out;
	size_t cap, n;
	bool full;
} emit;

static void put(emit *e, uint16_t code, uint8_t jt, uint8_t jf, uint32_t k)
{
	if (e->n >= e->cap) {
		e->full = true;
		return;
	}
	e->out[e->n++] = (struct sock_filter){ code, jt, jf, k };
}

static void load(emit *e, size_t offset)
{
	put(e, BPF_LD | BPF_W | BPF_ABS, 0, 0, (uint32_t)offset);
}

static void ret(emit *e, uint32_t action)
{
	put(e, BPF_RET | BPF_K, 0, 0, action);
}

static int nr_for(const bst_sc_entry *t, bst_seccomp_arch arch)
{
	return arch == BST_ARCH_X86_64 ? t->x86_64 : t->aarch64;
}

static bool applies(const bst_sc_entry *t, bst_seccomp_arch arch, bst_sandbox_role role)
{
	return nr_for(t, arch) >= 0 && (t->roles & (1u << role)) != 0;
}

/* Instructions cond takes, so that the test on the syscall number can jump past them. */
static size_t cond_len(const bst_sc_cond *c)
{
	switch (c->test) {
	case BST_SC_IN:
		return 1 + (c->mask != UINT32_MAX) + c->nvals + 1;
	case BST_SC_NO_BITS:
	case BST_SC_IS_SELF:
		return 3;
	}
	return 0;
}

/* Falls through to the next instruction when c holds, returns `deny` when it does not. */
static void put_cond(emit *e, const bst_sc_cond *c, uint32_t self_pid, uint32_t deny)
{
	load(e, offsetof(struct seccomp_data, args[0]) + c->arg * sizeof(uint64_t));
	switch (c->test) {
	case BST_SC_IN:
		if (c->mask != UINT32_MAX)
			put(e, BPF_ALU | BPF_AND | BPF_K, 0, 0, c->mask);
		for (unsigned i = 0; i < c->nvals; i++)
			put(e, BPF_JMP | BPF_JEQ | BPF_K, (uint8_t)(c->nvals - i), 0, c->vals[i]);
		break;
	case BST_SC_NO_BITS:
		put(e, BPF_JMP | BPF_JSET | BPF_K, 0, 1, c->mask);
		break;
	case BST_SC_IS_SELF:
		put(e, BPF_JMP | BPF_JEQ | BPF_K, 1, 0, self_pid);
		break;
	}
	ret(e, deny);
}

/* One entry: the test on the number, then a body that always ends in RET, which is what lets
 * the body clobber the accumulator without loading the number back. */
static bool put_entry(emit *e, const bst_sc_entry *t, const bst_seccomp_opts *o, uint32_t deny)
{
	size_t body = 1;
	for (unsigned i = 0; i < t->nconds; i++)
		body += cond_len(&t->conds[i]);
	if (body > UINT8_MAX)
		return false;
	put(e, BPF_JMP | BPF_JEQ | BPF_K, 0, (uint8_t)body, (uint32_t)nr_for(t, o->arch));
	for (unsigned i = 0; i < t->nconds; i++)
		put_cond(e, &t->conds[i], o->self_pid, deny);
	ret(e, t->fail_errno != 0 ? SECCOMP_RET_ERRNO | (uint32_t)t->fail_errno : SECCOMP_RET_ALLOW);
	return true;
}

long bst_seccomp_build(const bst_seccomp_opts *o, struct sock_filter *out, size_t cap)
{
	emit e = { .out = out, .cap = cap };
	uint32_t deny = o->mode == BST_SECCOMP_LOG ? SECCOMP_RET_LOG : SECCOMP_RET_KILL_PROCESS;
	bool x86 = o->arch == BST_ARCH_X86_64;

	load(&e, offsetof(struct seccomp_data, arch));
	put(&e, BPF_JMP | BPF_JEQ | BPF_K, 1, 0, x86 ? AUDIT_ARCH_X86_64 : AUDIT_ARCH_AARCH64);
	ret(&e, SECCOMP_RET_KILL_PROCESS);
	load(&e, offsetof(struct seccomp_data, nr));
	if (x86) { /* an unsigned compare: -1 lands here too, and on a default kill further down */
		put(&e, BPF_JMP | BPF_JGE | BPF_K, 0, 1, X32_SYSCALL_BIT);
		ret(&e, SECCOMP_RET_KILL_PROCESS);
	}
	size_t n;
	const bst_sc_entry *t = bst_seccomp_table(&n);
	for (size_t i = 0; i < n; i++) {
		/* A sanitizer row only keeps a report alive under a kill: under `log` nothing dies. */
		if (t[i].sanitizer_only && o->mode == BST_SECCOMP_LOG)
			continue;
		if (applies(&t[i], o->arch, o->role) && !put_entry(&e, &t[i], o, deny))
			return -EOVERFLOW;
	}
	ret(&e, deny);
	if (e.full)
		return -ENOSPC;
	if (e.n > BPF_MAXINSNS)
		return -EOVERFLOW;
	return (long)e.n;
}

size_t bst_seccomp_list(bst_seccomp_arch arch, bst_sandbox_role role, char *buf, size_t cap)
{
	size_t n, used = (size_t)snprintf(buf, cap, "\n");
	const bst_sc_entry *t = bst_seccomp_table(&n);
	for (size_t i = 0; i < n && used < cap; i++)
		if (applies(&t[i], arch, role))
			used += (size_t)snprintf(buf + used, cap - used, "%s\n", t[i].name);
	return used < cap ? used : cap - 1;
}

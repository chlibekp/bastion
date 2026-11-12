/* See reuseport.h. The program's ELF object is embedded by tools/embed.mk as
 * bst_embed_reuseport_quic[_end]. */
#include "xdp/reuseport.h"

#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#ifndef SO_ATTACH_REUSEPORT_EBPF
#define SO_ATTACH_REUSEPORT_EBPF 52
#endif

extern const unsigned char bst_embed_reuseport_quic[];
extern const unsigned char bst_embed_reuseport_quic_end[];

struct bst_reuseport {
	struct bpf_object *obj;
	int socks_fd, active_fd, stats_fd;
	int nfds;
};

/* libbpf prints to stderr by default; its messages are folded into err instead. */
static char last_msg[256];
static int on_libbpf_print(enum libbpf_print_level lvl, const char *fmt, va_list ap)
	__attribute__((format(printf, 2, 0)));
static int on_libbpf_print(enum libbpf_print_level lvl, const char *fmt, va_list ap)
{
	if (lvl == LIBBPF_WARN) {
		vsnprintf(last_msg, sizeof last_msg, fmt, ap);
		size_t n = strlen(last_msg);
		while (n > 0 && (last_msg[n - 1] == '\n' || last_msg[n - 1] == ' '))
			last_msg[--n] = '\0';
	}
	return 0;
}

static int fail(bst_err *e, const char *what, int err)
{
	if (last_msg[0])
		bst_err_set(e, "quic_routing ebpf: %s: %s (%s)", what, strerror(err), last_msg);
	else
		bst_err_set(e, "quic_routing ebpf: %s: %s", what, strerror(err));
	return -1;
}

int bst_reuseport_set_active(bst_reuseport *r, const bst_slot_map *a, bst_err *e)
{
	if (a == NULL || a->n == 0 || a->n > (size_t)r->nfds) {
		bst_err_set(e, "quic_routing ebpf: no active slots");
		return -1;
	}
	for (size_t i = 0; i < a->n; i++) {
		if (a->slots[i] >= r->nfds) {
			bst_err_set(e, "quic_routing ebpf: slot %u has no socket", a->slots[i]);
			return -1;
		}
		uint32_t k = (uint32_t)i + 1, v = a->slots[i];
		if (bpf_map_update_elem(r->active_fd, &k, &v, BPF_ANY) != 0)
			return fail(e, "active slots", errno);
	}
	/* The count last: a reader sees either the old n over the old slots and some new ones, or
	 * the new n. Every listed slot has a socket either way. */
	uint32_t zero = 0, n = (uint32_t)a->n;
	if (bpf_map_update_elem(r->active_fd, &zero, &n, BPF_ANY) != 0)
		return fail(e, "active slots", errno);
	return 0;
}

bst_reuseport *bst_reuseport_attach(const int *fds, int nfds, const bst_slot_map *active, bst_err *e)
{
	if (nfds < 1 || nfds > 8192) {
		bst_err_set(e, "quic_routing ebpf: %d sockets", nfds);
		return NULL;
	}
	last_msg[0] = '\0';
	libbpf_set_print(on_libbpf_print);
	bst_reuseport *r = calloc(1, sizeof *r);
	if (r == NULL) {
		bst_err_set(e, "quic_routing ebpf: out of memory");
		return NULL;
	}
	r->nfds = nfds;
	size_t len = (size_t)(bst_embed_reuseport_quic_end - bst_embed_reuseport_quic);
	LIBBPF_OPTS(bpf_object_open_opts, oo, .object_name = "bst_reuseport_quic");
	r->obj = bpf_object__open_mem(bst_embed_reuseport_quic, len, &oo);
	if (r->obj == NULL) {
		fail(e, "open", errno);
		free(r);
		return NULL;
	}
	struct bpf_map *socks = bpf_object__find_map_by_name(r->obj, "socks");
	struct bpf_map *act = bpf_object__find_map_by_name(r->obj, "active");
	struct bpf_map *st = bpf_object__find_map_by_name(r->obj, "stats");
	struct bpf_program *prog = bpf_object__find_program_by_name(r->obj, "bst_quic_select");
	if (socks == NULL || act == NULL || st == NULL || prog == NULL) {
		bst_err_set(e, "quic_routing ebpf: embedded object is incomplete");
		goto out;
	}
	if (bpf_map__set_max_entries(socks, (uint32_t)nfds) != 0) {
		fail(e, "map size", errno);
		goto out;
	}
	if (bpf_object__load(r->obj) != 0) {
		fail(e, "load", errno);
		goto out;
	}
	r->socks_fd = bpf_map__fd(socks);
	r->active_fd = bpf_map__fd(act);
	r->stats_fd = bpf_map__fd(st);
	for (int i = 0; i < nfds; i++) {
		uint32_t k = (uint32_t)i;
		uint64_t v = (uint64_t)fds[i];
		if (bpf_map_update_elem(r->socks_fd, &k, &v, BPF_NOEXIST) != 0) {
			fail(e, "socket map", errno);
			goto out;
		}
	}
	if (bst_reuseport_set_active(r, active, e) != 0)
		goto out;
	int pfd = bpf_program__fd(prog);
	if (setsockopt(fds[0], SOL_SOCKET, SO_ATTACH_REUSEPORT_EBPF, &pfd, sizeof pfd) != 0) {
		fail(e, "attach", errno);
		goto out;
	}
	return r;
out:
	bpf_object__close(r->obj);
	free(r);
	return NULL;
}

void bst_reuseport_stats(const bst_reuseport *r, uint64_t out[3])
{
	int ncpu = libbpf_num_possible_cpus();
	for (uint32_t k = 0; k < 3; k++) {
		out[k] = 0;
		if (ncpu <= 0 || ncpu > 4096)
			continue;
		uint64_t *v = calloc((size_t)ncpu, sizeof *v);
		if (v == NULL)
			continue;
		if (bpf_map_lookup_elem(r->stats_fd, &k, v) == 0)
			for (int c = 0; c < ncpu; c++)
				out[k] += v[c];
		free(v);
	}
}

void bst_reuseport_free(bst_reuseport *r)
{
	if (r == NULL)
		return;
	bpf_object__close(r->obj);
	free(r);
}

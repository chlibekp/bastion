/* See block.h. Map keys and values are xdp/xdp_common.h's; expiry is CLOCK_MONOTONIC (master's
 * bst_limit_now_us) in nanoseconds, the base bpf_ktime_get_coarse_ns counts from. */
#include "xdp/block.h"

#include <bpf/bpf.h>
#include <stdlib.h>
#include <string.h>

typedef struct xdp_be {
	bst_block_backend *inner;
	int fd4, fd6;
	bst_cidr *exempt;
	size_t nexempt;
	uint64_t skipped;
} xdp_be;

/* True when a and b agree on their first bits bits. */
static bool same_prefix(const uint8_t *a, const uint8_t *b, unsigned bits)
{
	for (unsigned i = 0; bits > 0; i++) {
		unsigned take = bits >= 8 ? 8 : bits;
		uint8_t m = (uint8_t)(0xff00u >> take);
		if ((a[i] & m) != (b[i] & m))
			return false;
		bits -= take;
	}
	return true;
}

/* The block overlaps an exempt network (covers an exempt address, or lies inside the network). */
static bool exempt(const xdp_be *b, const bst_block_entry *e)
{
	bst_ip ip = bst_ip_canon(&e->ip);
	unsigned ep = e->prefix;
	if (ip.family == BST_IP_V4 && e->ip.family == BST_IP_V6)
		ep = ep > 96 ? ep - 96 : 0;
	for (size_t i = 0; i < b->nexempt; i++) {
		bst_ip cip = bst_ip_canon(&b->exempt[i].ip);
		unsigned cp = b->exempt[i].prefix;
		if (cip.family == BST_IP_V4 && b->exempt[i].ip.family == BST_IP_V6)
			cp = cp > 96 ? cp - 96 : 0;
		if (cip.family == ip.family && same_prefix(cip.b, ip.b, ep < cp ? ep : cp))
			return true;
	}
	return false;
}

/* The map and key of e; false when it does not belong in the maps. */
static bool key_of(const xdp_be *b, const bst_block_entry *e, int *fd, uint8_t key[sizeof(struct bst_xdp_dyn6)])
{
	if (e->flags & BST_BLOCK_L7)
		return false;
	bst_ip ip = bst_ip_canon(&e->ip);
	if (ip.family == BST_IP_V4) {
		memcpy(key, ip.b, 4);
		*fd = b->fd4;
		return true;
	}
	if (e->prefix != 48 && e->prefix != 56 && e->prefix != 64 && e->prefix != 128)
		return false;
	struct bst_xdp_dyn6 k;
	memset(&k, 0, sizeof k);
	k.prefix = e->prefix;
	memcpy(k.addr, ip.b, 16); /* host bits are already zero (sec/block.h) */
	memcpy(key, &k, sizeof k);
	*fd = b->fd6;
	return true;
}

static int x_add(void *ctx, const bst_block_entry *e)
{
	xdp_be *b = ctx;
	int rc = b->inner->add(b->inner->ctx, e);
	int fd;
	uint8_t key[sizeof(struct bst_xdp_dyn6)];
	if (!key_of(b, e, &fd, key))
		return rc;
	if (exempt(b, e)) {
		b->skipped++;
		return rc;
	}
	uint64_t exp = e->expires_us * 1000u;
	if (bpf_map_update_elem(fd, key, &exp, BPF_ANY) != 0)
		b->skipped++; /* still blocked at L7 */
	return rc;
}

static int x_remove(void *ctx, const bst_block_entry *e)
{
	xdp_be *b = ctx;
	int rc = b->inner->remove(b->inner->ctx, e);
	int fd;
	uint8_t key[sizeof(struct bst_xdp_dyn6)];
	if (key_of(b, e, &fd, key))
		(void)bpf_map_delete_elem(fd, key);
	return rc;
}

/* What the maps hold (the XDP-enforced blocks), then the L7-only ones of the inner backend. */
static size_t x_list(void *ctx, bst_block_entry *out, size_t cap)
{
	xdp_be *b = ctx;
	size_t n = 0;
	uint32_t k4, *p4 = NULL;
	while (n < cap && bpf_map_get_next_key(b->fd4, p4, &k4) == 0) {
		uint64_t exp;
		p4 = &k4;
		if (bpf_map_lookup_elem(b->fd4, &k4, &exp) != 0)
			continue;
		memset(&out[n], 0, sizeof out[n]);
		out[n].ip.family = BST_IP_V4;
		memcpy(out[n].ip.b, &k4, 4);
		out[n].prefix = 32;
		out[n++].expires_us = exp / 1000u;
	}
	struct bst_xdp_dyn6 k6, *p6 = NULL;
	while (n < cap && bpf_map_get_next_key(b->fd6, p6, &k6) == 0) {
		uint64_t exp;
		p6 = &k6;
		if (bpf_map_lookup_elem(b->fd6, &k6, &exp) != 0)
			continue;
		memset(&out[n], 0, sizeof out[n]);
		out[n].ip.family = BST_IP_V6;
		memcpy(out[n].ip.b, k6.addr, 16);
		out[n].prefix = k6.prefix;
		out[n++].expires_us = exp / 1000u;
	}
	if (n < cap && b->inner->list != NULL) {
		bst_block_entry *tmp = calloc(cap, sizeof *tmp);
		if (tmp != NULL) {
			size_t m = b->inner->list(b->inner->ctx, tmp, cap);
			for (size_t i = 0; i < m && n < cap; i++)
				if (tmp[i].flags & BST_BLOCK_L7)
					out[n++] = tmp[i];
			free(tmp);
		}
	}
	return n;
}

static void x_commit(void *ctx)
{
	xdp_be *b = ctx;
	if (b->inner->commit != NULL)
		b->inner->commit(b->inner->ctx);
}

int bst_block_backend_xdp(bst_block_backend *out, bst_block_backend *inner, bst_xdp *x, const bst_cidr *ex, size_t nex)
{
	xdp_be *b = calloc(1, sizeof *b);
	if (b == NULL)
		return -1;
	if (nex > 0) {
		b->exempt = malloc(nex * sizeof *b->exempt);
		if (b->exempt == NULL) {
			free(b);
			return -1;
		}
		memcpy(b->exempt, ex, nex * sizeof *ex);
	}
	b->nexempt = nex;
	b->inner = inner;
	b->fd4 = bst_xdp_map_fd(x, "dyn_block4");
	b->fd6 = bst_xdp_map_fd(x, "dyn_block6");
	*out = (bst_block_backend){ .name = "xdp", .ctx = b, .add = x_add, .remove = x_remove, .list = x_list,
				    .commit = x_commit };
	return 0;
}

void bst_block_backend_xdp_free(bst_block_backend *bk)
{
	xdp_be *b = bk->ctx;
	if (b != NULL) {
		free(b->exempt);
		free(b);
	}
	bk->ctx = NULL;
}

uint64_t bst_block_xdp_skipped(const bst_block_backend *bk)
{
	const xdp_be *b = bk->ctx;
	return b != NULL ? b->skipped : 0;
}

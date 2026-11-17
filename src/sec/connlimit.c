/* See connlimit.h. */
#include "sec/connlimit.h"

#include "core/hash.h"

#include <stdatomic.h>
#include <stdlib.h>
#include <string.h>
#include <sys/random.h>
#include <sys/stat.h>

typedef struct row {
	_Atomic uint32_t b[BST_CONNLIMIT_BUCKETS];
} row;

static row *g_rows;
static int g_nworkers, g_slot = -1;
static uint8_t g_key[2][16];

/* What one fd holds: the buckets it bumped, and which socket it was. */
typedef struct held {
	bool on;
	dev_t dev;
	ino_t ino;
	uint32_t b[4]; /* two per key, two keys */
	unsigned nb;
} held;

static held *g_held;
static size_t g_nheld;

size_t bst_connlimit_bytes(int nworkers)
{
	return (size_t)(nworkers > 0 ? nworkers : 1) * sizeof(row);
}

int bst_connlimit_attach(void *mem, int nworkers)
{
	g_rows = mem;
	g_nworkers = nworkers;
	return getrandom(g_key, sizeof g_key, 0) == (ssize_t)sizeof g_key ? 0 : -1;
}

void bst_connlimit_worker(int slot)
{
	if (g_rows == NULL || slot < 0 || slot >= g_nworkers)
		return;
	g_slot = slot;
	for (uint32_t i = 0; i < BST_CONNLIMIT_BUCKETS; i++)
		atomic_store_explicit(&g_rows[slot].b[i], 0, memory_order_relaxed);
}

/* The key of ip cut to len bits (128 or 32: the address itself), tagged by kind. */
static void key_of(const bst_ip *ip, unsigned len, uint8_t kind, uint32_t out[2])
{
	bst_ip c = bst_ip_canon(ip);
	uint8_t buf[18];
	memset(buf, 0, sizeof buf);
	buf[0] = kind;
	buf[1] = c.family;
	unsigned n = c.family == BST_IP_V4 ? 4 : 16;
	for (unsigned i = 0; i < n; i++) {
		unsigned bits = len > i * 8 ? len - i * 8 : 0;
		uint8_t m = bits >= 8 ? 0xff : (uint8_t)(0xff00u >> bits);
		buf[2 + i] = c.b[i] & m;
	}
	for (int h = 0; h < 2; h++)
		out[h] = (uint32_t)bst_siphash13(g_key[h], buf, sizeof buf) % BST_CONNLIMIT_BUCKETS;
}

static unsigned total(uint32_t b)
{
	unsigned t = 0;
	for (int w = 0; w < g_nworkers; w++)
		t += atomic_load_explicit(&g_rows[w].b[b], memory_order_relaxed);
	return t;
}

static unsigned estimate(const uint32_t k[2])
{
	unsigned a = total(k[0]), b = total(k[1]);
	return a < b ? a : b;
}

static void bump(uint32_t b, int d)
{
	if (d > 0)
		atomic_fetch_add_explicit(&g_rows[g_slot].b[b], 1, memory_order_relaxed);
	else if (atomic_load_explicit(&g_rows[g_slot].b[b], memory_order_relaxed) > 0)
		atomic_fetch_sub_explicit(&g_rows[g_slot].b[b], 1, memory_order_relaxed);
}

void bst_connlimit_release(int fd)
{
	if (fd < 0 || (size_t)fd >= g_nheld || !g_held[fd].on)
		return;
	held *h = &g_held[fd];
	for (unsigned i = 0; i < h->nb; i++)
		bump(h->b[i], -1);
	h->on = false;
}

bool bst_connlimit_acquire(const bst_connlimit_cfg *c, const bst_ip *ip, int fd)
{
	if (g_rows == NULL || g_slot < 0 || c == NULL || !c->set || fd < 0)
		return true;
	bst_connlimit_release(fd); /* the number came back: whoever held it is closed */
	uint32_t kip[2], ksub[2];
	bst_ip cip = bst_ip_canon(ip);
	bool v4 = cip.family == BST_IP_V4;
	key_of(&cip, v4 ? 32 : 128, 1, kip);
	unsigned sublim = v4 ? c->subnet4 : c->subnet6;
	key_of(&cip, v4 ? c->subnet4_len : c->subnet6_len, 2, ksub);
	if (c->per_ip > 0 && estimate(kip) >= c->per_ip)
		return false;
	if (sublim > 0 && estimate(ksub) >= sublim)
		return false;
	if ((size_t)fd >= g_nheld) {
		size_t n = g_nheld ? g_nheld : 1024;
		while (n <= (size_t)fd)
			n *= 2;
		held *nh = realloc(g_held, n * sizeof *nh);
		if (nh == NULL)
			return true; /* not tracked, so not counted: never refuse for our own memory */
		memset(nh + g_nheld, 0, (n - g_nheld) * sizeof *nh);
		g_held = nh;
		g_nheld = n;
	}
	struct stat st;
	if (fstat(fd, &st) != 0)
		return true;
	held *h = &g_held[fd];
	*h = (held){ .on = true, .dev = st.st_dev, .ino = st.st_ino,
		     .b = { kip[0], kip[1], ksub[0], ksub[1] }, .nb = 4 };
	for (unsigned i = 0; i < 4; i++)
		bump(h->b[i], 1);
	return true;
}

void bst_connlimit_sweep(void)
{
	for (size_t fd = 0; fd < g_nheld; fd++) {
		if (!g_held[fd].on)
			continue;
		struct stat st;
		if (fstat((int)fd, &st) != 0 || st.st_ino != g_held[fd].ino || st.st_dev != g_held[fd].dev)
			bst_connlimit_release((int)fd);
	}
}

unsigned bst_connlimit_count(const bst_ip *ip)
{
	if (g_rows == NULL)
		return 0;
	uint32_t k[2];
	bst_ip c = bst_ip_canon(ip);
	key_of(&c, c.family == BST_IP_V4 ? 32 : 128, 1, k);
	return estimate(k);
}

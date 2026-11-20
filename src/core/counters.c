#include "core/counters.h"

#include <string.h>

enum { KIND_FREE = 0, KIND_COUNTER = 1, KIND_HIST = 2, KIND_GAUGE = 3 };

#define REG_MAGIC 0x62737452u /* "bstR" */
#define VAL_MAGIC 0x62737456u /* "bstV" */
#define TABLE_VERSION 2u      /* 1: registry and values in one worker-writable region */

struct bst_counter_entry {
	uint32_t kind;
	uint32_t hist; /* index into a slot's hists, histograms only */
	char name[BST_COUNTER_NAME_MAX];
	char help[BST_COUNTER_HELP_MAX];
	char labels[BST_COUNTER_LABELS_MAX];
};

/* What the counters are: names, kinds, histogram indices. Only master writes it (registration
 * happens in master before any fork); children map it read-only (core/shm.h), so nothing a
 * worker can write decides an index master or the helper uses. Position independent. */
struct bst_counter_registry {
	uint32_t magic, version;
	uint32_t count; /* entries in use; stored with release, read with acquire */
	uint32_t hist_count;
	struct bst_counter_entry entries[BST_COUNTER_MAX];
};

/* One process's values: a counter value or histogram observation count, a histogram sum, the
 * buckets. Aligned so two processes never share a cache line. */
struct bst_counter_slot {
	_Alignas(64) uint64_t value[BST_COUNTER_MAX];
	uint64_t sum[BST_COUNTER_MAX];
	uint64_t hists[BST_HIST_MAX][BST_HIST_BUCKETS];
};

/* The values: fixed offsets every process adds into. Nothing in here is ever used as a size,
 * an index or a string; a worker scribbling on it can only make the numbers wrong. */
struct bst_counter_values {
	_Alignas(64) uint32_t magic, version;
	struct bst_counter_slot slots[BST_COUNTER_SLOTS];
};

static struct bst_counter_registry local_reg;
static struct bst_counter_values local_vals;
static const struct bst_counter_registry *reg = &local_reg; /* what lookups read */
static struct bst_counter_registry *reg_rw = &local_reg;    /* NULL in a child */
static struct bst_counter_values *vals = &local_vals;
static unsigned my_slot = BST_COUNTER_SLOT_MASTER;

/* Ids handed out before the table moved to shared memory are local indices, mapped through
 * remap; ids handed out after carry SHARED_BIT. */
#define SHARED_BIT 0x40000000u
static uint32_t remap[BST_COUNTER_MAX];
static uint32_t nremap;
static bool shared;

static uint32_t reg_count(const struct bst_counter_registry *r)
{
	uint32_t n = __atomic_load_n(&r->count, __ATOMIC_ACQUIRE);
	return n < BST_COUNTER_MAX ? n : BST_COUNTER_MAX;
}

/* Index into reg->entries, or UINT32_MAX. */
static uint32_t resolve(bst_counter_id id)
{
	if (id == BST_COUNTER_INVALID)
		return UINT32_MAX;
	if (id & SHARED_BIT)
		return id & ~SHARED_BIT;
	if (!shared)
		return id;
	return id < nremap ? remap[id] : UINT32_MAX;
}

static bst_counter_id id_of(uint32_t idx)
{
	return shared ? (idx | SHARED_BIT) : idx;
}

/* Finds or adds an entry in r. UINT32_MAX when full, invalid, or of another kind. */
static uint32_t find_or_add(struct bst_counter_registry *r, uint32_t kind, const char *name,
			    const char *help, const char *labels)
{
	uint32_t n = reg_count(r);
	for (uint32_t i = 0; i < n; i++) {
		const struct bst_counter_entry *e = &r->entries[i];
		if (strcmp(e->name, name) == 0 && strcmp(e->labels, labels) == 0)
			return e->kind == kind ? i : UINT32_MAX;
	}
	if (n >= BST_COUNTER_MAX)
		return UINT32_MAX;
	uint32_t hist = 0;
	if (kind == KIND_HIST) {
		if (r->hist_count >= BST_HIST_MAX)
			return UINT32_MAX;
		hist = r->hist_count++;
	}
	struct bst_counter_entry *e = &r->entries[n];
	memset(e, 0, sizeof *e);
	e->kind = kind;
	e->hist = hist;
	strcpy(e->name, name);
	strcpy(e->help, help);
	strcpy(e->labels, labels);
	__atomic_store_n(&r->count, n + 1, __ATOMIC_RELEASE);
	return n;
}

static bst_counter_id register_kind(uint32_t kind, const char *name, const char *help,
				    const char *labels)
{
	if (name == NULL || name[0] == '\0')
		return BST_COUNTER_INVALID;
	if (help == NULL)
		help = "";
	if (labels == NULL)
		labels = "";
	if (strlen(name) >= BST_COUNTER_NAME_MAX || strlen(help) >= BST_COUNTER_HELP_MAX ||
	    strlen(labels) >= BST_COUNTER_LABELS_MAX)
		return BST_COUNTER_INVALID;
	if (reg_rw == NULL) { /* a child finds what master registered, and adds nothing */
		uint32_t n = reg_count(reg);
		for (uint32_t i = 0; i < n; i++) {
			const struct bst_counter_entry *e = &reg->entries[i];
			if (strncmp(e->name, name, sizeof e->name) == 0 &&
			    strncmp(e->labels, labels, sizeof e->labels) == 0)
				return e->kind == kind ? id_of(i) : BST_COUNTER_INVALID;
		}
		return BST_COUNTER_INVALID;
	}
	uint32_t idx = find_or_add(reg_rw, kind, name, help, labels);
	return idx == UINT32_MAX ? BST_COUNTER_INVALID : id_of(idx);
}

bst_counter_id bst_counter_register(const char *name, const char *help, const char *labels)
{
	return register_kind(KIND_COUNTER, name, help, labels);
}

bst_counter_id bst_histogram_register(const char *name, const char *help, const char *labels)
{
	return register_kind(KIND_HIST, name, help, labels);
}

bst_counter_id bst_gauge_register(const char *name, const char *help, const char *labels)
{
	return register_kind(KIND_GAUGE, name, help, labels);
}

static const struct bst_counter_entry *lookup(bst_counter_id id, uint32_t kind, uint32_t *idx)
{
	uint32_t i = resolve(id);
	if (i >= BST_COUNTER_MAX || i >= reg_count(reg) || reg->entries[i].kind != kind)
		return NULL;
	if (kind == KIND_HIST && reg->entries[i].hist >= BST_HIST_MAX)
		return NULL;
	*idx = i;
	return &reg->entries[i];
}

void bst_counter_add(bst_counter_id id, uint64_t n)
{
	uint32_t i;
	if (lookup(id, KIND_COUNTER, &i) != NULL)
		__atomic_fetch_add(&vals->slots[my_slot].value[i], n, __ATOMIC_RELAXED);
}

void bst_gauge_set(bst_counter_id id, int64_t v)
{
	uint32_t i;
	if (lookup(id, KIND_GAUGE, &i) != NULL)
		__atomic_store_n(&vals->slots[my_slot].value[i], (uint64_t)v, __ATOMIC_RELAXED);
}

unsigned bst_histogram_bucket_index(uint64_t value)
{
	if (value < BST_HIST_SUB)
		return (unsigned)value;
	unsigned e = 63u - (unsigned)__builtin_clzll(value); /* e >= BST_HIST_SUB_BITS */
	unsigned sub = (unsigned)(value >> (e - BST_HIST_SUB_BITS)) & (BST_HIST_SUB - 1u);
	return (e - BST_HIST_SUB_BITS + 1u) * BST_HIST_SUB + sub;
}

uint64_t bst_histogram_bucket_upper(unsigned bucket)
{
	if (bucket >= BST_HIST_BUCKETS - 1u)
		return UINT64_MAX;
	if (bucket < BST_HIST_SUB)
		return bucket;
	unsigned e = bucket / BST_HIST_SUB + BST_HIST_SUB_BITS - 1u;
	uint64_t sub = bucket % BST_HIST_SUB;
	unsigned shift = e - BST_HIST_SUB_BITS;
	return ((((uint64_t)BST_HIST_SUB + sub + 1u) << shift) - 1u);
}

void bst_histogram_observe(bst_counter_id id, uint64_t value)
{
	uint32_t i;
	const struct bst_counter_entry *e = lookup(id, KIND_HIST, &i);
	if (e == NULL)
		return;
	struct bst_counter_slot *s = &vals->slots[my_slot];
	__atomic_fetch_add(&s->hists[e->hist][bst_histogram_bucket_index(value)], 1, __ATOMIC_RELAXED);
	__atomic_fetch_add(&s->value[i], 1, __ATOMIC_RELAXED);
	__atomic_fetch_add(&s->sum[i], value, __ATOMIC_RELAXED);
}

static uint64_t sum_value(uint32_t i)
{
	uint64_t v = 0;
	for (unsigned s = 0; s < BST_COUNTER_SLOTS; s++)
		v += __atomic_load_n(&vals->slots[s].value[i], __ATOMIC_RELAXED);
	return v;
}

uint64_t bst_counter_get(bst_counter_id id)
{
	uint32_t i;
	return lookup(id, KIND_COUNTER, &i) ? sum_value(i) : 0;
}

int64_t bst_gauge_get(bst_counter_id id)
{
	uint32_t i;
	return lookup(id, KIND_GAUGE, &i) ? (int64_t)sum_value(i) : 0;
}

uint64_t bst_histogram_count(bst_counter_id id)
{
	uint32_t i;
	return lookup(id, KIND_HIST, &i) ? sum_value(i) : 0;
}

uint64_t bst_histogram_sum(bst_counter_id id)
{
	uint32_t i;
	if (lookup(id, KIND_HIST, &i) == NULL)
		return 0;
	uint64_t v = 0;
	for (unsigned s = 0; s < BST_COUNTER_SLOTS; s++)
		v += __atomic_load_n(&vals->slots[s].sum[i], __ATOMIC_RELAXED);
	return v;
}

uint64_t bst_histogram_bucket(bst_counter_id id, unsigned bucket)
{
	uint32_t i;
	const struct bst_counter_entry *e = lookup(id, KIND_HIST, &i);
	if (e == NULL || bucket >= BST_HIST_BUCKETS)
		return 0;
	uint64_t v = 0;
	for (unsigned s = 0; s < BST_COUNTER_SLOTS; s++)
		v += __atomic_load_n(&vals->slots[s].hists[e->hist][bucket], __ATOMIC_RELAXED);
	return v;
}

size_t bst_counter_count(void)
{
	return reg_count(reg);
}

bst_counter_id bst_counter_nth(size_t i)
{
	return i < bst_counter_count() ? id_of((uint32_t)i) : BST_COUNTER_INVALID;
}

bool bst_counter_info_get(bst_counter_id id, bst_counter_info *out)
{
	uint32_t i = resolve(id);
	if (i >= BST_COUNTER_MAX || i >= reg_count(reg))
		return false;
	const struct bst_counter_entry *e = &reg->entries[i];
	out->kind = e->kind == KIND_HIST ? BST_METRIC_HISTOGRAM
		    : e->kind == KIND_GAUGE ? BST_METRIC_GAUGE : BST_METRIC_COUNTER;
	out->name = e->name;
	out->help = e->help;
	out->labels = e->labels;
	return true;
}

/* ---- shared table ---- */

size_t bst_counters_registry_size(void)
{
	return sizeof(struct bst_counter_registry);
}

size_t bst_counters_values_size(void)
{
	return sizeof(struct bst_counter_values);
}

static bool terminated(const char *s, size_t cap)
{
	return memchr(s, '\0', cap) != NULL;
}

/* A kept registry is only ever written by a master, but it is checked as input anyway: every
 * count, kind and histogram index in range, every string terminated. */
static bool registry_ok(const struct bst_counter_registry *r, const struct bst_counter_values *v)
{
	if (r->magic != REG_MAGIC || r->version != TABLE_VERSION || v->magic != VAL_MAGIC ||
	    v->version != TABLE_VERSION || r->count > BST_COUNTER_MAX || r->hist_count > BST_HIST_MAX)
		return false;
	for (uint32_t i = 0; i < r->count; i++) {
		const struct bst_counter_entry *e = &r->entries[i];
		if (e->kind < KIND_COUNTER || e->kind > KIND_GAUGE)
			return false;
		if (e->kind == KIND_HIST && e->hist >= r->hist_count)
			return false;
		if (!terminated(e->name, sizeof e->name) || e->name[0] == '\0' ||
		    !terminated(e->help, sizeof e->help) || !terminated(e->labels, sizeof e->labels))
			return false;
	}
	return true;
}

int bst_counters_attach_shared(void *reg_mem, void *val_mem, bool reused)
{
	struct bst_counter_registry *t = reg_mem;
	struct bst_counter_values *tv = val_mem;
	const struct bst_counter_registry *l = reg_rw;
	const struct bst_counter_values *lv = vals;
	if (t == NULL || tv == NULL || l == NULL)
		return -1;
	int rc = 0;
	if (reused && !registry_ok(t, tv)) {
		rc = -1; /* another layout, or not ours: start over */
		reused = false;
	}
	if (!reused && (t != l || rc != 0)) {
		memset(t, 0, sizeof *t);
		memset(tv, 0, sizeof *tv);
		t->version = TABLE_VERSION;
		t->magic = REG_MAGIC;
		tv->version = TABLE_VERSION;
		tv->magic = VAL_MAGIC;
	}
	/* Fold what this process registered so far in by name, values added. Not when it is
	 * already this table (attached twice: nothing to move). */
	uint32_t ln = reg_count(l);
	if (t != l)
		nremap = 0;
	for (uint32_t i = 0; t != l && i < ln; i++) {
		const struct bst_counter_entry *e = &l->entries[i];
		uint32_t j = find_or_add(t, e->kind, e->name, e->help, e->labels);
		remap[nremap++] = j;
		if (j == UINT32_MAX)
			continue;
		for (unsigned s = 0; s < BST_COUNTER_SLOTS; s++) {
			const struct bst_counter_slot *ls = &lv->slots[s];
			struct bst_counter_slot *ts = &tv->slots[s];
			if (e->kind == KIND_GAUGE) {
				__atomic_store_n(&ts->value[j], ls->value[i], __ATOMIC_RELAXED);
				continue;
			}
			__atomic_fetch_add(&ts->value[j], ls->value[i], __ATOMIC_RELAXED);
			__atomic_fetch_add(&ts->sum[j], ls->sum[i], __ATOMIC_RELAXED);
			uint32_t th = t->entries[j].hist, lh = e->hist;
			if (e->kind == KIND_HIST && th < BST_HIST_MAX && lh < BST_HIST_MAX)
				for (unsigned b = 0; b < BST_HIST_BUCKETS; b++)
					__atomic_fetch_add(&ts->hists[th][b], ls->hists[lh][b], __ATOMIC_RELAXED);
		}
	}
	reg = t;
	reg_rw = t;
	vals = tv;
	shared = true;
	return rc;
}

void bst_counters_set_view(const void *reg_ro)
{
	if (reg_ro != NULL)
		reg = reg_ro;
}

void bst_counters_child(void)
{
	reg_rw = NULL;
}

void bst_counters_use_slot(unsigned slot)
{
	if (slot < BST_COUNTER_SLOTS)
		my_slot = slot;
}

#ifdef BST_TEST
void bst_counters_reset_for_test(void)
{
	if (reg_rw != NULL)
		memset(reg_rw, 0, sizeof *reg_rw);
	memset(vals, 0, sizeof *vals);
	if (reg_rw != NULL && shared) {
		reg_rw->magic = REG_MAGIC;
		reg_rw->version = TABLE_VERSION;
		vals->magic = VAL_MAGIC;
		vals->version = TABLE_VERSION;
	}
	nremap = 0;
}
#endif

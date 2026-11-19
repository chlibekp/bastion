#include "core/counters.h"

#include <string.h>

enum { KIND_FREE = 0, KIND_COUNTER = 1, KIND_HIST = 2, KIND_GAUGE = 3 };

#define TABLE_MAGIC 0x62737443u /* "bstC" */
#define TABLE_VERSION 1u

struct bst_counter_entry {
	uint32_t kind;
	uint32_t hist; /* index into a slot's hists, histograms only */
	char name[BST_COUNTER_NAME_MAX];
	char help[BST_COUNTER_HELP_MAX];
	char labels[BST_COUNTER_LABELS_MAX];
};

/* One process's values: a counter value or histogram observation count, a histogram sum, the
 * buckets. Aligned so two processes never share a cache line. */
struct bst_counter_slot {
	_Alignas(64) uint64_t value[BST_COUNTER_MAX];
	uint64_t sum[BST_COUNTER_MAX];
	uint64_t hists[BST_HIST_MAX][BST_HIST_BUCKETS];
};

/* Position independent: fixed-size arrays, indices instead of pointers. */
struct bst_counter_table {
	uint32_t magic, version;
	uint32_t lock;	/* registration only */
	uint32_t count; /* entries in use; written under lock, read with an acquire load */
	uint32_t hist_count;
	struct bst_counter_entry entries[BST_COUNTER_MAX];
	struct bst_counter_slot slots[BST_COUNTER_SLOTS];
};

static struct bst_counter_table local_table;
static struct bst_counter_table *table = &local_table;
static unsigned my_slot = BST_COUNTER_SLOT_MASTER;

/* Ids handed out before the table moved to shared memory are local indices, mapped through
 * remap; ids handed out after carry SHARED_BIT. */
#define SHARED_BIT 0x40000000u
static uint32_t remap[BST_COUNTER_MAX];
static uint32_t nremap;
static bool shared;

static void lock(struct bst_counter_table *t)
{
	while (__atomic_exchange_n(&t->lock, 1u, __ATOMIC_ACQUIRE) != 0)
		;
}

static void unlock(struct bst_counter_table *t)
{
	__atomic_store_n(&t->lock, 0u, __ATOMIC_RELEASE);
}

/* Index into table->entries, or UINT32_MAX. */
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

/* Finds or adds an entry in t. UINT32_MAX when full, invalid, or of another kind. */
static uint32_t find_or_add(struct bst_counter_table *t, uint32_t kind, const char *name,
			    const char *help, const char *labels)
{
	uint32_t n = t->count;
	for (uint32_t i = 0; i < n; i++) {
		struct bst_counter_entry *e = &t->entries[i];
		if (strcmp(e->name, name) == 0 && strcmp(e->labels, labels) == 0)
			return e->kind == kind ? i : UINT32_MAX;
	}
	if (n >= BST_COUNTER_MAX)
		return UINT32_MAX;
	uint32_t hist = 0;
	if (kind == KIND_HIST) {
		if (t->hist_count >= BST_HIST_MAX)
			return UINT32_MAX;
		hist = t->hist_count++;
	}
	struct bst_counter_entry *e = &t->entries[n];
	memset(e, 0, sizeof *e);
	e->kind = kind;
	e->hist = hist;
	strcpy(e->name, name);
	strcpy(e->help, help);
	strcpy(e->labels, labels);
	__atomic_store_n(&t->count, n + 1, __ATOMIC_RELEASE);
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
	struct bst_counter_table *t = table;
	lock(t);
	uint32_t idx = find_or_add(t, kind, name, help, labels);
	unlock(t);
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

static struct bst_counter_entry *lookup(bst_counter_id id, uint32_t kind, uint32_t *idx)
{
	struct bst_counter_table *t = table;
	uint32_t i = resolve(id);
	if (i >= BST_COUNTER_MAX || i >= __atomic_load_n(&t->count, __ATOMIC_ACQUIRE) ||
	    t->entries[i].kind != kind)
		return NULL;
	*idx = i;
	return &t->entries[i];
}

void bst_counter_add(bst_counter_id id, uint64_t n)
{
	uint32_t i;
	if (lookup(id, KIND_COUNTER, &i) != NULL)
		__atomic_fetch_add(&table->slots[my_slot].value[i], n, __ATOMIC_RELAXED);
}

void bst_gauge_set(bst_counter_id id, int64_t v)
{
	uint32_t i;
	if (lookup(id, KIND_GAUGE, &i) != NULL)
		__atomic_store_n(&table->slots[my_slot].value[i], (uint64_t)v, __ATOMIC_RELAXED);
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
	struct bst_counter_entry *e = lookup(id, KIND_HIST, &i);
	if (e == NULL)
		return;
	struct bst_counter_slot *s = &table->slots[my_slot];
	__atomic_fetch_add(&s->hists[e->hist][bst_histogram_bucket_index(value)], 1, __ATOMIC_RELAXED);
	__atomic_fetch_add(&s->value[i], 1, __ATOMIC_RELAXED);
	__atomic_fetch_add(&s->sum[i], value, __ATOMIC_RELAXED);
}

static uint64_t sum_value(uint32_t i)
{
	uint64_t v = 0;
	for (unsigned s = 0; s < BST_COUNTER_SLOTS; s++)
		v += __atomic_load_n(&table->slots[s].value[i], __ATOMIC_RELAXED);
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
		v += __atomic_load_n(&table->slots[s].sum[i], __ATOMIC_RELAXED);
	return v;
}

uint64_t bst_histogram_bucket(bst_counter_id id, unsigned bucket)
{
	uint32_t i;
	struct bst_counter_entry *e = lookup(id, KIND_HIST, &i);
	if (e == NULL || bucket >= BST_HIST_BUCKETS)
		return 0;
	uint64_t v = 0;
	for (unsigned s = 0; s < BST_COUNTER_SLOTS; s++)
		v += __atomic_load_n(&table->slots[s].hists[e->hist][bucket], __ATOMIC_RELAXED);
	return v;
}

size_t bst_counter_count(void)
{
	return __atomic_load_n(&table->count, __ATOMIC_ACQUIRE);
}

bst_counter_id bst_counter_nth(size_t i)
{
	return i < bst_counter_count() ? id_of((uint32_t)i) : BST_COUNTER_INVALID;
}

bool bst_counter_info_get(bst_counter_id id, bst_counter_info *out)
{
	struct bst_counter_table *t = table;
	uint32_t i = resolve(id);
	if (i >= BST_COUNTER_MAX || i >= __atomic_load_n(&t->count, __ATOMIC_ACQUIRE))
		return false;
	const struct bst_counter_entry *e = &t->entries[i];
	out->kind = e->kind == KIND_HIST ? BST_METRIC_HISTOGRAM
		    : e->kind == KIND_GAUGE ? BST_METRIC_GAUGE : BST_METRIC_COUNTER;
	out->name = e->name;
	out->help = e->help;
	out->labels = e->labels;
	return true;
}

/* ---- shared table ---- */

size_t bst_counters_region_size(void)
{
	return sizeof(struct bst_counter_table);
}

int bst_counters_attach_shared(void *mem, bool reused)
{
	struct bst_counter_table *t = mem, *l = table;
	int rc = 0;
	if (reused && (t->magic != TABLE_MAGIC || t->version != TABLE_VERSION)) {
		memset(t, 0, sizeof *t); /* another layout: start over */
		rc = -1;
		reused = false;
	}
	if (!reused) {
		t->version = TABLE_VERSION;
		__atomic_store_n(&t->magic, TABLE_MAGIC, __ATOMIC_RELEASE);
	}
	/* Fold what this process registered so far in by name, values (master's slot) added. Not
	 * when it is already this table (attached twice: nothing to move). */
	lock(t);
	if (t != l)
		nremap = 0;
	for (uint32_t i = 0; t != l && i < l->count; i++) {
		const struct bst_counter_entry *e = &l->entries[i];
		uint32_t j = find_or_add(t, e->kind, e->name, e->help, e->labels);
		remap[nremap++] = j;
		if (j == UINT32_MAX)
			continue;
		for (unsigned s = 0; s < BST_COUNTER_SLOTS; s++) {
			const struct bst_counter_slot *ls = &l->slots[s];
			struct bst_counter_slot *ts = &t->slots[s];
			if (e->kind == KIND_GAUGE) {
				__atomic_store_n(&ts->value[j], ls->value[i], __ATOMIC_RELAXED);
				continue;
			}
			__atomic_fetch_add(&ts->value[j], ls->value[i], __ATOMIC_RELAXED);
			__atomic_fetch_add(&ts->sum[j], ls->sum[i], __ATOMIC_RELAXED);
			if (e->kind == KIND_HIST)
				for (unsigned b = 0; b < BST_HIST_BUCKETS; b++)
					__atomic_fetch_add(&ts->hists[t->entries[j].hist][b], ls->hists[e->hist][b],
							   __ATOMIC_RELAXED);
		}
	}
	unlock(t);
	table = t;
	shared = true;
	return rc;
}

void bst_counters_use_slot(unsigned slot)
{
	if (slot < BST_COUNTER_SLOTS)
		my_slot = slot;
}

#ifdef BST_TEST
void bst_counters_reset_for_test(void)
{
	memset(table, 0, sizeof *table);
	nremap = 0;
}
#endif

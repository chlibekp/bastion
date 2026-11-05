#include "core/counters.h"

#include <string.h>

enum { KIND_FREE = 0, KIND_COUNTER = 1, KIND_HIST = 2 };

struct bst_counter_entry {
	uint64_t value; /* counter value, or histogram observation count */
	uint64_t sum;   /* histograms only */
	uint32_t kind;
	uint32_t hist;  /* index into hists, histograms only */
	char name[BST_COUNTER_NAME_MAX];
	char help[BST_COUNTER_HELP_MAX];
	char labels[BST_COUNTER_LABELS_MAX];
};

/* Position independent: fixed-size arrays, indices instead of pointers. */
struct bst_counter_table {
	uint32_t count;
	uint32_t hist_count;
	struct bst_counter_entry entries[BST_COUNTER_MAX];
	uint64_t hists[BST_HIST_MAX][BST_HIST_BUCKETS];
};

static struct bst_counter_table local_table;
/* Phase 14: point this at the shared mapping instead. Nothing else changes. */
static struct bst_counter_table *table = &local_table;

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
	for (uint32_t i = 0; i < t->count; i++) {
		struct bst_counter_entry *e = &t->entries[i];
		if (strcmp(e->name, name) == 0 && strcmp(e->labels, labels) == 0)
			return e->kind == kind ? i : BST_COUNTER_INVALID;
	}
	if (t->count >= BST_COUNTER_MAX)
		return BST_COUNTER_INVALID;
	uint32_t hist = 0;
	if (kind == KIND_HIST) {
		if (t->hist_count >= BST_HIST_MAX)
			return BST_COUNTER_INVALID;
		hist = t->hist_count++;
	}
	struct bst_counter_entry *e = &t->entries[t->count];
	memset(e, 0, sizeof *e);
	e->kind = kind;
	e->hist = hist;
	strcpy(e->name, name);
	strcpy(e->help, help);
	strcpy(e->labels, labels);
	return t->count++;
}

bst_counter_id bst_counter_register(const char *name, const char *help, const char *labels)
{
	return register_kind(KIND_COUNTER, name, help, labels);
}

bst_counter_id bst_histogram_register(const char *name, const char *help, const char *labels)
{
	return register_kind(KIND_HIST, name, help, labels);
}

static struct bst_counter_entry *lookup(bst_counter_id id, uint32_t kind)
{
	struct bst_counter_table *t = table;
	if (id >= BST_COUNTER_MAX || id >= t->count || t->entries[id].kind != kind)
		return NULL;
	return &t->entries[id];
}

void bst_counter_add(bst_counter_id id, uint64_t n)
{
	struct bst_counter_entry *e = lookup(id, KIND_COUNTER);
	if (e != NULL)
		__atomic_fetch_add(&e->value, n, __ATOMIC_RELAXED);
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
	struct bst_counter_entry *e = lookup(id, KIND_HIST);
	if (e == NULL)
		return;
	__atomic_fetch_add(&table->hists[e->hist][bst_histogram_bucket_index(value)], 1,
			   __ATOMIC_RELAXED);
	__atomic_fetch_add(&e->value, 1, __ATOMIC_RELAXED);
	__atomic_fetch_add(&e->sum, value, __ATOMIC_RELAXED);
}

uint64_t bst_counter_get(bst_counter_id id)
{
	struct bst_counter_entry *e = lookup(id, KIND_COUNTER);
	return e ? __atomic_load_n(&e->value, __ATOMIC_RELAXED) : 0;
}

uint64_t bst_histogram_count(bst_counter_id id)
{
	struct bst_counter_entry *e = lookup(id, KIND_HIST);
	return e ? __atomic_load_n(&e->value, __ATOMIC_RELAXED) : 0;
}

uint64_t bst_histogram_sum(bst_counter_id id)
{
	struct bst_counter_entry *e = lookup(id, KIND_HIST);
	return e ? __atomic_load_n(&e->sum, __ATOMIC_RELAXED) : 0;
}

uint64_t bst_histogram_bucket(bst_counter_id id, unsigned bucket)
{
	struct bst_counter_entry *e = lookup(id, KIND_HIST);
	if (e == NULL || bucket >= BST_HIST_BUCKETS)
		return 0;
	return __atomic_load_n(&table->hists[e->hist][bucket], __ATOMIC_RELAXED);
}

size_t bst_counter_count(void)
{
	return table->count;
}

#ifdef BST_TEST
void bst_counters_reset_for_test(void)
{
	memset(table, 0, sizeof *table);
}
#endif

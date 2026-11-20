/* Process counters, gauges and histograms.
 *
 * Threading model: registration is done by master (and the single-process paths: tests,
 * `-t`) at startup, before workers fork; a child cannot register. There is no process-shared
 * lock: a live upgrade's new image registers after the old master has handed over. Updates use
 * relaxed atomic adds, so bst_counter_add and
 * bst_histogram_observe are async-signal-safe, allocation-free and cheap. Readers in another
 * process see untorn 64-bit values but no cross-counter consistency. Sums and counts wrap
 * modulo 2^64.
 *
 * Values live in per-process slots (Phase 14): one cache-line-aligned slot for master, one for
 * the helper, and one per worker slot (modulo BST_COUNTER_WORKER_SLOTS). A process only adds
 * into its own slot; readers sum every slot. A respawned worker reuses its slot and two
 * processes sharing one (a reload's draining generation, a slot wrap) stay correct because
 * every update is an atomic add, so a total never goes down when a process dies.
 *
 * bst_counters_attach_shared moves the table into two shared regions kept across reload and
 * live upgrade (core/shm.h), so totals survive both: the registry, which only master writes
 * and children see read-only, and the values, fixed-offset slots nothing ever takes an index,
 * a size or a string from. Until then (and in tests) the table is process-local. Callers only
 * ever hold ids. */
#ifndef BST_CORE_COUNTERS_H
#define BST_CORE_COUNTERS_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef uint32_t bst_counter_id;

/* Returned when the table is full or the arguments are invalid. Every operation
 * accepts it and does nothing. */
#define BST_COUNTER_INVALID UINT32_MAX

#define BST_COUNTER_MAX 1024    /* counters, gauges and histograms combined */
#define BST_COUNTER_WORKER_SLOTS 64
/* Slot 0 master, 1 the helper, 2.. workers. */
#define BST_COUNTER_SLOTS (2 + BST_COUNTER_WORKER_SLOTS)
#define BST_COUNTER_SLOT_MASTER 0
#define BST_COUNTER_SLOT_HELPER 1
#define BST_HIST_MAX 32         /* histograms among them */
#define BST_COUNTER_NAME_MAX 64 /* bytes including NUL; longer names are rejected */
#define BST_COUNTER_HELP_MAX 128
#define BST_COUNTER_LABELS_MAX 128

/* Log-linear histogram. Values 0..3 each get a bucket; above that every power of two
 * [2^e, 2^(e+1)) is split into BST_HIST_SUB equal buckets. Bucket count covers all
 * of uint64_t, so no value overflows. */
#define BST_HIST_SUB_BITS 2
#define BST_HIST_SUB (1u << BST_HIST_SUB_BITS)
#define BST_HIST_BUCKETS (((64u - BST_HIST_SUB_BITS) + 1u) * BST_HIST_SUB) /* 252 */

/* Register (or find) a counter. labels is comma-separated k=v text or NULL. The same
 * name and labels return the same id. Returns BST_COUNTER_INVALID when the table is
 * full, a string is too long, or the name already exists as a histogram. */
bst_counter_id bst_counter_register(const char *name, const char *help, const char *labels);
bst_counter_id bst_histogram_register(const char *name, const char *help, const char *labels);
/* A gauge: each process sets its own slot's value, readers get the sum over slots. */
bst_counter_id bst_gauge_register(const char *name, const char *help, const char *labels);

void bst_counter_add(bst_counter_id id, uint64_t n);
void bst_histogram_observe(bst_counter_id id, uint64_t value);
void bst_gauge_set(bst_counter_id id, int64_t v);
int64_t bst_gauge_get(bst_counter_id id);

/* ---- shared table (Phase 14) ---- */

/* Bytes of the two shared regions: the registry (names, kinds, histogram indices: master
 * writes it, children map it read-only) and the values (every process adds into its slot). */
size_t bst_counters_registry_size(void);
size_t bst_counters_values_size(void);
/* Master, before any fork: moves the table into reg and vals. reused: both hold a table from
 * a previous image (reload, upgrade): its entries and values are kept and this process's
 * registrations so far are folded in by name. Ids already handed out stay valid. 0, or -1
 * when they hold a table of another layout or one that fails validation (counts, kinds,
 * indices, unterminated strings): then it is reinitialised, and its values are lost. */
int bst_counters_attach_shared(void *reg, void *vals, bool reused);
/* Readers use reg_ro (a read-only view of the registry, core/shm.h) from now on. */
void bst_counters_set_view(const void *reg_ro);
/* In a child: registration is master's alone; from now on it only finds what master
 * registered (BST_COUNTER_INVALID for a new name). */
void bst_counters_child(void);
/* A forked child: which slot its updates go to (BST_COUNTER_SLOT_HELPER, or 2 + worker slot). */
void bst_counters_use_slot(unsigned slot);
static inline unsigned bst_counter_worker_slot(int worker)
{
	return 2u + (unsigned)worker % BST_COUNTER_WORKER_SLOTS;
}

/* What an exposition needs: the i-th entry (i < bst_counter_count()). */
typedef enum { BST_METRIC_COUNTER = 1, BST_METRIC_HISTOGRAM = 2, BST_METRIC_GAUGE = 3 } bst_metric_kind;
typedef struct bst_counter_info {
	bst_metric_kind kind;
	const char *name, *help, *labels;
} bst_counter_info;
bool bst_counter_info_get(bst_counter_id id, bst_counter_info *out);
/* The id of the i-th entry, for walking the table (BST_COUNTER_INVALID past the end). */
bst_counter_id bst_counter_nth(size_t i);

/* Readers. Return 0 for invalid ids or the wrong kind. */
uint64_t bst_counter_get(bst_counter_id id);
uint64_t bst_histogram_count(bst_counter_id id);
uint64_t bst_histogram_sum(bst_counter_id id);
uint64_t bst_histogram_bucket(bst_counter_id id, unsigned bucket);

/* Bucket math, exposed for exposition code and tests. Upper bound is inclusive. */
unsigned bst_histogram_bucket_index(uint64_t value);
uint64_t bst_histogram_bucket_upper(unsigned bucket);

/* Number of registered entries (counters and histograms). */
size_t bst_counter_count(void);

#ifdef BST_TEST
/* Test builds only (BST_TEST, not set for release): forget every registration and zero
 * the table. Invalidates ids cached elsewhere, e.g. the log drop counter, so call
 * bst_log_init again afterwards. */
void bst_counters_reset_for_test(void);
#endif

#endif

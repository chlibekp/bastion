/* Process counters and histograms.
 *
 * Threading model: the table has a single registering writer (registration is not
 * signal-safe and must happen at startup, before workers fork). Updates use relaxed
 * atomic adds, so bst_counter_add and bst_histogram_observe are async-signal-safe,
 * allocation-free and cheap. Each process owns its slots: readers in another process
 * (Phase 14) see untorn 64-bit values but no cross-counter consistency. Sums and
 * counts wrap modulo 2^64.
 *
 * The table is one self-contained struct with no internal pointers, reached through a
 * single base pointer in counters.c, so Phase 14 can relocate it to shared memory by
 * changing that pointer. Callers only ever hold ids. */
#ifndef BST_CORE_COUNTERS_H
#define BST_CORE_COUNTERS_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef uint32_t bst_counter_id;

/* Returned when the table is full or the arguments are invalid. Every operation
 * accepts it and does nothing. */
#define BST_COUNTER_INVALID UINT32_MAX

#define BST_COUNTER_MAX 256     /* counters and histograms combined */
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

void bst_counter_add(bst_counter_id id, uint64_t n);
void bst_histogram_observe(bst_counter_id id, uint64_t value);

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

/* Forget every registration and zero the table. Startup in a forked child, and tests. */
void bst_counters_reset(void);

#endif

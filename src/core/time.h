/* Coarse monotonic clock. */
#ifndef BST_TIME_H
#define BST_TIME_H

#include <stdint.h>

/* Milliseconds from CLOCK_MONOTONIC_COARSE. Cheap (vDSO, no syscall); resolution is
 * one kernel tick (typically 1-4 ms), which is all the timer wheel needs. */
uint64_t bst_now_ms(void);

#endif

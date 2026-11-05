/* ASan poison hooks; no-ops outside ASan builds. */
#ifndef BST_POISON_H
#define BST_POISON_H

#if defined(__SANITIZE_ADDRESS__)
#define BST_ASAN 1
#elif defined(__has_feature)
#if __has_feature(address_sanitizer)
#define BST_ASAN 1
#endif
#endif

#ifdef BST_ASAN
#include <sanitizer/asan_interface.h>
#define BST_POISON(p, n) ASAN_POISON_MEMORY_REGION((p), (n))
#define BST_UNPOISON(p, n) ASAN_UNPOISON_MEMORY_REGION((p), (n))
#else
#define BST_POISON(p, n) ((void)(p), (void)(n))
#define BST_UNPOISON(p, n) ((void)(p), (void)(n))
#endif

#endif

/* Minimal TAP harness. A test binary is one file: include this, define tests with
 * TEST(name) { ... }, and end the file with TAP_MAIN(). Output is TAP version 13;
 * the exit status is 0 only if every test passed. ASSERT* record a failure and
 * return from the test, so they may only be used directly in a TEST body (a void
 * function). ASSERT_EQ compares as long long; use ASSERT_STR for strings. */
#ifndef BST_TAP_H
#define BST_TAP_H

#include <stdio.h>
#include <string.h>

#define TAP_MAX_TESTS 256

typedef void (*tap_fn)(void);

static struct {
	const char *name[TAP_MAX_TESTS];
	tap_fn fn[TAP_MAX_TESTS];
	int count;
	int current_failed;
} tap_state;

static inline void tap_register(const char *name, tap_fn fn)
{
	if (tap_state.count < TAP_MAX_TESTS) {
		tap_state.name[tap_state.count] = name;
		tap_state.fn[tap_state.count] = fn;
		tap_state.count++;
	}
}

static inline int tap_run(void)
{
	int failed = 0;
	printf("TAP version 13\n1..%d\n", tap_state.count);
	for (int i = 0; i < tap_state.count; i++) {
		tap_state.current_failed = 0;
		tap_state.fn[i]();
		printf("%s %d - %s\n", tap_state.current_failed ? "not ok" : "ok", i + 1,
		       tap_state.name[i]);
		failed += tap_state.current_failed;
	}
	fflush(stdout);
	return failed ? 1 : 0;
}

#define TEST(name)                                                                      \
	static void name(void);                                                         \
	static void __attribute__((constructor)) tap_reg_##name(void)                   \
	{                                                                               \
		tap_register(#name, name);                                              \
	}                                                                               \
	static void name(void)

#define TAP_FAIL_(...)                                                                  \
	do {                                                                            \
		tap_state.current_failed = 1;                                           \
		printf("# %s:%d: ", __FILE__, __LINE__);                                \
		printf(__VA_ARGS__);                                                    \
		printf("\n");                                                           \
		return;                                                                 \
	} while (0)

#define ASSERT(cond)                                                                    \
	do {                                                                            \
		if (!(cond))                                                            \
			TAP_FAIL_("assertion failed: %s", #cond);                       \
	} while (0)

#define ASSERT_EQ(a, b)                                                                 \
	do {                                                                            \
		long long tap_a_ = (long long)(a), tap_b_ = (long long)(b);             \
		if (tap_a_ != tap_b_)                                                   \
			TAP_FAIL_("%s == %s failed: %lld vs %lld", #a, #b, tap_a_, tap_b_); \
	} while (0)

#define ASSERT_STR(a, b)                                                                \
	do {                                                                            \
		const char *tap_a_ = (a), *tap_b_ = (b);                                \
		if (tap_a_ == NULL || tap_b_ == NULL || strcmp(tap_a_, tap_b_) != 0)    \
			TAP_FAIL_("%s == %s failed: \"%s\" vs \"%s\"", #a, #b,          \
				  tap_a_ ? tap_a_ : "(null)", tap_b_ ? tap_b_ : "(null)"); \
	} while (0)

#define TAP_MAIN()                                                                      \
	int main(void)                                                                  \
	{                                                                               \
		return tap_run();                                                       \
	}

#endif

/* A compiled tcp_profile: the requested TCP socket tuning for a listener and the connections
 * it accepts. The config compiler fills it (config/tcp_directives.c); io/listener.c and
 * io/sockopts.c apply it. A bit in `set` says the profile asks for that option (an option
 * never mentioned costs no syscall anywhere); a bit in `require` says a kernel refusal is a
 * startup error instead of a logged warning.
 *
 * The documented default profile (bst_tcp_profile_defaults) is what a listener without
 * `tcp_profile=` gets, and what a `tcp_profile name { }` block holds before its own
 * directives: TCP_NODELAY on and a listen backlog of BST_TCP_DEFAULT_BACKLOG. Everything
 * else is left at the kernel's defaults. */
#ifndef BST_IO_TCP_PROFILE_H
#define BST_IO_TCP_PROFILE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define BST_TCP_DEFAULT_BACKLOG 4096 /* the kernel's own default net.core.somaxconn since 5.4 */
#define BST_TCP_CA_NAME_MAX 16       /* TCP_CA_NAME_MAX: 15 characters and the NUL */
#define BST_TCP_KEY_LEN 16           /* one TCP Fast Open key */

/* One per tcp_profile directive. The order is the order options are applied in, and the bit
 * position in bst_tcp_profile.set and .require. */
typedef enum bst_tcp_opt {
	BST_TCP_FASTOPEN,
	BST_TCP_FASTOPEN_KEY,
	BST_TCP_DEFER_ACCEPT,
	BST_TCP_BUSY_POLL,
	BST_TCP_PREFER_BUSY_POLL,
	BST_TCP_BUSY_POLL_BUDGET,
	BST_TCP_NODELAY,
	BST_TCP_QUICKACK,
	BST_TCP_CONGESTION,
	BST_TCP_NOTSENT_LOWAT,
	BST_TCP_USER_TIMEOUT,
	BST_TCP_KEEPALIVE,
	BST_TCP_RCVBUF,
	BST_TCP_SNDBUF,
	BST_TCP_PACING_RATE,
	BST_TCP_MARK,
	BST_TCP_FREEBIND,
	BST_TCP_BACKLOG,
	BST_TCP_STEERING,
	BST_TCP_OPT_COUNT
} bst_tcp_opt;

_Static_assert(BST_TCP_OPT_COUNT <= 32, "set and require are 32-bit masks");

typedef enum bst_steering {
	BST_STEER_NONE = 0,
	BST_STEER_INCOMING_CPU, /* SO_INCOMING_CPU: slot i prefers connections arriving on CPU i */
} bst_steering;

typedef struct bst_tcp_profile {
	const char *name; /* "default" for the implicit profile; lives as long as the config */
	uint32_t set;     /* bit (1u << bst_tcp_opt) per requested option */
	uint32_t require; /* subset of set: refusal fails startup */
	int fastopen;     /* TCP_FASTOPEN: queue length of pending SYNs with data */
	uint8_t fastopen_key[BST_TCP_KEY_LEN];
	unsigned defer_accept_s; /* TCP_DEFER_ACCEPT seconds (the kernel rounds to retransmits) */
	unsigned busy_poll_us;   /* SO_BUSY_POLL */
	bool prefer_busy_poll;   /* SO_PREFER_BUSY_POLL */
	unsigned busy_poll_budget; /* SO_BUSY_POLL_BUDGET packets per poll */
	bool nodelay;            /* TCP_NODELAY */
	bool quickack;           /* TCP_QUICKACK, applied to each accepted connection */
	char congestion[BST_TCP_CA_NAME_MAX]; /* TCP_CONGESTION */
	uint32_t notsent_lowat;  /* TCP_NOTSENT_LOWAT bytes */
	unsigned user_timeout_ms; /* TCP_USER_TIMEOUT */
	unsigned ka_idle_s, ka_interval_s, ka_count; /* SO_KEEPALIVE with TCP_KEEP* */
	uint32_t rcvbuf, sndbuf; /* SO_RCVBUF, SO_SNDBUF bytes as written (the kernel doubles them) */
	uint32_t pacing_rate;    /* SO_MAX_PACING_RATE bytes per second */
	uint32_t mark;           /* SO_MARK */
	bool freebind;           /* IP_FREEBIND */
	int backlog;             /* listen(2) backlog */
	bst_steering steering;
} bst_tcp_profile;

#define BST_TCP_HAS(p, o) ((((p)->set) >> (o)) & 1u)
#define BST_TCP_REQUIRED(p, o) ((((p)->require) >> (o)) & 1u)

/* Zeroes *p and sets the documented default profile under the given name. */
void bst_tcp_profile_defaults(bst_tcp_profile *p, const char *name);

/* fastopen_key text: 32 hex digits, or the kernel sysctl form, four groups of 8 hex digits
 * separated by '-'. Either case. False (and out untouched) otherwise. */
bool bst_tcp_parse_key(const char *s, size_t len, uint8_t out[BST_TCP_KEY_LEN]);

#endif

#include "http/h2/guard.h"

#include "core/counters.h"

static const char *const names[BST_H2G_ALL_KINDS] = {
	"rst", "server_reset", "settings", "ping", "empty", "priority", "window_update", "continuation",
	"control_queue", "stream_reset", "qpack", "control_stream",
};

static bst_counter_id c_abuse[BST_H2G_ALL_KINDS];

const char *bst_h2_guard_name(unsigned kind)
{
	return kind < BST_H2G_ALL_KINDS ? names[kind] : "unknown";
}

void bst_h2_guard_init(void)
{
	for (unsigned i = 0; i < BST_H2G_ALL_KINDS; i++) {
		char labels[48];
		unsigned n = 0;
		for (const char *p = "kind="; *p; p++)
			labels[n++] = *p;
		for (const char *p = names[i]; *p && n + 1 < sizeof labels; p++)
			labels[n++] = *p;
		labels[n] = '\0';
		c_abuse[i] = bst_counter_register("bastion_h2_abuse_total",
						  "HTTP/2 and HTTP/3 connections closed because a client used up an abuse budget",
						  labels);
	}
}

/* Phase 12 (escalation) takes the strike here: until it exists the hook is empty. */
static void escalate_hook(unsigned kind)
{
	(void)kind;
}

void bst_h2_guard_hit(unsigned kind)
{
	if (kind < BST_H2G_ALL_KINDS) {
		bst_counter_add(c_abuse[kind], 1);
		escalate_hook(kind);
	}
}

bool bst_h2_guard_charge(bst_h2_guard *g, const bst_cfg_h2_abuse *cfg, bst_h2_guard_kind kind,
			 uint64_t now_ms)
{
	static const size_t rate_off[BST_H2G_KINDS] = {
		[BST_H2G_RST] = offsetof(bst_cfg_h2_abuse, rst_rate),
		[BST_H2G_SERVER_RST] = offsetof(bst_cfg_h2_abuse, server_reset_rate),
		[BST_H2G_SETTINGS] = offsetof(bst_cfg_h2_abuse, settings_rate),
		[BST_H2G_PING] = offsetof(bst_cfg_h2_abuse, ping_rate),
		[BST_H2G_EMPTY] = offsetof(bst_cfg_h2_abuse, empty_frame_rate),
		[BST_H2G_PRIORITY] = offsetof(bst_cfg_h2_abuse, priority_rate),
		[BST_H2G_WINDOW_UPDATE] = offsetof(bst_cfg_h2_abuse, window_update_rate),
	};
	uint64_t rate = *(const uint32_t *)((const char *)cfg + rate_off[kind]);
	/* thousandths of an event: a bucket of `rate` events drains `rate` per second, which is `rate`
	 * thousandths per millisecond */
	uint64_t cap = rate * 1000;
	if (g->last_ms[kind] != 0 && now_ms > g->last_ms[kind]) {
		uint64_t drain = (now_ms - g->last_ms[kind]) * rate;
		g->level[kind] = g->level[kind] > drain ? g->level[kind] - drain : 0;
	}
	g->last_ms[kind] = now_ms != 0 ? now_ms : 1;
	g->level[kind] += 1000;
	if (g->level[kind] > cap) {
		g->hits[kind]++;
		return true;
	}
	return false;
}

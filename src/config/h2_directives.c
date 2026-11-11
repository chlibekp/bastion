/* HTTP/2 directives (Phase 7): the SETTINGS Bastion advertises, its timeouts and write policy. Per
 * server, read from the default server of the listener a connection arrived on (a connection
 * takes its figures before any Host says which server it is for). Every figure is a directive with a
 * default; src/http/h2 carries no constant an operator might need to change. */
#include "config/compile.h"
#include "config/values.h"

#include <string.h>

#define SEC 1000000LL

static bst_str as_str(const bst_ast_arg *a)
{
	return (bst_str){ a->text, (uint32_t)a->len };
}

static uint64_t u64_of(const bst_directive *d, const bst_ast_node *n)
{
	uint64_t v = 0;
	(void)bst_str_to_u64(as_str(bst_dir_pos(d, n, 0)), &v); /* validated by the argspec */
	return v;
}

static uint64_t size_of(const bst_directive *d, const bst_ast_node *n)
{
	uint64_t v = 0;
	(void)bst_parse_size(as_str(bst_dir_pos(d, n, 0)), &v);
	return v;
}

static uint64_t ms_of(const bst_directive *d, const bst_ast_node *n)
{
	uint64_t us = 0;
	(void)bst_parse_duration_us(as_str(bst_dir_pos(d, n, 0)), &us);
	return us / 1000;
}

static bool bool_of(const bst_directive *d, const bst_ast_node *n)
{
	bool v = false;
	(void)bst_parse_bool(as_str(bst_dir_pos(d, n, 0)), &v);
	return v;
}

#define AP(fn, field, expr)                                                          \
	static int fn(bst_cfg_ctx *c, const bst_directive *d, const bst_ast_node *n, \
		      bst_err *e)                                                    \
	{                                                                            \
		(void)e;                                                             \
		c->common->http.h2.field = (expr);                                   \
		return 0;                                                            \
	}

AP(ap_streams, max_concurrent_streams, (uint32_t)u64_of(d, n))
AP(ap_window, initial_window, (uint32_t)size_of(d, n))
AP(ap_conn_window, connection_window, (uint32_t)size_of(d, n))
AP(ap_frame, max_frame_size, (uint32_t)size_of(d, n))
AP(ap_list, max_header_list_size, (uint32_t)size_of(d, n))
AP(ap_idle, idle_timeout_ms, ms_of(d, n))
AP(ap_table, header_table_size, (uint32_t)size_of(d, n))
AP(ap_prio, priorities, bool_of(d, n))
AP(ap_chunk, write_chunk, (uint32_t)size_of(d, n))

static int ap_policy(bst_cfg_ctx *c, const bst_directive *d, const bst_ast_node *n, bst_err *e)
{
	(void)e;
	c->common->http.h2.recv_window_policy =
		strcmp(bst_dir_pos(d, n, 0)->text, "eager") == 0 ? BST_H2_WINDOW_EAGER : BST_H2_WINDOW_FIXED;
	return 0;
}

AP(ap_connect, connect_protocol, bool_of(d, n))

#define APA(fn, field, expr)                                                         \
	static int fn(bst_cfg_ctx *c, const bst_directive *d, const bst_ast_node *n, \
		      bst_err *e)                                                    \
	{                                                                            \
		(void)e;                                                             \
		c->common->http.h2.abuse.field = (expr);                             \
		return 0;                                                            \
	}

APA(ap_rst, rst_rate, (uint32_t)u64_of(d, n))
APA(ap_srst, server_reset_rate, (uint32_t)u64_of(d, n))
APA(ap_settings, settings_rate, (uint32_t)u64_of(d, n))
APA(ap_ping, ping_rate, (uint32_t)u64_of(d, n))
APA(ap_empty, empty_frame_rate, (uint32_t)u64_of(d, n))
APA(ap_priority, priority_rate, (uint32_t)u64_of(d, n))
APA(ap_wu, window_update_rate, (uint32_t)u64_of(d, n))
APA(ap_cont, continuation_max, (uint32_t)u64_of(d, n))
APA(ap_ctlq, control_queue_max, (uint32_t)size_of(d, n))

static int ap_abuse(bst_cfg_ctx *c, const bst_directive *d, const bst_ast_node *n, bst_err *e)
{
	(void)c, (void)d, (void)n, (void)e; /* the children fill c->common->http.h2.abuse */
	return 0;
}

#define ARG1(...) .args = { .min_args = 1, .max_args = 1, .pos = { __VA_ARGS__ } }
#define SRV BST_CTX_SERVER
#define AB BST_CTX_H2_ABUSE
#define RATE(nm, fn, dflt, what)                                                                \
	{ .name = nm, .contexts = AB, .apply = fn, .default_value = dflt,                        \
	  .doc = what " The budget is a leaky bucket that holds this many events and drains this " \
		 "many per second: a client inside it is never affected, one that keeps going "    \
		 "past it has the connection closed with GOAWAY(ENHANCE_YOUR_CALM) and counted in "\
		 "bastion_h2_abuse_total.",                                                        \
	  ARG1({ .kind = BST_T_INT, .min = 1, .max = 10000000 }) }

static const char *const policy_values[] = { "fixed", "eager", NULL };

static const bst_directive h2_dirs[] = {
	{ .name = "http2_max_concurrent_streams", .contexts = SRV, .apply = ap_streams,
	  .default_value = "128",
	  .doc = "SETTINGS_MAX_CONCURRENT_STREAMS: most requests one HTTP/2 connection may have in "
		 "progress. A request opened beyond it is refused with RST_STREAM(REFUSED_STREAM), "
		 "which clients retry safely. Each open stream costs a few kilobytes, so this bounds "
		 "what one connection can hold.",
	  ARG1({ .kind = BST_T_INT, .min = 1, .max = 1 << 20 }) },
	{ .name = "http2_initial_window", .contexts = SRV, .apply = ap_window, .default_value = "64k",
	  .doc = "SETTINGS_INITIAL_WINDOW_SIZE: bytes of request body a client may send on one stream "
		 "before the handler has taken some. Credit comes back as the handler reads, so a "
		 "stream holds at most this much unread data.",
	  ARG1({ .kind = BST_T_SIZE, .min = 1, .max = 2147483647 }) },
	{ .name = "http2_connection_window", .contexts = SRV, .apply = ap_conn_window,
	  .default_value = "1m",
	  .doc = "Bytes of request bodies a client may have in flight over the whole connection (the "
		 "connection-level flow-control window; raised from the protocol's 65535 with a "
		 "WINDOW_UPDATE when the connection starts).",
	  ARG1({ .kind = BST_T_SIZE, .min = 65535, .max = 2147483647 }) },
	{ .name = "http2_max_frame_size", .contexts = SRV, .apply = ap_frame, .default_value = "16k",
	  .doc = "SETTINGS_MAX_FRAME_SIZE: the largest frame payload accepted. A larger frame ends the "
		 "connection (FRAME_SIZE_ERROR) before its payload is read. At least 16384, the "
		 "protocol's own minimum.",
	  ARG1({ .kind = BST_T_SIZE, .min = 16384, .max = 16777215 }) },
	{ .name = "http2_max_header_list_size", .contexts = SRV, .apply = ap_list,
	  .default_value = "16k",
	  .doc = "SETTINGS_MAX_HEADER_LIST_SIZE: the most a request's header fields may add up to, "
		 "each counted as name + value + 32 bytes (RFC 9113 section 6.5.2), after HPACK "
		 "decoding. It also bounds the compressed header block that is buffered, so a block "
		 "that never ends (a CONTINUATION flood) is cut at this size and a small block that "
		 "expands into huge headers (an HPACK bomb) is cut as it expands. Either ends the "
		 "connection.",
	  ARG1({ .kind = BST_T_SIZE, .min = 1024, .max = 1 << 24 }) },
	{ .name = "http2_idle_timeout", .contexts = SRV, .apply = ap_idle, .default_value = "120s",
	  .doc = "How long an HTTP/2 connection with no request in progress may stay silent before it "
		 "is closed (after a GOAWAY).",
	  ARG1({ .kind = BST_T_DURATION, .min = 1 * SEC, .max = (int64_t)86400 * SEC }) },
	{ .name = "http2_header_table_size", .contexts = SRV, .apply = ap_table,
	  .default_value = "4k",
	  .doc = "SETTINGS_HEADER_TABLE_SIZE: the HPACK dynamic table the client may use for request "
		 "headers, and the most Bastion uses for response headers. Each decoder holds this "
		 "much per connection; 0 turns HPACK indexing off.",
	  ARG1({ .kind = BST_T_SIZE, .min = 0, .max = 1 << 20 }) },
	{ .name = "http2_priorities", .contexts = SRV, .apply = ap_prio, .default_value = "on",
	  .doc = "Honour RFC 9218 priorities (the Priority header and PRIORITY_UPDATE frames): "
		 "responses are written in urgency order, and equally urgent incremental ones share "
		 "the connection round-robin. Off sends in the order the responses became ready.",
	  ARG1({ .kind = BST_T_BOOL }) },
	{ .name = "http2_write_chunk", .contexts = SRV, .apply = ap_chunk, .default_value = "64k",
	  .doc = "Most DATA payload handed to the socket in one write. Smaller writes let a "
		 "later, more urgent response overtake one in progress sooner (priorities take effect "
		 "between writes) at the cost of more system calls; with the listener's tcp_profile "
		 "TCP_NOTSENT_LOWAT this keeps little data queued in the kernel.",
	  ARG1({ .kind = BST_T_SIZE, .min = 1024, .max = 1 << 24 }) },
	{ .name = "http2_recv_window_policy", .contexts = SRV, .apply = ap_policy,
	  .default_value = "fixed",
	  .doc = "When request-body credit goes back to the client: `fixed` sends a WINDOW_UPDATE once "
		 "half of a window has been consumed by the handler (fewer frames), `eager` sends one "
		 "as soon as the handler took the data (tighter memory, more frames).",
	  ARG1({ .kind = BST_T_ENUM, .enum_values = policy_values }) },
	{ .name = "http2_connect_protocol", .contexts = SRV, .apply = ap_connect, .default_value = "off",
	  .doc = "Advertise SETTINGS_ENABLE_CONNECT_PROTOCOL (RFC 8441), which lets clients open "
		 "WebSocket and other tunnels as an extended CONNECT request (`:protocol`). Off "
		 "refuses such requests as malformed. Turn it on only where a handler that serves "
		 "tunnels exists; until then an extended CONNECT is answered 501.",
	  ARG1({ .kind = BST_T_BOOL }) },
	{ .name = "http2_abuse", .contexts = SRV, .apply = ap_abuse, .singleton = true,
	  .child_ctx = AB,
	  .doc = "Budgets against HTTP/2 attacks that cost the server work or memory for next to "
		 "nothing from the client: Rapid Reset (CVE-2023-44487), MadeYouReset "
		 "(CVE-2025-8671), CONTINUATION floods (CVE-2024-27983), and the 2019 settings, "
		 "ping, reset, empty-frame and dependency floods (CVE-2019-9511 to -9518). Every "
		 "default applies when the block is absent.",
	  .args = { .block = BST_BLOCK_REQUIRED } },
	RATE("rst_rate", ap_rst, "200",
	     "RST_STREAM frames from the client per second (Rapid Reset). A browser leaving a page "
	     "cancels its open streams in one burst, so the default leaves room for http2_max_"
	     "concurrent_streams of them."),
	RATE("server_reset_rate", ap_srst, "100",
	     "Resets the server has to send because of what the client did (malformed requests, "
	     "frames for closed streams, refused streams: MadeYouReset)."),
	RATE("settings_rate", ap_settings, "20", "SETTINGS frames from the client per second."),
	RATE("ping_rate", ap_ping, "50", "PING frames from the client per second."),
	RATE("empty_frame_rate", ap_empty, "100",
	     "DATA, HEADERS and CONTINUATION frames without payload and without an end flag, per "
	     "second."),
	RATE("priority_rate", ap_priority, "500",
	     "PRIORITY and PRIORITY_UPDATE frames per second (the dependency flood). Browsers send "
	     "one per request at page load, so the default is generous."),
	RATE("window_update_rate", ap_wu, "5000",
	     "WINDOW_UPDATE frames from the client per second (the window drip). Fast downloads "
	     "legitimately cause thousands."),
	{ .name = "continuation_max", .contexts = AB, .apply = ap_cont, .default_value = "32",
	  .doc = "Most CONTINUATION frames in one header block. More ends the connection "
		 "(ENHANCE_YOUR_CALM); the block's total size is separately bounded by "
		 "http2_max_header_list_size.",
	  ARG1({ .kind = BST_T_INT, .min = 1, .max = 65536 }) },
	{ .name = "control_queue_max", .contexts = AB, .apply = ap_ctlq, .default_value = "1m",
	  .doc = "Bytes of control frames (acknowledgements, resets, header blocks) that may wait for "
		 "a client that does not read its socket. Past it the connection is closed.",
	  ARG1({ .kind = BST_T_SIZE, .min = 4096, .max = 1 << 30 }) },
};
BST_DIRECTIVES(h2_dirs);

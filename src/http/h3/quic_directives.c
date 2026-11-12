/* QUIC directives (Phase 8 Task 3): the transport figures of an `http3` listener, read from its
 * default server (a datagram carries no Host), and `quic_routing`, global. Every figure the QUIC
 * endpoint (quic.c) uses is a directive with a default; nothing there is a constant an operator might
 * need to change, apart from the token lifetimes documented in token.h. */
#include "config/compile.h"
#include "config/values.h"

#include <ngtcp2/ngtcp2.h>
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

static bool is(const bst_directive *d, const bst_ast_node *n, size_t i, const char *word)
{
	return strcmp(bst_dir_pos(d, n, i)->text, word) == 0;
}

#define AP(fn, field, expr)                                                          \
	static int fn(bst_cfg_ctx *c, const bst_directive *d, const bst_ast_node *n, \
		      bst_err *e)                                                    \
	{                                                                            \
		(void)e;                                                             \
		c->common->http.quic.field = (expr);                                 \
		return 0;                                                            \
	}

AP(ap_maxconn, max_connections, (uint32_t)u64_of(d, n))
AP(ap_idle, idle_timeout_ms, ms_of(d, n))
AP(ap_hs, handshake_timeout_ms, ms_of(d, n))
AP(ap_bidi, max_streams_bidi, u64_of(d, n))
AP(ap_uni, max_streams_uni, u64_of(d, n))
AP(ap_data, initial_max_data, size_of(d, n))
AP(ap_sdata, initial_max_stream_data, size_of(d, n))
AP(ap_cc, cc, is(d, n, 0, "bbr") ? BST_QUIC_CC_BBR : is(d, n, 0, "reno") ? BST_QUIC_CC_RENO : BST_QUIC_CC_CUBIC)
AP(ap_retry, retry,
   is(d, n, 0, "always") ? BST_QUIC_RETRY_ALWAYS : is(d, n, 0, "never") ? BST_QUIC_RETRY_NEVER : BST_QUIC_RETRY_AUTO)
AP(ap_threshold, retry_threshold, (uint32_t)u64_of(d, n))
AP(ap_reset, stateless_reset, bool_of(d, n))
AP(ap_h3_fields, h3_max_field_section_size, size_of(d, n))
AP(ap_h3_qpack, h3_qpack_table_size, size_of(d, n))
AP(ap_h3_blocked, h3_qpack_blocked_streams, u64_of(d, n))

static int ap_versions(bst_cfg_ctx *c, const bst_directive *d, const bst_ast_node *n, bst_err *e)
{
	bst_cfg_quic *q = &c->common->http.quic;
	q->nversions = 0;
	for (size_t i = 0; i < bst_dir_npos(d, n); i++) {
		uint32_t v = is(d, n, i, "v2") ? NGTCP2_PROTO_VER_V2 : NGTCP2_PROTO_VER_V1;
		for (uint32_t k = 0; k < q->nversions; k++)
			if (q->versions[k] == v) {
				bst_err_set(e, "quic_versions: %s given twice", bst_dir_pos(d, n, i)->text);
				bst_cfg_err_at(e, &bst_dir_pos(d, n, i)->loc);
				return -1;
			}
		q->versions[q->nversions++] = v;
	}
	return 0;
}

static int ap_routing(bst_cfg_ctx *c, const bst_directive *d, const bst_ast_node *n, bst_err *e)
{
	(void)e;
	c->global->quic_routing_hash = is(d, n, 0, "hash");
	return 0;
}

#define ARG1(...) .args = { .min_args = 1, .max_args = 1, .pos = { __VA_ARGS__ } }
#define SRV BST_CTX_SERVER

static const char *const cc_values[] = { "cubic", "bbr", "reno", NULL };
static const char *const retry_values[] = { "auto", "always", "never", NULL };
static const char *const version_values[] = { "v1", "v2", NULL };
static const char *const routing_values[] = { "ebpf", "hash", NULL };

static const bst_directive quic_dirs[] = {
	{ .name = "quic_routing", .contexts = BST_CTX_GLOBAL, .apply = ap_routing, .default_value = "ebpf",
	  .doc = "How datagrams of an `http3` listener reach the worker that holds their connection. "
		 "ebpf: master attaches an sk_reuseport program that reads the worker out of the "
		 "connection ID, so a client whose address changes (NAT rebinding, Wi-Fi to cellular) "
		 "keeps reaching the same worker. It needs CAP_BPF and CAP_NET_ADMIN at start; without "
		 "them the server logs a warning and uses hash. hash: the kernel spreads datagrams by "
		 "address and port, and a client that changes address lands on another worker, which "
		 "answers with a stateless reset (connection migration across workers is unsupported).",
	  ARG1({ .kind = BST_T_ENUM, .enum_values = routing_values }) },
	{ .name = "quic_max_connections", .contexts = SRV, .apply = ap_maxconn, .default_value = "10000",
	  .doc = "QUIC connections one worker holds at most. A new connection past it is refused with "
		 "CONNECTION_REFUSED in one small Initial, and no state is kept for it.",
	  ARG1({ .kind = BST_T_INT, .min = 1, .max = 1 << 24 }) },
	{ .name = "quic_idle_timeout", .contexts = SRV, .apply = ap_idle, .default_value = "30s",
	  .doc = "max_idle_timeout transport parameter: a connection with no packet in either "
		 "direction for this long is freed, silently (RFC 9000 section 10.1).",
	  ARG1({ .kind = BST_T_DURATION, .min = 1 * SEC, .max = (int64_t)3600 * SEC }) },
	{ .name = "quic_handshake_timeout", .contexts = SRV, .apply = ap_hs, .default_value = "10s",
	  .doc = "A handshake not complete after this long is abandoned and its state freed.",
	  ARG1({ .kind = BST_T_DURATION, .min = 1 * SEC, .max = (int64_t)300 * SEC }) },
	{ .name = "quic_max_streams_bidi", .contexts = SRV, .apply = ap_bidi, .default_value = "100",
	  .doc = "initial_max_streams_bidi: requests a client may have open at once on one connection.",
	  ARG1({ .kind = BST_T_INT, .min = 1, .max = 1 << 20 }) },
	{ .name = "quic_max_streams_uni", .contexts = SRV, .apply = ap_uni, .default_value = "3",
	  .doc = "initial_max_streams_uni: unidirectional streams a client may open (HTTP/3 needs 3: "
		 "control, QPACK encoder and decoder).",
	  ARG1({ .kind = BST_T_INT, .min = 3, .max = 100 }) },
	{ .name = "quic_initial_max_data", .contexts = SRV, .apply = ap_data, .default_value = "1m",
	  .doc = "initial_max_data: bytes a client may send over the whole connection before the "
		 "server gives more credit.",
	  ARG1({ .kind = BST_T_SIZE, .min = 16384, .max = 1 << 30 }) },
	{ .name = "quic_initial_max_stream_data", .contexts = SRV, .apply = ap_sdata, .default_value = "256k",
	  .doc = "initial_max_stream_data_bidi_remote and _uni: bytes a client may send on one stream "
		 "before the server gives more credit.",
	  ARG1({ .kind = BST_T_SIZE, .min = 4096, .max = 1 << 30 }) },
	{ .name = "quic_cc", .contexts = SRV, .apply = ap_cc, .default_value = "cubic",
	  .doc = "Congestion controller of every connection: cubic (RFC 9438), bbr (BBRv2) or reno.",
	  ARG1({ .kind = BST_T_ENUM, .enum_values = cc_values }) },
	{ .name = "quic_retry", .contexts = SRV, .apply = ap_retry, .default_value = "auto",
	  .doc = "When a new connection must prove its address with a Retry round trip before the "
		 "server keeps any state for it (RFC 9000 section 8.1). auto: while more than "
		 "quic_retry_threshold handshakes are half open in the worker (a flood of Initials "
		 "from spoofed sources). always: every new connection. never: never on the server's "
		 "own initiative; a ClientHello that does not start in the first Initial (a large one, "
		 "post-quantum key shares) still gets a Retry, since the QUIC library buffers it only "
		 "for a validated address (docs/conformance.md).",
	  ARG1({ .kind = BST_T_ENUM, .enum_values = retry_values }) },
	{ .name = "quic_retry_threshold", .contexts = SRV, .apply = ap_threshold, .default_value = "100",
	  .doc = "Half-open handshakes one worker accepts without Retry under `quic_retry auto`.",
	  ARG1({ .kind = BST_T_INT, .min = 0, .max = 1 << 24 }) },
	{ .name = "quic_versions", .contexts = SRV, .apply = ap_versions, .default_value = "v1 v2",
	  .doc = "QUIC versions served, most preferred first: v1 (RFC 9000), v2 (RFC 9369). A "
		 "client starting in one may be moved to a preferred one by compatible version "
		 "negotiation (RFC 9368). Any other version gets a Version Negotiation packet.",
	  .args = { .min_args = 1, .max_args = 2,
		    .pos = { { .kind = BST_T_ENUM, .enum_values = version_values } } } },
	{ .name = "quic_stateless_reset", .contexts = SRV, .apply = ap_reset, .default_value = "on",
	  .doc = "Answer a short-header packet for a connection no worker holds (after a restart, "
		 "or a client that moved to another worker under `quic_routing hash`) with a stateless "
		 "reset (RFC 9000 section 10.3), always smaller than the packet that caused it.",
	  ARG1({ .kind = BST_T_BOOL }) },
	{ .name = "http3_max_field_section_size", .contexts = SRV, .apply = ap_h3_fields, .default_value = "16k",
	  .doc = "SETTINGS_MAX_FIELD_SECTION_SIZE of HTTP/3 (RFC 9114 section 4.2.2): the largest "
		 "request header or trailer section, counted as name plus value plus 32 per field. "
		 "A larger one is answered 431.",
	  ARG1({ .kind = BST_T_SIZE, .min = 1024, .max = 1 << 20 }) },
	{ .name = "http3_qpack_table_size", .contexts = SRV, .apply = ap_h3_qpack, .default_value = "4k",
	  .doc = "SETTINGS_QPACK_MAX_TABLE_CAPACITY (RFC 9204): the dynamic table the client's QPACK "
		 "encoder may use on one connection. 0 turns the dynamic table off.",
	  ARG1({ .kind = BST_T_SIZE, .min = 0, .max = 1 << 20 }) },
	{ .name = "http3_qpack_blocked_streams", .contexts = SRV, .apply = ap_h3_blocked, .default_value = "16",
	  .doc = "SETTINGS_QPACK_BLOCKED_STREAMS (RFC 9204): request streams the client may leave "
		 "waiting on dynamic table updates at once.",
	  ARG1({ .kind = BST_T_INT, .min = 0, .max = 1000 }) },
};
BST_DIRECTIVES(quic_dirs);

/* Test-only directive table describing every directive in the full example of
 * docs/implementation-plan/config-language.md, plus a few extras for schema tests. It is
 * handed to bst_schema_build explicitly and never registered in the linker section, so it
 * cannot collide with the real tables. */
#ifndef BST_TEST_CFG_FIXTURE_H
#define BST_TEST_CFG_FIXTURE_H

#include "config/schema.h"

static int fx_noop(bst_cfg_ctx *c, const bst_directive *d, const bst_ast_node *n, bst_err *e)
{
	(void)c, (void)d, (void)n, (void)e;
	return 0;
}

#define STR { .kind = BST_T_STRING }
#define TPL { .kind = BST_T_TEMPLATE }
#define PATH { .kind = BST_T_PATH }
#define SIZE { .kind = BST_T_SIZE }
#define DUR { .kind = BST_T_DURATION }
#define RATE { .kind = BST_T_RATE }
#define BOOL { .kind = BST_T_BOOL }
#define PCT { .kind = BST_T_PERCENT }
#define CIDR { .kind = BST_T_CIDR }
#define MODE { .kind = BST_T_MODE }
#define INT(a, b) { .kind = BST_T_INT, .min = a, .max = b }
#define EN(v) { .kind = BST_T_ENUM, .enum_values = v }
#define E_(name, ...) static const char *const name[] = { __VA_ARGS__, NULL }
#define D(nm, ctx, ...) { .name = nm, .contexts = ctx, .doc = "d", .apply = fx_noop, __VA_ARGS__ }
#define A1(t) .args = { .min_args = 1, .max_args = 1, .pos = { t } }
#define AN(lo, hi, ...) .args = { .min_args = lo, .max_args = hi, .pos = { __VA_ARGS__ } }
#define OPTS(o) .opts = o, .nopts = sizeof(o) / sizeof(o[0])
#define BLK(cc, ...) .child_ctx = cc, .args = { .block = BST_BLOCK_REQUIRED, __VA_ARGS__ }
#define NAMED(cc) .repeatable = true, BLK(cc, .min_args = 1, .max_args = 1, .pos = { STR })
#define O(k, t) { .key = k, .type = t }
#define G BST_CTX_GLOBAL
#define SV BST_CTX_SERVER
#define LOC BST_CTX_LOCATION
#define UP BST_CTX_UPSTREAM
#define BOOLD(nm, ctx) D(nm, ctx, A1(BOOL))

E_(ev_loglevel, "debug", "info", "notice", "warn", "error");
E_(ev_backend, "auto", "uring", "epoll");
E_(ev_onlogoff, "on", "log", "off");
E_(ev_xmode, "auto", "native", "generic", "hw");
E_(ev_offonauto, "off", "on", "auto");
E_(ev_steer, "none", "incoming_cpu", "ebpf");
E_(ev_ktls, "off", "tx", "tx+rx");
E_(ev_vers, "1.2", "1.3");
E_(ev_proto, "http1", "http2");
E_(ev_resolve, "resolve", "backup");
E_(ev_flag, "tls", "http2", "http3", "redirect_https", "default_server", "proxy_protocol");
E_(ev_sec, "off", "basic", "strict");
E_(ev_comp, "zstd", "br", "gzip", "off");
E_(ev_imm, "immutable");
E_(ev_chal, "on", "off", "auto");
E_(ev_fmt, "json", "text");
E_(ev_matchf, "path", "uri", "header", "method");
E_(ev_matchop, "~", "~*", "=");
E_(ev_act, "deny", "allow", "log", "challenge");
E_(kw_auto, "auto");
E_(kw_retry_on, "connect_error", "timeout", "reset");

#define KINT(a, b, kw) { .kind = BST_T_INT, .min = a, .max = b, .keywords = kw }

static const bst_optspec o_rate[] = { O("burst=", INT(0, 100000000)) };
static const bst_optspec o_ka[] = { { .key = "idle=", .type = DUR, .required = true },
				    O("interval=", DUR), O("count=", INT(1, 127)) };
static const bst_optspec o_tick[] = { O("rotate=", DUR), O("keep=", INT(1, 16)),
				      O("file=", PATH) };
static const bst_optspec o_srv[] = { O("weight=", INT(1, 1000)), O("max_conns=", INT(0, 1000000)) };
static const bst_optspec o_hc[] = { O("path=", STR), O("interval=", DUR), O("timeout=", DUR),
				    O("fails=", INT(1, 1000)), O("passes=", INT(1, 1000)),
				    O("expect=", STR) };
static const bst_optspec o_pe[] = { O("fails=", INT(1, 1000)), O("window=", DUR), O("for=", DUR) };
static const bst_optspec o_retry[] = {
	O("attempts=", INT(0, 100)), O("budget=", PCT),
	{ .key = "on=",
	  .type = { .kind = BST_T_INT, .min = 100, .max = 599, .keywords = kw_retry_on, .list = true } },
	O("timeout=", DUR)
};
static const bst_optspec o_cb[] = { O("max_pending=", INT(0, 10000000)),
				    O("max_active=", INT(0, 10000000)),
				    O("max_retries=", INT(0, 10000000)) };
static const bst_optspec o_disk[] = { O("size=", SIZE) };
static const bst_optspec o_esc[] = { O("after=", INT(1, 1000000)), O("window=", DUR),
				     O("block=", DUR) };
static const bst_optspec o_listen[] = { O("tcp_profile=", STR) };
static const bst_optspec o_alog[] = { O("sample=", PCT), O("errors_only=", BOOL), O("if=", TPL) };
static const bst_optspec o_jwt[] = { O("keys=", PATH), O("alg=", STR), O("iss=", STR),
				     O("aud=", STR), O("leeway=", DUR), O("header=", STR),
				     O("cookie=", STR) };
static const bst_optspec o_sock[] = { O("mode=", MODE), O("group=", STR) };

static const bst_directive fx_dirs[] = {
	/* global */
	D("user", G, A1(STR)),
	D("workers", G, A1(KINT(1, 1024, kw_auto))),
	D("worker_cpu_affinity", G, A1(STR)),
	D("pid", G, A1(PATH)),
	D("error_log", G, AN(1, 2, PATH, EN(ev_loglevel))),
	D("io", G, BLK(BST_CTX_IO)),
	D("sandbox", G, BLK(BST_CTX_SANDBOX)),
	D("limits", G, BLK(BST_CTX_LIMITS)),
	D("xdp", G, BLK(BST_CTX_XDP)),
	D("tcp_profile", G, NAMED(BST_CTX_TCP_PROFILE)),
	D("tls_profile", G, NAMED(BST_CTX_TLS_PROFILE)),
	D("log_format", G, .repeatable = true,
	  BLK(BST_CTX_LOG_FORMAT, .min_args = 2, .max_args = 2, .pos = { STR, EN(ev_fmt) })),
	/* Every statement in a log_format block is a field: name, then a template. */
	D("field", BST_CTX_LOG_FORMAT, .any_name = true, .repeatable = true, A1(TPL)),
	D("upstream", G, NAMED(UP)),
	D("cache_store", G, NAMED(BST_CTX_CACHE_STORE)),
	D("limit_zone", G, NAMED(BST_CTX_LIMIT_ZONE)),
	D("waf_rule", G, NAMED(BST_CTX_WAF_RULE)),
	D("server", G, .repeatable = true, BLK(SV)),
	D("metrics", G, BLK(BST_CTX_METRICS)),
	D("admin", G, BLK(BST_CTX_ADMIN)),
	D("acme", G, BLK(BST_CTX_ACME)),
	/* extras for schema tests */
	D("nums", G, .repeatable = true, AN(1, 4, STR, INT(0, 9))),
	/* io */
	D("backend", BST_CTX_IO, A1(EN(ev_backend))),
	D("uring_entries", BST_CTX_IO, A1(INT(1, 65536))),
	BOOLD("uring_sqpoll", BST_CTX_IO),
	BOOLD("uring_napi", BST_CTX_IO),
	D("aio_threads", BST_CTX_IO, A1(INT(1, 1024))),
	D("huge_pages", BST_CTX_IO, A1(EN(ev_offonauto))),
	D("numa", BST_CTX_IO, A1(EN(ev_offonauto))),
	/* sandbox */
	D("seccomp", BST_CTX_SANDBOX, A1(EN(ev_onlogoff))),
	BOOLD("landlock", BST_CTX_SANDBOX),
	BOOLD("namespaces", BST_CTX_SANDBOX),
	BOOLD("drop_capabilities", BST_CTX_SANDBOX),
	/* limits */
	D("max_connections", BST_CTX_LIMITS, A1(INT(1, 100000000))),
	D("worker_memory", BST_CTX_LIMITS, A1(SIZE)),
	D("escalation_ceiling", BST_CTX_LIMITS, A1(INT(1, 100000000))),
	D("overload_status", BST_CTX_LIMITS, A1(INT(100, 599))),
	D("overload_retry_after", BST_CTX_LIMITS, A1(DUR)),
	/* xdp */
	D("interface", BST_CTX_XDP, .repeatable = true, A1(STR)),
	D("mode", BST_CTX_XDP, .require = true, A1(EN(ev_xmode))),
	D("allow", BST_CTX_XDP, .repeatable = true, A1(CIDR)),
	D("deny_file", BST_CTX_XDP, .repeatable = true, A1(PATH)),
	D("syn_rate", BST_CTX_XDP, .args = { .min_args = 1, .max_args = 1, .pos = { RATE }, OPTS(o_rate) }),
	D("udp_rate", BST_CTX_XDP, .args = { .min_args = 1, .max_args = 1, .pos = { RATE }, OPTS(o_rate) }),
	BOOLD("drop_reflection", BST_CTX_XDP),
	D("syn_cookies", BST_CTX_XDP, A1(EN(ev_offonauto))),
	D("ipv6_prefix", BST_CTX_XDP, A1(INT(1, 128))),
	/* tcp_profile */
#define TP BST_CTX_TCP_PROFILE
	D("fastopen", TP, .require = true, A1(INT(0, 1000000))),
	D("defer_accept", TP, .require = true, A1(DUR)),
	D("busy_poll", TP, .require = true, A1(DUR)),
	D("prefer_busy_poll", TP, .require = true, A1(BOOL)),
	D("congestion", TP, .require = true, A1(STR)),
	D("notsent_lowat", TP, .require = true, A1(SIZE)),
	D("user_timeout", TP, .require = true, A1(DUR)),
	D("keepalive", TP, .require = true, .args = { OPTS(o_ka) }),
	D("steering", TP, .require = true, A1(EN(ev_steer))),
	D("backlog", TP, .require = true, A1(INT(1, 1000000))),
	/* tls_profile */
#define TL BST_CTX_TLS_PROFILE
	D("versions", TL, AN(1, 2, EN(ev_vers))),
	D("groups", TL, AN(1, 16, STR)),
	D("ciphers_tls12", TL, AN(1, 32, STR)),
	D("ktls", TL, .require = true, A1(EN(ev_ktls))),
	D("tickets", TL, .args = { .max_args = 1, .pos = { STR }, OPTS(o_tick) }),
	BOOLD("ocsp_stapling", TL),
	BOOLD("early_data", TL),
	D("handshake_timeout", TL, A1(DUR)),
	/* upstream: balance and tls are two-word directives */
	D("balance", UP, .subname = "round_robin", .args = { 0 }),
	D("balance", UP, .subname = "least_conn", .args = { 0 }),
	D("balance", UP, .subname = "peak_ewma", .args = { 0 }),
	D("balance", UP, .subname = "hash", A1(TPL)),
	D("tls", UP, .subname = "verify", A1(BOOL)),
	D("tls", UP, .subname = "ca", A1(PATH)),
	D("server", UP, .repeatable = true,
	  .args = { .min_args = 1, .max_args = 3, .pos = { STR, EN(ev_resolve) }, OPTS(o_srv) }),
	D("keepalive", UP, A1(INT(0, 1000000))),
	D("connect_timeout", UP, A1(DUR)),
	D("health_check", UP, .args = { OPTS(o_hc) }),
	D("passive_eject", UP, .args = { OPTS(o_pe) }),
	D("retry", UP, .args = { OPTS(o_retry) }),
	D("circuit_breaker", UP, .args = { OPTS(o_cb) }),
	D("protocol", UP, A1(EN(ev_proto))),
	/* cache_store */
#define CS BST_CTX_CACHE_STORE
	D("disk", CS, .args = { .min_args = 1, .max_args = 1, .pos = { PATH }, OPTS(o_disk) }),
	D("ram", CS, A1(SIZE)),
	D("max_object", CS, A1(SIZE)),
	D("lock_timeout", CS, A1(DUR)),
	/* limit_zone */
#define LZ BST_CTX_LIMIT_ZONE
	D("key", LZ, A1(TPL)),
	D("rate", LZ, .args = { .min_args = 1, .max_args = 1, .pos = { RATE }, OPTS(o_rate) }),
	D("escalate", LZ, .args = { OPTS(o_esc) }),
	/* waf_rule */
	D("match", BST_CTX_WAF_RULE, .repeatable = true,
	  AN(3, 3, EN(ev_matchf), EN(ev_matchop), STR)),
	D("action", BST_CTX_WAF_RULE, AN(1, 2, EN(ev_act), INT(100, 599))),
	/* server */
	D("name", SV, .repeatable = true, AN(1, 32, STR)),
	D("listen", SV, .repeatable = true, .require = true,
	  .args = { .min_args = 1, .max_args = 8, .pos = { STR, EN(ev_flag) }, OPTS(o_listen) }),
	D("tls_profile", SV, A1(STR)),
	D("tls_cert", SV, .repeatable = true, AN(2, 2, PATH, PATH)),
	D("access_log", SV | LOC, .repeatable = true,
	  .args = { .min_args = 1, .max_args = 2, .pos = { STR }, OPTS(o_alog) }),
	D("security_headers", SV | LOC, A1(EN(ev_sec))),
	D("limit", SV | LOC, .repeatable = true, A1(STR)),
	D("waf", SV | LOC, .repeatable = true, A1(STR)),
	D("compress", SV | LOC, AN(1, 3, EN(ev_comp))),
	D("client_max_body_size", SV | LOC, A1(SIZE)),
	D("client_header_timeout", SV, A1(DUR)),
	D("client_body_min_rate", SV, A1(RATE)),
	D("location", SV | LOC, .repeatable = true,
	  BLK(LOC, .min_args = 1, .max_args = 2, .pos = { STR })),
	/* location */
	D("root", SV | LOC, A1(PATH)),
	D("try_files", SV | LOC, AN(1, 16, TPL)),
	D("expires", SV | LOC, AN(1, 2, DUR, EN(ev_imm))),
	BOOLD("precompressed", SV | LOC),
	D("proxy", SV | LOC, A1(STR)),
	D("cache", SV | LOC, A1(STR)),
	D("cache_valid", SV | LOC, .repeatable = true, AN(2, 2, INT(100, 599), DUR)),
	D("stale_while_revalidate", SV | LOC, A1(DUR)),
	D("stale_if_error", SV | LOC, A1(DUR)),
	D("auth_jwt", SV | LOC, .args = { OPTS(o_jwt) }),
	D("challenge", SV | LOC, A1(EN(ev_chal))),
	D("redirect", SV | LOC, AN(2, 2, INT(300, 399), TPL)),
	/* metrics, admin, acme */
	D("listen", BST_CTX_METRICS, A1(STR)),
	D("socket", BST_CTX_ADMIN,
	  .args = { .min_args = 1, .max_args = 1, .pos = { PATH }, OPTS(o_sock) }),
	D("email", BST_CTX_ACME, A1(STR)),
};

static const bst_dirtab fx_tab = { fx_dirs, sizeof fx_dirs / sizeof fx_dirs[0] };

#endif

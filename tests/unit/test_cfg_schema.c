#include "config/parser.h"
#include "config/schema.h"
#include "config/values.h"
#include "core/arena.h"
#include "tap.h"

#include <stdint.h>
#include <string.h>

#define S(lit) ((bst_str){ (lit), (uint32_t)(sizeof(lit) - 1) })

/* ---- Test-only directive tables, registered from this file. ---- */

static const char *const ev_ktls[] = { "off", "tx", "tx+rx", NULL };
static const char *const ev_mode[] = { "auto", "native", "generic", NULL };

#define STR { .kind = BST_T_STRING }

static const bst_directive t_global[] = {
	{ .name = "server", .contexts = BST_CTX_GLOBAL, .child_ctx = BST_CTX_SERVER,
	  .repeatable = true, .args = { .block = BST_BLOCK_REQUIRED },
	  .doc = "A virtual server." },
	{ .name = "upstream", .contexts = BST_CTX_GLOBAL, .child_ctx = BST_CTX_UPSTREAM,
	  .repeatable = true,
	  .args = { .min_args = 1, .max_args = 1, .pos = { STR }, .block = BST_BLOCK_REQUIRED },
	  .doc = "A named upstream group." },
	{ .name = "tcp_profile", .contexts = BST_CTX_GLOBAL, .child_ctx = BST_CTX_TCP_PROFILE,
	  .repeatable = true,
	  .args = { .min_args = 1, .max_args = 1, .pos = { STR }, .block = BST_BLOCK_REQUIRED },
	  .doc = "A named TCP socket profile." },
	{ .name = "log_format", .contexts = BST_CTX_GLOBAL, .child_ctx = BST_CTX_LOG_FORMAT,
	  .repeatable = true,
	  .args = { .min_args = 2, .max_args = 2, .pos = { STR }, .block = BST_BLOCK_REQUIRED },
	  .doc = "A named access log format." },
	{ .name = "limit_zone", .contexts = BST_CTX_GLOBAL, .child_ctx = BST_CTX_LIMIT_ZONE,
	  .repeatable = true,
	  .args = { .min_args = 1, .max_args = 1, .pos = { STR }, .block = BST_BLOCK_REQUIRED },
	  .doc = "A named rate limit zone." },
	{ .name = "tls_profile", .contexts = BST_CTX_GLOBAL, .child_ctx = BST_CTX_TLS_PROFILE,
	  .repeatable = true,
	  .args = { .min_args = 1, .max_args = 1, .pos = { STR }, .block = BST_BLOCK_REQUIRED },
	  .doc = "A named TLS profile." },
	{ .name = "io", .contexts = BST_CTX_GLOBAL, .child_ctx = BST_CTX_IO,
	  .args = { .block = BST_BLOCK_REQUIRED }, .doc = "I/O engine settings." },
	{ .name = "workers", .contexts = BST_CTX_GLOBAL, .default_value = "auto",
	  .args = { .min_args = 1, .max_args = 1, .pos = { STR } },
	  .doc = "Worker count or auto." },
	{ .name = "worker_memory", .contexts = BST_CTX_GLOBAL, .default_value = "1g",
	  .args = { .min_args = 1, .max_args = 1, .pos = { { .kind = BST_T_SIZE } } },
	  .doc = "Memory ceiling per worker." },
	{ .name = "overload_retry_after", .contexts = BST_CTX_GLOBAL, .default_value = "5s",
	  .args = { .min_args = 1, .max_args = 1, .pos = { { .kind = BST_T_DURATION } } },
	  .doc = "Retry-After value on overload." },
	{ .name = "overload_status", .contexts = BST_CTX_GLOBAL, .default_value = "503",
	  .args = { .min_args = 1, .max_args = 1,
		    .pos = { { .kind = BST_T_INT, .min = 100, .max = 599 } } },
	  .doc = "HTTP status sent on overload." },
	{ .name = "uring_sqpoll", .contexts = BST_CTX_IO, .default_value = "off",
	  .args = { .min_args = 1, .max_args = 1, .pos = { { .kind = BST_T_BOOL } } },
	  .doc = "Kernel submission queue polling." },
	{ .name = "mode", .contexts = BST_CTX_XDP, .default_value = "auto",
	  .args = { .min_args = 1, .max_args = 1,
		    .pos = { { .kind = BST_T_ENUM, .enum_values = ev_mode } } },
	  .doc = "XDP attach mode." },
	{ .name = "allow", .contexts = BST_CTX_XDP, .repeatable = true,
	  .args = { .min_args = 1, .max_args = 1, .pos = { { .kind = BST_T_CIDR } } },
	  .doc = "Allowed source network." },
	{ .name = "xdp", .contexts = BST_CTX_GLOBAL, .child_ctx = BST_CTX_XDP,
	  .args = { .block = BST_BLOCK_REQUIRED }, .doc = "XDP packet filter." },
};
BST_DIRECTIVES(t_global);

static const bst_optspec o_listen[] = {
	{ .key = "tcp_profile=", .type = { .kind = BST_T_STRING } },
};

static const bst_directive t_server[] = {
	{ .name = "root", .contexts = BST_CTX_SERVER | BST_CTX_LOCATION,
	  .args = { .min_args = 1, .max_args = 1, .pos = { { .kind = BST_T_PATH } } },
	  .doc = "Document root." },
	{ .name = "proxy", .contexts = BST_CTX_LOCATION,
	  .args = { .min_args = 1, .max_args = 1, .pos = { STR } },
	  .doc = "Forward to an upstream or URL." },
	{ .name = "listen", .contexts = BST_CTX_SERVER, .repeatable = true,
	  .args = { .min_args = 1, .max_args = 8, .pos = { STR },
		    .opts = o_listen, .nopts = 1 },
	  .doc = "Listen address and flags." },
	{ .name = "location", .contexts = BST_CTX_SERVER | BST_CTX_LOCATION,
	  .child_ctx = BST_CTX_LOCATION, .repeatable = true,
	  .args = { .min_args = 1, .max_args = 2, .pos = { STR }, .block = BST_BLOCK_REQUIRED },
	  .doc = "Match requests by path." },
	{ .name = "tls_cert", .contexts = BST_CTX_SERVER,
	  .args = { .min_args = 2, .max_args = 2,
		    .pos = { { .kind = BST_T_PATH }, { .kind = BST_T_PATH } } },
	  .doc = "Certificate and key files." },
	{ .name = "try_files", .contexts = BST_CTX_LOCATION,
	  .args = { .min_args = 1, .max_args = 8, .pos = { { .kind = BST_T_TEMPLATE } } },
	  .doc = "Candidate files; the last is a fallback." },
	{ .name = "ktls", .contexts = BST_CTX_TLS_PROFILE, .require = true,
	  .args = { .min_args = 1, .max_args = 1,
		    .pos = { { .kind = BST_T_ENUM, .enum_values = ev_ktls } } },
	  .doc = "Kernel TLS offload." },
};
BST_DIRECTIVES(t_server);

static const bst_optspec o_keepalive[] = {
	{ .key = "idle=", .type = { .kind = BST_T_DURATION }, .required = true },
	{ .key = "interval=", .type = { .kind = BST_T_DURATION } },
	{ .key = "count=", .type = { .kind = BST_T_INT, .min = 1, .max = 127 } },
};
static const bst_optspec o_retry[] = {
	{ .key = "attempts=", .type = { .kind = BST_T_INT, .min = 0, .max = 10 } },
	{ .key = "budget=", .type = { .kind = BST_T_PERCENT } },
	{ .key = "on=", .type = { .kind = BST_T_STRING } },
};
static const bst_optspec o_rate[] = {
	{ .key = "burst=", .type = { .kind = BST_T_INT, .min = 0, .max = 1000000 } },
};
static const bst_optspec o_srv[] = {
	{ .key = "weight=", .type = { .kind = BST_T_INT, .min = 1, .max = 1000 } },
};

static const bst_directive t_misc[] = {
	{ .name = "keepalive", .contexts = BST_CTX_TCP_PROFILE,
	  .args = { .opts = o_keepalive, .nopts = 3 }, .doc = "TCP keepalive probes." },
	{ .name = "retry", .contexts = BST_CTX_UPSTREAM,
	  .args = { .opts = o_retry, .nopts = 3 }, .doc = "Retry policy." },
	{ .name = "rate", .contexts = BST_CTX_LIMIT_ZONE,
	  .args = { .min_args = 1, .max_args = 1, .pos = { { .kind = BST_T_RATE } },
		    .opts = o_rate, .nopts = 1 },
	  .doc = "Request rate limit." },
	{ .name = "key", .contexts = BST_CTX_LIMIT_ZONE,
	  .args = { .min_args = 1, .max_args = 1, .pos = { { .kind = BST_T_TEMPLATE } } },
	  .doc = "Limit key template." },
	/* Same name as the global block, disjoint context: legal. */
	{ .name = "server", .contexts = BST_CTX_UPSTREAM, .repeatable = true,
	  .args = { .min_args = 1, .max_args = 4, .pos = { STR }, .opts = o_srv, .nopts = 1 },
	  .doc = "A backend address." },
	{ .name = "budget_pct", .contexts = BST_CTX_UPSTREAM,
	  .args = { .min_args = 1, .max_args = 1, .pos = { { .kind = BST_T_PERCENT } } },
	  .doc = "Retry budget." },
};
BST_DIRECTIVES(t_misc);

/* ---- Helpers ---- */

static bst_arena *A;
static bst_err E;

static int validate(const char *text)
{
	if (A)
		bst_arena_free(A);
	A = bst_arena_new(1 << 16);
	memset(&E, 0, sizeof E);
	bst_ast *ast = bst_cfg_parse_string(text, strlen(text), "t.conf", NULL, A, &E);
	if (!ast) {
		snprintf(E.msg, sizeof E.msg, "PARSE FAILED");
		return -2;
	}
	return bst_cfg_validate(ast, &E);
}

static int has(const char *needle)
{
	return strstr(E.msg, needle) != NULL;
}

/* ---- Values ---- */

TEST(size_values)
{
	uint64_t v;
	ASSERT(bst_parse_size(S("512"), &v) && v == 512);
	ASSERT(bst_parse_size(S("16k"), &v) && v == 16384);
	ASSERT(bst_parse_size(S("1m"), &v) && v == 1048576);
	ASSERT(bst_parse_size(S("2g"), &v) && v == 2147483648ull);
	ASSERT(bst_parse_size(S("0"), &v) && v == 0);
	ASSERT(bst_parse_size(S("18446744073709551615"), &v) && v == UINT64_MAX);
	ASSERT(!bst_parse_size(S("18446744073709551616"), &v));
	ASSERT(!bst_parse_size(S("99999999999g"), &v));
	ASSERT(!bst_parse_size(S("17179869184g"), &v)); /* 2^34 * 2^30 = 2^64 */
	ASSERT(bst_parse_size(S("17179869183g"), &v));
	ASSERT(!bst_parse_size(S("1x"), &v));
	ASSERT(!bst_parse_size(S("-1"), &v));
	ASSERT(!bst_parse_size(S("+1"), &v));
	ASSERT(!bst_parse_size(S("1K"), &v)); /* case-sensitive */
	ASSERT(!bst_parse_size(S("1G"), &v));
	ASSERT(!bst_parse_size(S("1kb"), &v));
	ASSERT(!bst_parse_size(S("k"), &v));
	ASSERT(!bst_parse_size(S(""), &v));
	ASSERT(!bst_parse_size(S(" 1"), &v));
	ASSERT(!bst_parse_size(S("1 "), &v));
	ASSERT(!bst_parse_size(S("1.5k"), &v));
	ASSERT(!bst_parse_size(S("0x10"), &v));
	ASSERT(!bst_parse_size((bst_str){ "1\0" "k", 3 }, &v));
}

TEST(duration_values)
{
	uint64_t v;
	ASSERT(bst_parse_duration_us(S("50us"), &v) && v == 50);
	ASSERT(bst_parse_duration_us(S("10ms"), &v) && v == 10000);
	ASSERT(bst_parse_duration_us(S("30s"), &v) && v == 30000000ull);
	ASSERT(bst_parse_duration_us(S("5m"), &v) && v == 300000000ull);
	ASSERT(bst_parse_duration_us(S("1h"), &v) && v == 3600000000ull);
	ASSERT(bst_parse_duration_us(S("1d"), &v) && v == 86400000000ull);
	ASSERT(bst_parse_duration_us(S("0s"), &v) && v == 0);
	ASSERT(!bst_parse_duration_us(S("5"), &v));
	ASSERT(!bst_parse_duration_us(S("s"), &v));
	ASSERT(!bst_parse_duration_us(S("5S"), &v));
	ASSERT(!bst_parse_duration_us(S("5y"), &v));
	ASSERT(!bst_parse_duration_us(S("5mm"), &v));
	ASSERT(!bst_parse_duration_us(S("1.5s"), &v));
	ASSERT(!bst_parse_duration_us(S("-1s"), &v));
	ASSERT(!bst_parse_duration_us(S("99999999999999999d"), &v));
	ASSERT(!bst_parse_duration_us(S("18446744073709551616us"), &v));
	ASSERT(bst_parse_duration_us(S("18446744073709551615us"), &v) && v == UINT64_MAX);
}

TEST(rate_values)
{
	bst_rate r, q;
	ASSERT(bst_parse_rate(S("100/s"), &r) && r.count == 100 && r.period_us == 1000000);
	ASSERT(bst_parse_rate(S("1k/s"), &r) && r.count == 1024 && r.period_us == 1000000);
	ASSERT(bst_parse_rate(S("6000/m"), &r) && r.count == 6000 && r.period_us == 60000000);
	ASSERT(bst_parse_rate(S("100/s"), &q));
	{
		bst_rate six;
		ASSERT(bst_parse_rate(S("6000/m"), &six));
		ASSERT(bst_rate_eq(&six, &q));
	}
	/* 5/m is not a whole number per second: kept exact, not rounded to 0. */
	ASSERT(bst_parse_rate(S("5/m"), &r) && r.count == 5 && r.period_us == 60000000);
	ASSERT(!bst_rate_eq(&r, &q));
	ASSERT(!bst_parse_rate(S("0/s"), &r));
	ASSERT(!bst_parse_rate(S("0k/s"), &r));
	ASSERT(!bst_parse_rate(S("100"), &r));
	ASSERT(!bst_parse_rate(S("100/"), &r));
	ASSERT(!bst_parse_rate(S("/s"), &r));
	ASSERT(!bst_parse_rate(S("100/h"), &r));
	ASSERT(!bst_parse_rate(S("100/S"), &r));
	ASSERT(!bst_parse_rate(S("1.5/s"), &r));
	ASSERT(!bst_parse_rate(S("100/s "), &r));
	ASSERT(!bst_parse_rate(S("99999999999g/s"), &r));
	ASSERT(!bst_parse_rate(S("-1/s"), &r));
}

TEST(bool_enum_kv_int)
{
	bool b = false;
	ASSERT(bst_parse_bool(S("on"), &b) && b);
	ASSERT(bst_parse_bool(S("off"), &b) && !b);
	ASSERT(!bst_parse_bool(S("true"), &b));
	ASSERT(!bst_parse_bool(S("yes"), &b));
	ASSERT(!bst_parse_bool(S("ON"), &b));
	ASSERT(!bst_parse_bool(S("1"), &b));
	ASSERT(!bst_parse_bool(S(""), &b));

	size_t idx = 99;
	ASSERT(bst_parse_enum(S("tx"), ev_ktls, &idx) && idx == 1);
	ASSERT(bst_parse_enum(S("tx+rx"), ev_ktls, &idx) && idx == 2);
	ASSERT(!bst_parse_enum(S("t"), ev_ktls, &idx));
	ASSERT(!bst_parse_enum(S("TX"), ev_ktls, &idx));
	ASSERT(!bst_parse_enum(S(""), ev_ktls, &idx));

	int64_t i;
	ASSERT(bst_parse_int(S("503"), 100, 599, &i) && i == 503);
	ASSERT(bst_parse_int(S("-5"), -10, 10, &i) && i == -5);
	ASSERT(!bst_parse_int(S("600"), 100, 599, &i));
	ASSERT(!bst_parse_int(S("99999999999999999999"), INT64_MIN, INT64_MAX, &i));
	ASSERT(bst_parse_int(S("-9223372036854775808"), INT64_MIN, INT64_MAX, &i) &&
	       i == INT64_MIN);
	ASSERT(!bst_parse_int(S("9223372036854775808"), INT64_MIN, INT64_MAX, &i));
	ASSERT(!bst_parse_int(S("-"), -10, 10, &i));
	ASSERT(!bst_parse_int(S("+1"), -10, 10, &i));
	ASSERT(!bst_parse_int(S("1 "), -10, 10, &i));

	uint8_t p;
	ASSERT(bst_parse_percent(S("10%"), &p) && p == 10);
	ASSERT(bst_parse_percent(S("100%"), &p) && p == 100);
	ASSERT(bst_parse_percent(S("0%"), &p) && p == 0);
	ASSERT(!bst_parse_percent(S("101%"), &p));
	ASSERT(!bst_parse_percent(S("10"), &p));
	ASSERT(!bst_parse_percent(S("%"), &p));
	ASSERT(!bst_parse_percent(S("1.5%"), &p));

	bst_str val = { 0 };
	bool seen = false;
	ASSERT_EQ(bst_parse_kv(S("weight=2"), "weight=", &val, &seen), 1);
	ASSERT(seen && val.len == 1 && val.p[0] == '2');
	ASSERT_EQ(bst_parse_kv(S("weight=3"), "weight=", &val, &seen), -1); /* repeated */
	seen = false;
	ASSERT_EQ(bst_parse_kv(S("weight="), "weight=", &val, &seen), -1);  /* empty */
	ASSERT_EQ(bst_parse_kv(S("other=1"), "weight=", &val, &seen), 0);
	ASSERT_EQ(bst_parse_kv(S("weigh"), "weight=", &val, &seen), 0);
	ASSERT_EQ(bst_parse_kv(S("weight"), "weight=", &val, &seen), 0);
	ASSERT_EQ(bst_parse_kv(S("weight=a=b"), "weight=", &val, &seen), 1);
	ASSERT(val.len == 3);
}

/* ---- Validation ---- */

TEST(unknown_directive_suggestion)
{
	ASSERT_EQ(validate("server { location / { proxi up; } }"), -1);
	ASSERT(has("unknown directive \"proxi\""));
	ASSERT(has("did you mean \"proxy\"?"));
	ASSERT_STR(E.file, "t.conf");
	ASSERT_EQ(E.line, 1);
	ASSERT_EQ(E.col, 23);

	/* Nothing close: no suggestion. */
	ASSERT_EQ(validate("server { frobnicate_widgets 1; }"), -1);
	ASSERT(has("unknown directive \"frobnicate_widgets\""));
	ASSERT(!has("did you mean"));

	/* Distance 3 is too far. */
	ASSERT_EQ(validate("server { prxyyyy a; }"), -1);
	ASSERT(!has("did you mean"));

	/* Distance 2: still suggested. */
	ASSERT_EQ(validate("server { lisen 80; }"), -1);
	ASSERT(has("did you mean \"listen\"?"));
}

TEST(suggestion_tie_is_deterministic)
{
	/* "tls_cert" and "tls_cer" style ties: "rooa" is distance 1 from "root" only; here
	 * "serve" is distance 1 from "server" (global) and nothing else in global. */
	ASSERT_EQ(validate("serve { }"), -1);
	ASSERT(has("did you mean \"server\"?"));
	/* workers/worker_memory both within range of nothing; ensure a stable pick among
	 * equals: "wirkers" -> workers (1) beats others. */
	ASSERT_EQ(validate("wirkers 4;"), -1);
	ASSERT(has("did you mean \"workers\"?"));
}

TEST(wrong_context)
{
	ASSERT_EQ(validate("upstream api { root /x; }"), -1);
	ASSERT(has("\"root\""));
	ASSERT(has("upstream"));
	ASSERT(has("valid in: server, location"));
	ASSERT_EQ(E.line, 1);
	ASSERT_EQ(E.col, 16);
	/* Top level uses the context name "global". */
	ASSERT_EQ(validate("root /x;"), -1);
	ASSERT(has("not valid in global"));
	ASSERT(has("valid in: server, location"));
}

TEST(duplicate_scalar)
{
	ASSERT_EQ(validate("server {\n  root /a;\n  root /b;\n}"), -1);
	ASSERT(has("duplicate"));
	ASSERT(has("\"root\""));
	ASSERT_EQ(E.line, 3);
	ASSERT_EQ(E.col, 3);
	ASSERT(has("t.conf:2:3")); /* first location */
	/* Same name in sibling scopes is fine. */
	ASSERT_EQ(validate("server { root /a; location /x { root /b; } location /y { root /c; } }"), 0);
	/* Repeatable directives may repeat. */
	ASSERT_EQ(validate("server { listen 80; listen 443; }"), 0);
	/* Same scalar in two different server blocks is fine. */
	ASSERT_EQ(validate("server { root /a; } server { root /b; }"), 0);
	/* Duplicate across includes-like interleaving with a block between. */
	ASSERT_EQ(validate("server { root /a; location / { } root /b; }"), -1);
}

TEST(example_shapes)
{
	ASSERT_EQ(validate(
		"tcp_profile edge {\n  keepalive idle=60s interval=10s count=4;\n}\n"
		"upstream api {\n  retry attempts=2 budget=10% on=connect_error,502,503,504;\n"
		"  server 10.0.0.1:8080 weight=2;\n  server backend.internal:8080 resolve;\n}\n"
		"limit_zone per_ip { key $remote_addr; rate 100/s burst=200; }\n"
		"limit_zone strict_login { key $remote_addr; rate 5/m burst=10; }\n"
		"log_format main json { }\n"
		"server {\n  listen 443 tls http2 http3 tcp_profile=edge;\n  listen 80 redirect_https;\n"
		"  tls_cert /etc/b/example.crt /etc/b/example.key;\n"
		"  location / { root /var/www; try_files $uri $uri/ /index.html; }\n"
		"  location ^~ /assets/ { root /var/www; }\n"
		"  location ~ \"^/old/(.+)$\" { proxy api; }\n"
		"}\n"), 0);
	if (E.msg[0])
		printf("# %s\n", E.msg);
	ASSERT_EQ(validate("workers auto; worker_memory 2g; overload_retry_after 5s;"
			   "xdp { mode auto; allow 10.0.0.0/8; allow ::1/128; }"
			   "io { uring_sqpoll off; }"), 0);
	ASSERT_EQ(validate("tls_profile modern { ktls tx require; }"), 0);
	ASSERT_EQ(validate("tls_profile modern { ktls tx; }"), 0);
}

TEST(arg_errors)
{
	ASSERT_EQ(validate("worker_memory 1x;"), -1);
	ASSERT(has("size"));
	ASSERT_EQ(E.col, 15);
	ASSERT_EQ(validate("overload_retry_after 5;"), -1);
	ASSERT(has("duration"));
	ASSERT_EQ(validate("overload_status 700;"), -1);
	ASSERT(has("100"));
	ASSERT_EQ(validate("xdp { mode fast; }"), -1);
	ASSERT(has("auto, native, generic"));
	ASSERT_EQ(validate("xdp { allow 10.0.0.1/8; }"), -1);
	ASSERT_EQ(validate("io { uring_sqpoll true; }"), -1);
	ASSERT(has("on or off"));
	ASSERT_EQ(validate("workers;"), -1);
	ASSERT(has("at least 1"));
	ASSERT_EQ(validate("workers 1 2;"), -1);
	ASSERT(has("at most 1"));
	ASSERT_EQ(validate("workers 4 { }"), -1);
	ASSERT(has("does not take a block"));
	ASSERT_EQ(validate("server;"), -1);
	ASSERT(has("requires a block"));
	ASSERT_EQ(validate("tls_profile m { ktls tx require require; }"), -1);
	ASSERT_EQ(validate("tls_profile m { ktls require; }"), -1);
}

TEST(option_errors)
{
	ASSERT_EQ(validate("tcp_profile e { keepalive idle=60s idle=1s; }"), -1);
	ASSERT(has("repeated"));
	ASSERT_EQ(validate("tcp_profile e { keepalive idle=; }"), -1);
	ASSERT(has("empty"));
	ASSERT_EQ(validate("tcp_profile e { keepalive interval=1s; }"), -1);
	ASSERT(has("idle="));
	ASSERT_EQ(validate("tcp_profile e { keepalive idle=60; }"), -1);
	ASSERT(has("duration"));
	ASSERT_EQ(validate("tcp_profile e { keepalive idle=1s count=0; }"), -1);
	ASSERT_EQ(validate("tcp_profile e { keepalive idle=1s stray; }"), -1);
	ASSERT(has("at most 0"));
	ASSERT_EQ(validate("upstream u { retry budget=200%; }"), -1);
	ASSERT_EQ(validate("limit_zone z { rate 0/s; }"), -1);
}

TEST(variables)
{
	/* A bare variable is fine in a template position. */
	ASSERT_EQ(validate("limit_zone z { key $remote_addr; }"), 0);
	/* But not in a typed position, and never silently. */
	ASSERT_EQ(validate("worker_memory $mem;"), -1);
	ASSERT(has("variable"));
	ASSERT_EQ(validate("server { root $docroot; }"), -1);
	ASSERT(has("variable"));
	ASSERT_EQ(validate("server { root \"/srv/$host\"; }"), -1);
	ASSERT(has("variable"));
	/* In a typed option value too. */
	ASSERT_EQ(validate("tcp_profile e { keepalive idle=$x; }"), -1);
	/* Raw single quotes are literal; a trailing regex $ is not a variable. */
	ASSERT_EQ(validate("server { root '/srv/$host'; }"), 0);
	ASSERT_EQ(validate("server { location ~ \"^/a$\" { } }"), 0);
}

TEST(env_dollar_is_not_a_variable)
{
	/* The parser doubles $ from env values in tpl, so env data in a plain string
	 * position is not mistaken for a variable. */
	setenv("BST_T_DOLLAR", "/srv/$host", 1);
	ASSERT_EQ(validate("server { root ${BST_T_DOLLAR}; }"), 0);
	unsetenv("BST_T_DOLLAR");
}

TEST(deep_nesting_is_iterative)
{
	char buf[4096];
	size_t n = 0;
	n += (size_t)snprintf(buf + n, sizeof buf - n, "server {");
	for (int i = 0; i < 60; i++)
		n += (size_t)snprintf(buf + n, sizeof buf - n, " location /a {");
	for (int i = 0; i < 60; i++)
		n += (size_t)snprintf(buf + n, sizeof buf - n, " }");
	snprintf(buf + n, sizeof buf - n, " }");
	ASSERT_EQ(validate(buf), 0);
}

TEST(many_siblings_are_linear)
{
	/* 50k repeated scalars: the duplicate is found at the second, and 50k repeatable
	 * siblings validate quickly (no per-sibling rescans). */
	size_t cap = 50000 * 14 + 64;
	char *buf = malloc(cap);
	ASSERT(buf != NULL);
	size_t n = (size_t)snprintf(buf, cap, "server {");
	for (int i = 0; i < 50000; i++)
		n += (size_t)snprintf(buf + n, cap - n, " listen 80;");
	snprintf(buf + n, cap - n, " }");
	int rc = validate(buf);
	free(buf);
	ASSERT_EQ(rc, 0);
}

/* ---- Table integrity ---- */

TEST(all_directives_documented)
{
	bst_err e;
	const bst_schema *sc = bst_schema_registry(&e);
	ASSERT(sc != NULL);
	size_t ntabs;
	const bst_dirtab *const *tabs = bst_dirtabs(&ntabs);
	ASSERT(ntabs >= 3);
	size_t total = 0;
	for (size_t t = 0; t < ntabs; t++) {
		for (size_t i = 0; i < tabs[t]->n; i++) {
			const bst_directive *d = &tabs[t]->dirs[i];
			ASSERT(d->name != NULL && d->name[0] != 0);
			ASSERT(d->doc != NULL && d->doc[0] != 0);
			ASSERT(bst_directive_check(d, &e) == 0);
			total++;
		}
	}
	ASSERT_EQ(total, 28); /* all three tables registered */
}

TEST(integrity_failures)
{
	bst_err e;
	bst_directive d = { .name = "x", .contexts = BST_CTX_GLOBAL, .doc = "d",
			    .args = { .min_args = 1, .max_args = 1, .pos = { STR } } };
	bst_dirtab tab = { &d, 1 };
	const bst_dirtab *tabs[] = { &tab };

	bst_schema *s = bst_schema_build(tabs, 1, &e);
	ASSERT(s != NULL);
	bst_schema_free(s);

	d.doc = "";
	ASSERT(bst_schema_build(tabs, 1, &e) == NULL);
	ASSERT(strstr(e.msg, "doc") != NULL);
	d.doc = NULL;
	ASSERT(bst_schema_build(tabs, 1, &e) == NULL);
	d.doc = "d";

	d.default_value = "a b"; /* two args, max is one */
	ASSERT(bst_schema_build(tabs, 1, &e) == NULL);
	ASSERT(strstr(e.msg, "default") != NULL);
	d.default_value = NULL;

	d.args.pos[0].kind = BST_T_SIZE;
	d.default_value = "12x";
	ASSERT(bst_schema_build(tabs, 1, &e) == NULL);
	d.default_value = "12k";
	s = bst_schema_build(tabs, 1, &e);
	ASSERT(s != NULL);
	bst_schema_free(s);
	d.default_value = NULL;

	d.contexts = 0;
	ASSERT(bst_schema_build(tabs, 1, &e) == NULL);
	d.contexts = BST_CTX_GLOBAL;

	d.args.pos[0].kind = BST_T_ENUM; /* no value list */
	ASSERT(bst_schema_build(tabs, 1, &e) == NULL);
	d.args.pos[0].kind = BST_T_STRING;

	d.args.block = BST_BLOCK_OPTIONAL; /* block without a child context */
	ASSERT(bst_schema_build(tabs, 1, &e) == NULL);
	d.args.block = BST_BLOCK_FORBIDDEN;
	d.child_ctx = BST_CTX_SERVER; /* child context without a block */
	ASSERT(bst_schema_build(tabs, 1, &e) == NULL);
}

TEST(duplicate_names_overlapping_contexts)
{
	bst_err e;
	bst_directive a[2] = {
		{ .name = "dup", .contexts = BST_CTX_SERVER | BST_CTX_LOCATION, .doc = "a",
		  .args = { .min_args = 1, .max_args = 1, .pos = { STR } } },
		{ .name = "dup", .contexts = BST_CTX_LOCATION | BST_CTX_UPSTREAM, .doc = "b",
		  .args = { .min_args = 1, .max_args = 1, .pos = { STR } } },
	};
	bst_dirtab t1 = { &a[0], 1 }, t2 = { &a[1], 1 };
	const bst_dirtab *tabs[] = { &t1, &t2 };
	ASSERT(bst_schema_build(tabs, 2, &e) == NULL);
	ASSERT(strstr(e.msg, "dup") != NULL);
	ASSERT(strstr(e.msg, "location") != NULL);

	/* Disjoint contexts are fine. */
	a[1].contexts = BST_CTX_UPSTREAM;
	bst_schema *s = bst_schema_build(tabs, 2, &e);
	ASSERT(s != NULL);
	ASSERT(bst_schema_find(s, "dup", 3, BST_CTX_SERVER) == &a[0]);
	ASSERT(bst_schema_find(s, "dup", 3, BST_CTX_UPSTREAM) == &a[1]);
	ASSERT(bst_schema_find(s, "dup", 3, BST_CTX_GLOBAL) == NULL);
	ASSERT(bst_schema_find(s, "du", 2, BST_CTX_SERVER) == NULL);
	ASSERT(bst_schema_find(s, "dupx", 4, BST_CTX_SERVER) == NULL);
	bst_schema_free(s);

	/* Same table twice (or within one table) also collides. */
	bst_directive b[2] = { a[0], a[0] };
	bst_dirtab t3 = { b, 2 };
	const bst_dirtab *tabs3[] = { &t3 };
	ASSERT(bst_schema_build(tabs3, 1, &e) == NULL);
}

TEST(registry_is_built_once_and_clean)
{
	bst_err e;
	const bst_schema *a = bst_schema_registry(&e);
	const bst_schema *b = bst_schema_registry(&e);
	ASSERT(a != NULL && a == b);
	ASSERT(bst_schema_find(a, "root", 4, BST_CTX_LOCATION) != NULL);
	ASSERT(bst_schema_find(a, "root", 4, BST_CTX_UPSTREAM) == NULL);
}

TEST(context_names)
{
	ASSERT_STR(bst_ctx_name(BST_CTX_GLOBAL), "global");
	ASSERT_STR(bst_ctx_name(BST_CTX_TCP_PROFILE), "tcp_profile");
	ASSERT_STR(bst_ctx_name(BST_CTX_ACME), "acme");
	ASSERT_STR(bst_ctx_name(BST_CTX_SERVER | BST_CTX_LOCATION), "?");
	ASSERT_STR(bst_ctx_name(0), "?");
}

TAP_MAIN()

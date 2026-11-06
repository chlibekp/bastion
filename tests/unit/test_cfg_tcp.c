/* tcp_profile blocks, the listen tcp_profile= option and the post hook that resolves it. */
#include "config/compile.h"
#include "config/parser.h"
#include "core/arena.h"
#include "io/tcp_profile.h"
#include "tap.h"

#include <stdlib.h>
#include <string.h>

static bst_arena *LAST;
static bst_err E;

/* The AST stays alive until the next call, so E.file (which points into it) is readable. */
static bst_config *compile(const char *text)
{
	bst_arena_free(LAST);
	LAST = bst_arena_new(1 << 16);
	memset(&E, 0, sizeof E);
	bst_ast *ast = bst_cfg_parse_string(text, strlen(text), "t.conf", NULL, LAST, &E);
	return ast ? bst_cfg_compile(ast, &E) : NULL;
}

static bool err_has(const char *needle)
{
	return strstr(E.msg, needle) != NULL;
}

#define HAS(p, o) (((p)->set >> (o)) & 1u)
#define REQ(p, o) (((p)->require >> (o)) & 1u)

TEST(profile_values_from_the_example)
{
	bst_config *c = compile("tcp_profile edge {\n"
				"  fastopen 4096; defer_accept 5s; busy_poll 50us; prefer_busy_poll on;\n"
				"  congestion bbr; notsent_lowat 128k; user_timeout 30s;\n"
				"  keepalive idle=60s interval=10s count=4; steering incoming_cpu;\n"
				"  backlog 65535;\n}\n"
				"server { listen 8080 tcp_profile=edge; }\n");
	ASSERT(c != NULL);
	ASSERT_EQ(c->global.ntcp_profiles, 1);
	const bst_tcp_profile *p = c->global.tcp_profiles[0];
	ASSERT_STR(p->name, "edge");
	ASSERT_EQ(p->fastopen, 4096);
	ASSERT_EQ(p->defer_accept_s, 5);
	ASSERT_EQ(p->busy_poll_us, 50);
	ASSERT(p->prefer_busy_poll);
	ASSERT_STR(p->congestion, "bbr");
	ASSERT_EQ(p->notsent_lowat, 128 * 1024);
	ASSERT_EQ(p->user_timeout_ms, 30000);
	ASSERT_EQ(p->ka_idle_s, 60);
	ASSERT_EQ(p->ka_interval_s, 10);
	ASSERT_EQ(p->ka_count, 4);
	ASSERT_EQ(p->steering, BST_STEER_INCOMING_CPU);
	ASSERT_EQ(p->backlog, 65535);
	ASSERT(HAS(p, BST_TCP_FASTOPEN) && HAS(p, BST_TCP_CONGESTION) && HAS(p, BST_TCP_KEEPALIVE));
	ASSERT(!HAS(p, BST_TCP_RCVBUF) && !HAS(p, BST_TCP_FASTOPEN_KEY));
	ASSERT_EQ(p->require, 0);
	/* the listener points at the very profile */
	ASSERT(c->global.servers[0]->listens[0].tcp == p);
	bst_config_free(c);
}

TEST(profile_every_directive_and_require)
{
	bst_config *c = compile(
		"tcp_profile all {\n"
		"  fastopen 10 require; fastopen_key 000102030405060708090a0b0c0d0e0f require;\n"
		"  defer_accept 1s require; busy_poll 10us require; prefer_busy_poll off require;\n"
		"  busy_poll_budget 64 require; nodelay off require; quickack off require;\n"
		"  congestion cubic require; notsent_lowat 16k require; user_timeout 5s require;\n"
		"  keepalive idle=30s interval=5s count=3 require; rcvbuf 256k require;\n"
		"  sndbuf 512k require; pacing_rate 10m require; mark 7 require; freebind on require;\n"
		"  backlog 100 require; steering none require;\n}\n"
		"server { listen 8080; }\n");
	ASSERT(c != NULL);
	const bst_tcp_profile *p = c->global.tcp_profiles[0];
	for (int o = 0; o < BST_TCP_OPT_COUNT; o++) {
		ASSERT(HAS(p, o));
		ASSERT(REQ(p, o));
	}
	ASSERT_EQ(p->fastopen_key[0], 0x00);
	ASSERT_EQ(p->fastopen_key[15], 0x0f);
	ASSERT(!p->nodelay && !p->quickack && !p->prefer_busy_poll);
	ASSERT_EQ(p->busy_poll_budget, 64);
	ASSERT_EQ(p->rcvbuf, 256 * 1024);
	ASSERT_EQ(p->sndbuf, 512 * 1024);
	ASSERT_EQ(p->pacing_rate, 10u << 20);
	ASSERT_EQ(p->mark, 7);
	ASSERT(p->freebind);
	ASSERT_EQ(p->steering, BST_STEER_NONE);
	bst_config_free(c);
}

TEST(profile_block_gets_documented_defaults)
{
	bst_config *c = compile("tcp_profile e { }\nserver { listen 8080; }\n");
	ASSERT(c != NULL);
	bst_tcp_profile d;
	bst_tcp_profile_defaults(&d, "e");
	const bst_tcp_profile *p = c->global.tcp_profiles[0];
	ASSERT(p->nodelay && HAS(p, BST_TCP_NODELAY));
	ASSERT_EQ(p->backlog, BST_TCP_DEFAULT_BACKLOG);
	ASSERT_EQ(p->set, d.set);
	ASSERT_EQ(p->require, 0);
	bst_config_free(c);
}

TEST(listener_without_profile_gets_the_default)
{
	bst_config *c = compile("tcp_profile edge { fastopen 1; }\nserver { listen 8080; listen 9090; }\n");
	ASSERT(c != NULL);
	const bst_tcp_profile *d = &c->global.tcp_default;
	ASSERT_STR(d->name, "default");
	ASSERT(d->nodelay && HAS(d, BST_TCP_NODELAY));
	ASSERT_EQ(d->backlog, BST_TCP_DEFAULT_BACKLOG);
	ASSERT(!HAS(d, BST_TCP_FASTOPEN));
	ASSERT(c->global.servers[0]->listens[0].tcp == d);
	ASSERT(c->global.servers[0]->listens[1].tcp == d);
	bst_config_free(c);
}

TEST(profile_defined_after_use_resolves)
{
	bst_config *c = compile("server { listen 8080 tcp_profile=late; }\n"
				"tcp_profile other { }\ntcp_profile late { fastopen 7; }\n");
	ASSERT(c != NULL);
	const bst_tcp_profile *p = c->global.servers[0]->listens[0].tcp;
	ASSERT(p != NULL);
	ASSERT_STR(p->name, "late");
	ASSERT_EQ(p->fastopen, 7);
	bst_config_free(c);
}

TEST(undefined_profile_is_positioned_with_suggestion)
{
	bst_config *c = compile("tcp_profile edge { }\nserver {\n  listen 8080 tcp_profile=edgee;\n}\n");
	ASSERT(c == NULL);
	ASSERT(err_has("undefined tcp_profile \"edgee\""));
	ASSERT(err_has("did you mean \"edge\"?"));
	ASSERT_STR(E.file, "t.conf");
	ASSERT_EQ(E.line, 3);
	c = compile("server { listen 8080 tcp_profile=nope; }\n");
	ASSERT(c == NULL);
	ASSERT(err_has("undefined tcp_profile \"nope\""));
	ASSERT(!err_has("did you mean"));
	ASSERT_EQ(E.line, 1);
}

TEST(duplicate_profile_name_is_an_error)
{
	bst_config *c = compile("tcp_profile edge { }\nserver { listen 1; }\ntcp_profile edge { }\n");
	ASSERT(c == NULL);
	ASSERT(err_has("duplicate tcp_profile \"edge\""));
	ASSERT_STR(E.file, "t.conf");
	ASSERT_EQ(E.line, 3);
}

TEST(steering_ebpf_is_not_supported_yet)
{
	bst_config *c = compile("tcp_profile e { steering ebpf; }\nserver { listen 1; }\n");
	ASSERT(c == NULL);
	ASSERT(err_has("not supported yet"));
	ASSERT_EQ(E.line, 1);
	c = compile("tcp_profile e { steering sideways; }\nserver { listen 1; }\n");
	ASSERT(c == NULL); /* anything else is an ordinary enum error */
	ASSERT(err_has("expected one of"));
}

TEST(fastopen_key_format_and_length)
{
	const char *bad[] = {
		"00", "000102030405060708090a0b0c0d0e0", "000102030405060708090a0b0c0d0e0f00",
		"zz0102030405060708090a0b0c0d0e0f", "00010203-04050607-08090a0b-0c0d0e0",
		"00010203-04050607-08090a0b", "0001020304050607-08090a0b-0c0d0e0f",
	};
	for (size_t i = 0; i < sizeof bad / sizeof bad[0]; i++) {
		char text[200];
		snprintf(text, sizeof text, "tcp_profile e { fastopen_key %s; }\nserver { listen 1; }\n",
			 bad[i]);
		ASSERT(compile(text) == NULL);
		ASSERT(err_has("fastopen_key"));
		ASSERT_EQ(E.line, 1);
	}
	/* 32 hex digits, or the kernel's sysctl form: four dash-separated groups of 8 */
	bst_config *c = compile("tcp_profile e { fastopen_key 00010203-04050607-08090A0B-0c0d0e0f; }\n"
				"server { listen 1; }\n");
	ASSERT(c != NULL);
	const bst_tcp_profile *p = c->global.tcp_profiles[0];
	ASSERT_EQ(p->fastopen_key[0], 0x00);
	ASSERT_EQ(p->fastopen_key[10], 0x0a);
	ASSERT_EQ(p->fastopen_key[15], 0x0f);
	bst_config_free(c);
}

TEST(ranges_and_shapes_are_rejected_by_the_schema)
{
	const char *bad[] = {
		"busy_poll 0us", "busy_poll 2s", "defer_accept 0s", "defer_accept 2h", "backlog 0",
		"backlog 70000", "fastopen 0", "keepalive idle=60s interval=10s",
		"keepalive idle=0s interval=10s count=4", "keepalive idle=60s interval=10s count=200",
		"keepalive 60", "congestion \"two words\"", "congestion averyveryverylongname",
		"congestion BBR", "user_timeout 0s", "rcvbuf 10", "nodelay maybe", "bogus 1",
		"mark 0", "pacing_rate 0",
	};
	for (size_t i = 0; i < sizeof bad / sizeof bad[0]; i++) {
		char text[200];
		snprintf(text, sizeof text, "tcp_profile e { %s; }\nserver { listen 1; }\n", bad[i]);
		ASSERT(compile(text) == NULL);
		ASSERT_EQ(E.line, 1);
	}
	ASSERT(compile("tcp_profile e { backlog 1; backlog 2; }\nserver { listen 1; }\n") == NULL);
	ASSERT(err_has("duplicate"));
}

TEST(one_socket_one_profile_per_address)
{
	/* Servers that differ by name share the socket of an address: the profile they name must
	 * agree, and a listen that names none takes the one that is named. */
	bst_config *c = compile("tcp_profile a { fastopen 1; }\ntcp_profile b { fastopen 2; }\n"
				"server { name x; listen 8080; }\n"
				"server { name y; listen 8080 tcp_profile=a; }\n"
				"server { name z; listen 8080 tcp_profile=a; }\n"
				"server { name w; listen 9090; }\n");
	ASSERT(c != NULL);
	ASSERT_STR(c->global.servers[0]->listens[0].tcp->name, "a"); /* inherited */
	ASSERT_STR(c->global.servers[2]->listens[0].tcp->name, "a");
	ASSERT(c->global.servers[3]->listens[0].tcp == &c->global.tcp_default);
	bst_config_free(c);
	c = compile("tcp_profile a { }\ntcp_profile b { }\n"
		    "server { name x; listen 8080 tcp_profile=a; }\n"
		    "server { name y;\n  listen 8080 tcp_profile=b; }\n");
	ASSERT(c == NULL);
	ASSERT(err_has("names tcp_profile \"b\" but the first listen on that address (t.conf:3:"));
	ASSERT(err_has("names \"a\""));
	ASSERT_EQ(E.line, 5); /* the offending listen, not the first one */
	/* the same name twice is no conflict, and different addresses never conflict */
	c = compile("tcp_profile a { }\ntcp_profile b { }\n"
		    "server { name x; listen 8080 tcp_profile=a; listen 8081 tcp_profile=b; }\n"
		    "server { name y; listen 8080 tcp_profile=a; }\n");
	ASSERT(c != NULL);
	bst_config_free(c);
}

TEST(tcp_profile_is_global_only)
{
	ASSERT(compile("server { listen 1; tcp_profile e { } }\n") == NULL);
	ASSERT(compile("tcp_profile { }\nserver { listen 1; }\n") == NULL);
}

TAP_MAIN()

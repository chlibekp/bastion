/* limits { } directives and the admission counters (io/admission.h). The descriptor-limit shed
 * runs here on a real listening socket; the whole path (EMFILE, pause, recovery) is
 * tests/integration/test_overload.py. */
#include "config/compile.h"
#include "config/parser.h"
#include "core/arena.h"
#include "io/admission.h"
#include "io/loop.h"
#include "tap.h"

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

typedef struct {
	bst_arena *a;
	bst_config *cfg;
	bst_err e;
} conf;

static bool compile(conf *c, const char *limits_text)
{
	char text[1024];
	snprintf(text, sizeof text, "%sserver { listen 8080; }\n", limits_text);
	c->a = bst_arena_new(1 << 16);
	c->e = (bst_err){.msg = ""};
	bst_ast *ast = bst_cfg_parse_string(text, strlen(text), "t.conf", NULL, c->a, &c->e);
	c->cfg = ast ? bst_cfg_compile(ast, &c->e) : NULL;
	return c->cfg != NULL;
}

static void conf_free(conf *c)
{
	bst_config_free(c->cfg);
	bst_arena_free(c->a);
}

TEST(limits_defaults_without_block)
{
	conf c;
	ASSERT(compile(&c, ""));
	const bst_cfg_limits *l = &c.cfg->global.limits;
	ASSERT_EQ(l->max_connections, 10240);
	ASSERT_EQ(l->worker_memory, 1ll << 30);
	ASSERT_EQ(l->overload_status, 503);
	ASSERT_EQ(l->overload_retry_after, 1);
	ASSERT_EQ(l->reserve_fds, 1);
	ASSERT_EQ(l->accept_backoff_ms, 100);
	conf_free(&c);
}

TEST(limits_values_are_read)
{
	conf c;
	ASSERT(compile(&c, "limits { max_connections 50; worker_memory 64m; overload_status 429;"
			   " overload_retry_after 90s; reserve_fds 3; accept_backoff 250ms; }\n"));
	const bst_cfg_limits *l = &c.cfg->global.limits;
	ASSERT_EQ(l->max_connections, 50);
	ASSERT_EQ(l->worker_memory, 64ll << 20);
	ASSERT_EQ(l->overload_status, 429);
	ASSERT_EQ(l->overload_retry_after, 90);
	ASSERT_EQ(l->reserve_fds, 3);
	ASSERT_EQ(l->accept_backoff_ms, 250);
	conf_free(&c);
	ASSERT(compile(&c, "limits { overload_retry_after 1500ms; }\n")); /* rounded up to seconds */
	ASSERT_EQ(c.cfg->global.limits.overload_retry_after, 2);
	conf_free(&c);
}

TEST(limits_rejects_bad_values)
{
	const char *bad[] = {"limits { max_connections 0; }", "limits { worker_memory 1k; }",
			     "limits { overload_status 200; }", "limits { overload_status 600; }",
			     "limits { overload_retry_after 0s; }", "limits { reserve_fds 0; }",
			     "limits { reserve_fds 65; }", "limits { accept_backoff 0ms; }",
			     "limits { }\nlimits { }"};
	for (unsigned i = 0; i < sizeof bad / sizeof bad[0]; i++) {
		conf c;
		bool ok = compile(&c, bad[i]);
		if (ok)
			conf_free(&c);
		else
			bst_arena_free(c.a);
		if (ok)
			TAP_FAIL_("accepted: %s", bad[i]);
	}
}

/* ---- admission ---- */

typedef struct {
	bst_loop *loop;
	bst_cfg_limits lim;
	bst_admission adm;
} fixture;

static bool setup(fixture *f, unsigned max_conn, size_t memory, unsigned reserve)
{
	bst_err e = {.msg = ""};
	bst_loop_cfg lc = {.backend = BST_BACKEND_EPOLL};
	f->loop = bst_loop_new(&lc, &e);
	if (f->loop == NULL)
		return false;
	f->lim = (bst_cfg_limits){.max_connections = max_conn, .worker_memory = memory,
				  .overload_status = 503, .overload_retry_after = 1,
				  .reserve_fds = reserve, .accept_backoff_ms = 100};
	bst_adm_init(&f->adm, &f->lim, f->loop, 0);
	return true;
}

static void teardown(fixture *f)
{
	for (unsigned i = 0; i < f->lim.reserve_fds; i++)
		if (f->adm.reserve[i] >= 0)
			close(f->adm.reserve[i]);
	bst_loop_free(f->loop);
}

TEST(admit_stops_at_max_connections_and_counts)
{
	fixture f;
	ASSERT(setup(&f, 3, 1 << 20, 1));
	ASSERT(bst_adm_admit(&f.adm, 0));
	ASSERT(bst_adm_admit(&f.adm, 2));
	ASSERT(!bst_adm_admit(&f.adm, 3));
	ASSERT(!bst_adm_admit(&f.adm, 4));
	ASSERT_EQ(atomic_load(&f.adm.closed), 2);
	ASSERT(bst_adm_admit(&f.adm, 2)); /* recovers on its own: nothing latched */
	teardown(&f);
}

TEST(memory_budget_refuses_past_the_cap_and_recovers)
{
	fixture f;
	ASSERT(setup(&f, 10, 1 << 20, 1));
	ASSERT(bst_adm_mem_charge(&f.adm, 600000));
	ASSERT(!bst_adm_overloaded(&f.adm));
	ASSERT(!bst_adm_mem_charge(&f.adm, 600000)); /* refused, and nothing was charged */
	ASSERT_EQ(atomic_load(&f.adm.mem_used), 600000);
	ASSERT(bst_adm_mem_charge(&f.adm, (1 << 20) - 600000)); /* exactly the cap */
	ASSERT(bst_adm_overloaded(&f.adm));
	ASSERT(!bst_adm_mem_charge(&f.adm, 1));
	bst_adm_mem_release(&f.adm, 600000);
	ASSERT(!bst_adm_overloaded(&f.adm));
	ASSERT(bst_adm_mem_charge(&f.adm, 1));
	teardown(&f);
}

TEST(memory_charge_cannot_overflow)
{
	fixture f;
	ASSERT(setup(&f, 10, 1 << 20, 1));
	ASSERT(!bst_adm_mem_charge(&f.adm, (size_t)-1));
	ASSERT_EQ(atomic_load(&f.adm.mem_used), 0);
	teardown(&f);
}

TEST(refused_requests_are_counted)
{
	fixture f;
	ASSERT(setup(&f, 10, 1 << 20, 1));
	bst_adm_refused(&f.adm);
	bst_adm_refused(&f.adm);
	ASSERT_EQ(atomic_load(&f.adm.refused), 2);
	teardown(&f);
}

TEST(reserve_is_held_and_shed_closes_queued_connections)
{
	fixture f;
	ASSERT(setup(&f, 10, 1 << 20, 2));
	ASSERT(f.adm.reserve[0] >= 0 && f.adm.reserve[1] >= 0 && f.adm.reserve[2] < 0);

	int ls = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
	struct sockaddr_in a = {.sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
	socklen_t al = sizeof a;
	ASSERT(ls >= 0 && bind(ls, (void *)&a, sizeof a) == 0 && listen(ls, 8) == 0);
	ASSERT(getsockname(ls, (void *)&a, &al) == 0);
	int cl[3];
	for (int i = 0; i < 3; i++) {
		cl[i] = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
		ASSERT(connect(cl[i], (void *)&a, sizeof a) == 0);
	}
	ASSERT_EQ(bst_adm_shed_fds(&f.adm, ls), 3);
	ASSERT_EQ(atomic_load(&f.adm.fd_closed), 3);
	ASSERT(f.adm.reserve[0] >= 0 && f.adm.reserve[1] >= 0); /* taken back */
	for (int i = 0; i < 3; i++) {
		char b;
		ASSERT_EQ(recv(cl[i], &b, 1, 0), 0); /* closed by the worker's side, not left waiting */
		close(cl[i]);
	}
	ASSERT_EQ(bst_adm_shed_fds(&f.adm, ls), 0); /* nothing queued: no count */
	close(ls);
	teardown(&f);
}

TAP_MAIN()

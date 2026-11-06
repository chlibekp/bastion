/* io { } directives, the loop config built from them, and runtime backend selection. */
#include "config/compile.h"
#include "config/parser.h"
#include "core/arena.h"
#include "core/counters.h"
#include "core/log.h"
#include "io/aio.h"
#include "io/backend.h"
#include "io/loop.h"
#include "tap.h"

#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static const char *SRV = "server { listen 8080; }\n";

typedef struct {
	bst_arena *a;
	bst_config *cfg;
	bst_err e;
} conf;

static bool compile(conf *c, const char *io_text)
{
	char text[1024];
	snprintf(text, sizeof text, "%s%s", io_text, SRV);
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

static size_t nwarn(const conf *c)
{
	size_t n;
	(void)bst_config_warnings(c->cfg, &n);
	return n;
}

static const char *warn0(const conf *c)
{
	size_t n;
	const bst_cfg_warning *w = bst_config_warnings(c->cfg, &n);
	return n ? w[0].msg : "";
}

TEST(io_defaults_without_block)
{
	conf c;
	ASSERT(compile(&c, ""));
	bst_loop_cfg lc;
	bst_io_loop_cfg(c.cfg, &lc);
	ASSERT_EQ(lc.backend, BST_BACKEND_AUTO);
	ASSERT_EQ(lc.uring_entries, 256);
	ASSERT_EQ(lc.uring_bufs, 256);
	ASSERT_EQ(lc.uring_sqpoll, 0);
	ASSERT_EQ(lc.uring_napi, 0);
	ASSERT_EQ(lc.uring_send_zc_min, 0);
	ASSERT(lc.aio_threads >= 1 && lc.aio_threads <= BST_AIO_THREADS_AUTO_MAX);
	ASSERT(lc.aio_queue >= 1);
	ASSERT_EQ(nwarn(&c), 0);
	conf_free(&c);
}

TEST(io_values_reach_loop_cfg)
{
	conf c;
	ASSERT(compile(&c, "io { backend epoll; uring_entries 1024; uring_bufs 64; uring_sqpoll 50ms;"
			   " uring_napi on; uring_send_zc_min 16k; aio_threads 3; aio_queue 99; }\n"));
	bst_loop_cfg lc;
	bst_io_loop_cfg(c.cfg, &lc);
	ASSERT_EQ(lc.backend, BST_BACKEND_EPOLL);
	ASSERT_EQ(lc.uring_entries, 1024);
	ASSERT_EQ(lc.uring_bufs, 64);
	ASSERT_EQ(lc.uring_sqpoll, 50);
	ASSERT(lc.uring_napi > 0);
	ASSERT(!lc.uring_napi_require);
	ASSERT_EQ(lc.uring_send_zc_min, 16384);
	ASSERT_EQ(lc.aio_threads, 3);
	ASSERT_EQ(lc.aio_queue, 99);
	conf_free(&c);
	ASSERT(compile(&c, "io { uring_napi on require; uring_sqpoll off; aio_threads auto; }\n"));
	bst_io_loop_cfg(c.cfg, &lc);
	ASSERT(lc.uring_napi_require);
	ASSERT_EQ(lc.uring_sqpoll, 0);
	conf_free(&c);
}

TEST(io_rejects_bad_values)
{
	const char *bad[] = {"io { backend iouring; }", "io { uring_entries 0; }",
			     "io { uring_entries 99999999; }", "io { uring_sqpoll 0ms; }",
			     "io { aio_threads 0; }", "io { uring_napi maybe; }", "io { }\nio { }",
			     "io { uring_send_zc_min -1; }"};
	for (unsigned i = 0; i < sizeof bad / sizeof bad[0]; i++) {
		conf c;
		bool ok = compile(&c, bad[i]);
		if (ok)
			conf_free(&c);
		else
			bst_arena_free(c.a);
		ASSERT(!ok);
	}
}

TEST(io_entries_rounded_up_with_warning)
{
	conf c;
	ASSERT(compile(&c, "io { uring_entries 300; uring_bufs 100; }\n"));
	bst_loop_cfg lc;
	bst_io_loop_cfg(c.cfg, &lc);
	ASSERT_EQ(lc.uring_entries, 512);
	ASSERT_EQ(lc.uring_bufs, 128);
	ASSERT_EQ(nwarn(&c), 2);
	ASSERT(strstr(warn0(&c), "rounded up to 512") != NULL);
	conf_free(&c);
	ASSERT(compile(&c, "io { uring_entries 512; }\n"));
	ASSERT_EQ(nwarn(&c), 0);
	conf_free(&c);
}

TEST(aio_auto_is_capped)
{
	conf c;
	ASSERT(compile(&c, "io { aio_threads auto; }\n"));
	bst_loop_cfg lc;
	bst_io_loop_cfg(c.cfg, &lc);
	long cpus = sysconf(_SC_NPROCESSORS_ONLN);
	unsigned want = cpus < 1 ? 1u : (unsigned)cpus;
	if (want > BST_AIO_THREADS_AUTO_MAX)
		want = BST_AIO_THREADS_AUTO_MAX;
	ASSERT(lc.aio_threads <= BST_AIO_THREADS_AUTO_MAX);
	ASSERT(lc.aio_threads >= 1);
	(void)want;
	conf_free(&c);
}

/* ---- selection ---- */

static bst_loop *mk(bst_backend b, bst_err *e)
{
	bst_loop_cfg cfg = {.backend = b};
	return bst_loop_new(&cfg, e);
}

TEST(auto_prefers_uring)
{
	unsetenv("BST_TEST_URING_FAIL");
	bst_err e;
	bst_loop *l = mk(BST_BACKEND_AUTO, &e);
	ASSERT(l != NULL);
	ASSERT_EQ(bst_loop_backend(l), BST_BACKEND_URING);
	ASSERT(strstr(bst_loop_backend_reason(l), "SINGLE_ISSUER") != NULL);
	bst_loop_free(l);
}

static void expect_fallback(const char *spec, const char *word)
{
	setenv("BST_TEST_URING_FAIL", spec, 1);
	bst_err e;
	bst_loop *l = mk(BST_BACKEND_AUTO, &e);
	unsetenv("BST_TEST_URING_FAIL");
	ASSERT(l != NULL);
	ASSERT_EQ(bst_loop_backend(l), BST_BACKEND_EPOLL);
	if (strstr(bst_loop_backend_reason(l), word) == NULL)
		printf("# reason '%s' lacks '%s'\n", bst_loop_backend_reason(l), word);
	ASSERT(strstr(bst_loop_backend_reason(l), word) != NULL);
	bst_loop_free(l);
}

TEST(fallback_reasons_name_the_cause)
{
	expect_fallback("setup:38", "ENOSYS");
	expect_fallback("setup:1", "EPERM");
	expect_fallback("probe:95", "opcode");
}

TEST(forced_uring_failure_is_an_error)
{
	setenv("BST_TEST_URING_FAIL", "setup:1", 1);
	bst_err e = {.msg = ""};
	bst_loop *l = mk(BST_BACKEND_URING, &e);
	unsetenv("BST_TEST_URING_FAIL");
	ASSERT(l == NULL);
	ASSERT(strstr(e.msg, "uring") != NULL);
	ASSERT(strstr(e.msg, "EPERM") != NULL);
}

TEST(non_fallback_errors_do_not_hide)
{
	/* ENOMEM is not on the fallback list: auto reports it instead of quietly using epoll. */
	setenv("BST_TEST_URING_FAIL", "setup:12", 1);
	bst_err e = {.msg = ""};
	bst_loop *l = mk(BST_BACKEND_AUTO, &e);
	unsetenv("BST_TEST_URING_FAIL");
	ASSERT(l == NULL);
}

TEST(flag_ladder_steps_down_and_still_uses_uring)
{
	setenv("BST_TEST_URING_FAIL", "defer_taskrun:22", 1);
	bst_err e;
	bst_loop *l = mk(BST_BACKEND_AUTO, &e);
	unsetenv("BST_TEST_URING_FAIL");
	ASSERT(l != NULL);
	ASSERT_EQ(bst_loop_backend(l), BST_BACKEND_URING);
	const char *r = bst_loop_backend_reason(l);
	ASSERT(strstr(r, "DEFER_TASKRUN refused") != NULL);
	ASSERT(strstr(r, "SINGLE_ISSUER") != NULL);
	bst_loop_free(l);
}

TEST(napi_require_fails_and_plain_warns)
{
	setenv("BST_TEST_URING_FAIL", "napi:95", 1);
	bst_err e = {.msg = ""};
	bst_loop_cfg cfg = {.backend = BST_BACKEND_URING, .uring_napi = 50, .uring_napi_require = true};
	bst_loop *l = bst_loop_new(&cfg, &e);
	ASSERT(l == NULL);
	ASSERT(strstr(e.msg, "NAPI") != NULL);
	cfg.uring_napi_require = false;
	int nul = open("/dev/null", O_WRONLY); /* the warning is expected: keep the output clean */
	bst_log_init(nul, BST_LOG_WARN);
	l = bst_loop_new(&cfg, &e);
	bst_log_init(STDERR_FILENO, BST_LOG_WARN);
	close(nul);
	unsetenv("BST_TEST_URING_FAIL");
	ASSERT(l != NULL);
	ASSERT_EQ(bst_loop_backend(l), BST_BACKEND_URING);
	bst_loop_free(l);
}

TEST(report_line_and_metric)
{
	unsetenv("BST_TEST_URING_FAIL");
	bst_counters_reset_for_test();
	bst_err e;
	bst_loop *l = mk(BST_BACKEND_EPOLL, &e);
	ASSERT(l != NULL);
	char line[256];
	bst_io_backend_line(l, line, sizeof line);
	ASSERT(strncmp(line, "io backend: epoll (", 19) == 0);
	ASSERT(line[strlen(line) - 1] == ')');
	bst_io_backend_report(l);
	bst_counter_id id = bst_counter_register("bastion_io_backend", "x", "name=epoll");
	ASSERT_EQ(bst_counter_get(id), 1);
	bst_counter_id other = bst_counter_register("bastion_io_backend", "x", "name=uring");
	ASSERT_EQ(bst_counter_get(other), 0);
	bst_loop_free(l);
}

TAP_MAIN()

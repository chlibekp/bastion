#include "tap.h"

#include "core/counters.h"
#include "ops/metrics.h"

#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <unistd.h>

/* Values from every slot are summed; a slot's values stay after its process is gone. */
TEST(slots_sum_and_survive)
{
	bst_counters_reset_for_test();
	bst_counter_id c = bst_counter_register("x_total", "h", NULL);
	bst_gauge_set(bst_gauge_register("g", "", NULL), 3);
	bst_counters_use_slot(bst_counter_worker_slot(0));
	bst_counter_add(c, 2);
	bst_counters_use_slot(bst_counter_worker_slot(1));
	bst_counter_add(c, 5);
	bst_counters_use_slot(bst_counter_worker_slot(BST_COUNTER_WORKER_SLOTS)); /* wraps to slot 0's */
	bst_counter_add(c, 1);
	bst_counters_use_slot(BST_COUNTER_SLOT_MASTER);
	ASSERT_EQ(bst_counter_get(c), 8);
	ASSERT_EQ(bst_gauge_get(bst_gauge_register("g", "", NULL)), 3);
}

/* Moving to a shared region keeps ids handed out before, and a second image attaching the same
 * region (a reload) finds the entries and values by name. */
TEST(attach_shared_keeps_ids_and_values)
{
	bst_counters_reset_for_test();
	bst_counter_id early = bst_counter_register("early_total", "", NULL);
	bst_counter_add(early, 4);
	size_t sz = bst_counters_registry_size(), vsz = bst_counters_values_size();
	void *mem = mmap(NULL, sz, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
	void *vmem = mmap(NULL, vsz, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
	ASSERT(mem != MAP_FAILED && vmem != MAP_FAILED);
	ASSERT_EQ(bst_counters_attach_shared(mem, vmem, false), 0);
	ASSERT_EQ(bst_counter_get(early), 4);
	bst_counter_id late = bst_counter_register("late_total", "", "a=b");
	bst_counter_add(late, 1);
	bst_counter_add(early, 1);
	ASSERT_EQ(bst_counter_get(early), 5);
	/* attached again (a re-run): nothing moves or doubles; names find the same entries */
	ASSERT_EQ(bst_counters_attach_shared(mem, vmem, true), 0);
	ASSERT_EQ(bst_counter_get(bst_counter_register("late_total", "", "a=b")), 1);
	ASSERT_EQ(bst_counter_get(bst_counter_register("early_total", "", NULL)), 5);
	ASSERT_EQ(bst_counter_get(early), 5);
	/* a region of another layout is started over */
	memset(mem, 0xab, 64);
	ASSERT_EQ(bst_counters_attach_shared(mem, vmem, true), -1);
	ASSERT_EQ(bst_counter_count(), 0);
	ASSERT(bst_counter_register("fresh_total", "", NULL) != BST_COUNTER_INVALID);
	/* a child finds master's entries but adds none */
	pid_t pid = fork();
	ASSERT(pid >= 0);
	if (pid == 0) {
		bst_counters_child();
		int bad = bst_counter_register("fresh_total", "", NULL) == BST_COUNTER_INVALID ||
			  bst_counter_register("new_in_child_total", "", NULL) != BST_COUNTER_INVALID ||
			  bst_counter_count() != 1;
		_exit(bad);
	}
	int st = 0;
	ASSERT_EQ(waitpid(pid, &st, 0), pid);
	ASSERT(WIFEXITED(st) && WEXITSTATUS(st) == 0);
}

/* Security review H2: a kept registry is validated before master trusts it. Each corruption
 * (a count past the table, a histogram index past the buckets, an unterminated name) used to
 * drive out-of-bounds reads or writes in root master on the next reload; now the region is
 * started over and every access stays in bounds (ASan). Uses fresh processes' state: forks. */
static int corrupt_case(int which)
{
	size_t sz = bst_counters_registry_size(), vsz = bst_counters_values_size();
	unsigned char *r = mmap(NULL, sz, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
	void *v = mmap(NULL, vsz, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
	if (r == MAP_FAILED || v == MAP_FAILED)
		return 10;
	bst_counters_reset_for_test();
	if (bst_counters_attach_shared(r, v, false) != 0)
		return 11;
	bst_counter_id h = bst_histogram_register("lat", "", NULL);
	bst_histogram_observe(h, 5);
	/* registry header: magic, version, count, hist_count; then entries {kind, hist, name..} */
	uint32_t *hdr = (uint32_t *)r;
	uint32_t *e0 = hdr + 4;
	if (which == 0)
		hdr[2] = 0xffffffffu; /* count */
	else if (which == 1)
		e0[1] = 0x7fffffffu; /* the histogram's index */
	else
		memset(e0 + 2, 'A', BST_COUNTER_NAME_MAX); /* unterminated name */
	/* the next image attaches the kept regions: refused and started over */
	if (bst_counters_attach_shared(r, v, true) != -1)
		return 12;
	if (bst_counter_count() != 0)
		return 13;
	h = bst_histogram_register("lat", "", NULL);
	bst_histogram_observe(h, 5);
	if (bst_histogram_bucket(h, bst_histogram_bucket_index(5)) != 1)
		return 14;
	size_t len = 0;
	char *s = bst_metrics_render(&len, 1, 1);
	if (s == NULL)
		return 15;
	free(s);
	return 0;
}

TEST(kept_registry_is_validated)
{
	for (int which = 0; which < 3; which++) {
		pid_t pid = fork();
		ASSERT(pid >= 0);
		if (pid == 0)
			_exit(corrupt_case(which));
		int st = 0;
		ASSERT_EQ(waitpid(pid, &st, 0), pid);
		ASSERT(WIFEXITED(st));
		ASSERT_EQ(WEXITSTATUS(st), 0);
	}
}

TEST(label_values_are_reduced)
{
	char out[16];
	bst_metrics_label_value("a.test", out, sizeof out);
	ASSERT_STR(out, "a.test");
	bst_metrics_label_value("x\"y\\z\n{}=,", out, sizeof out);
	ASSERT_STR(out, "x_y_z_____");
	bst_metrics_label_value("", out, sizeof out);
	ASSERT_STR(out, "_");
	bst_metrics_label_value("0123456789abcdefghij", out, sizeof out);
	ASSERT_EQ(strlen(out), 15);
}

TEST(render_format)
{
	bst_counters_reset_for_test();
	bst_counter_id a = bst_counter_register("req_total", "line1\nback\\slash", "server=a,code=2xx");
	bst_counter_id b = bst_counter_register("req_total", "", "server=b,code=2xx");
	bst_counter_id h = bst_histogram_register("lat_seconds", "latency", "protocol=http1");
	bst_counter_add(a, 3);
	bst_counter_add(b, 1);
	bst_histogram_observe(h, 500);	   /* 0.5 ms */
	bst_histogram_observe(h, 2000000); /* 2 s */
	size_t len = 0;
	char *s = bst_metrics_render(&len, 7, 1);
	ASSERT(s != NULL && len == strlen(s) && s[len - 1] == '\n');
	ASSERT(strstr(s, "# HELP req_total line1\\nback\\\\slash\n# TYPE req_total counter\n") != NULL);
	ASSERT(strstr(s, "req_total{server=\"a\",code=\"2xx\"} 3\n") != NULL);
	ASSERT(strstr(s, "req_total{server=\"b\",code=\"2xx\"} 1\n") != NULL);
	/* one TYPE line per family */
	ASSERT(strstr(strstr(s, "# TYPE req_total") + 1, "# TYPE req_total") == NULL);
	ASSERT(strstr(s, "# TYPE lat_seconds histogram\n") != NULL);
	ASSERT(strstr(s, "lat_seconds_bucket{protocol=\"http1\",le=\"0.001\"} 1\n") != NULL);
	ASSERT(strstr(s, "lat_seconds_bucket{protocol=\"http1\",le=\"1\"} 1\n") != NULL);
	ASSERT(strstr(s, "lat_seconds_bucket{protocol=\"http1\",le=\"2.5\"} 2\n") != NULL);
	ASSERT(strstr(s, "lat_seconds_bucket{protocol=\"http1\",le=\"+Inf\"} 2\n") != NULL);
	ASSERT(strstr(s, "lat_seconds_count{protocol=\"http1\"} 2\n") != NULL);
	ASSERT(strstr(s, "lat_seconds_sum{protocol=\"http1\"} 2.000500\n") != NULL);
	ASSERT(strstr(s, "bastion_connections 7\n") != NULL);
	ASSERT(strstr(s, "# TYPE bastion_under_attack gauge\nbastion_under_attack 1\n") != NULL);
	free(s);
	s = bst_metrics_render(&len, -1, -1);
	ASSERT(s != NULL && strstr(s, "bastion_connections") == NULL && strstr(s, "under_attack") == NULL);
	free(s);
}

TAP_MAIN()

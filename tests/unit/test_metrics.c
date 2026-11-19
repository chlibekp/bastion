#include "tap.h"

#include "core/counters.h"
#include "ops/metrics.h"

#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>

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
	size_t sz = bst_counters_region_size();
	void *mem = mmap(NULL, sz, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
	ASSERT(mem != MAP_FAILED);
	ASSERT_EQ(bst_counters_attach_shared(mem, false), 0);
	ASSERT_EQ(bst_counter_get(early), 4);
	bst_counter_id late = bst_counter_register("late_total", "", "a=b");
	bst_counter_add(late, 1);
	bst_counter_add(early, 1);
	ASSERT_EQ(bst_counter_get(early), 5);
	/* attached again (a re-run): nothing moves or doubles; names find the same entries */
	ASSERT_EQ(bst_counters_attach_shared(mem, true), 0);
	ASSERT_EQ(bst_counter_get(bst_counter_register("late_total", "", "a=b")), 1);
	ASSERT_EQ(bst_counter_get(bst_counter_register("early_total", "", NULL)), 5);
	ASSERT_EQ(bst_counter_get(early), 5);
	/* a region of another layout is started over */
	memset(mem, 0xab, 64);
	ASSERT_EQ(bst_counters_attach_shared(mem, true), -1);
	ASSERT_EQ(bst_counter_count(), 0);
	ASSERT(bst_counter_register("fresh_total", "", NULL) != BST_COUNTER_INVALID);
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

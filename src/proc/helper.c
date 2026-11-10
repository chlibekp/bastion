/* See helper.h. */
#include "proc/helper.h"

#include "core/log.h"
#include "io/backend.h"
#include "io/sock.h"
#include "proc/channel.h"
#include "proc/test_hooks.h"

#include <errno.h>
#include <poll.h>
#include <string.h>
#include <unistd.h>

typedef struct helper {
	bst_runtime *rt;
	bst_sock *chan;
} helper;

static void on_channel(void *ud, uint32_t events, int err)
{
	helper *h = ud;
	(void)events, (void)err;
	for (;;) {
		bst_msg m;
		int rc = bst_chan_recv(h->rt->channel, &m);
		if (rc == -EAGAIN)
			break;
		if (rc <= 0) { /* EOF: master is gone; anything else, nothing to wait for */
#ifdef BST_TEST
			if (rc == 0 && bst_test_ignore_channel_eof())
				return;
#endif
			_exit(0);
		}
		if (m.type == BST_MSG_STOP)
			_exit(0); /* nothing of the helper's is in flight yet */
	}
	if (bst_io_poll(h->chan, POLLIN | POLLRDHUP, on_channel, h) != 0)
		_exit(1);
}

void bst_helper_main(bst_runtime *rt)
{
	static helper h;
	h.rt = rt;
	bst_child_start(rt, -1, "helper");
#ifdef BST_TEST
	bst_test_child_exit78();
	bst_test_sandbox_claim(-1);
#endif
	bst_loop *l = bst_child_loop_and_drop(rt, -1, "helper");
	bst_child_watch_master(rt);
#ifdef BST_TEST
	bst_test_sandbox_prepare(l);
#endif
	bst_child_sandbox(rt, BST_SANDBOX_HELPER);
	bst_io_backend_report(l);
#ifdef BST_TEST
	bst_test_child_crash(-1);
	bst_test_sandbox_probe_ring();
#endif
	h.chan = bst_sock_wrap(l, rt->channel);
	if (h.chan == NULL || bst_io_poll(h.chan, POLLIN | POLLRDHUP, on_channel, &h) != 0)
		_exit(1);
	bst_msg ready = {.type = BST_MSG_READY, .ready = {.backend = bst_loop_backend(l)}};
	if (bst_chan_send(rt->channel, &ready) != 0)
		_exit(1);
#ifdef BST_TEST
	bst_test_sandbox_probe();
#endif
	int rc = bst_loop_run(l);
	if (rc < 0)
		bst_log(BST_LOG_ERROR, "helper loop failed: %s", strerror(-rc));
	_exit(rc < 0 ? 1 : 0);
}

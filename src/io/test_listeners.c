/* `bastion --test-listeners N [--test-accept-ms MS]`: a test-build tool that exercises the
 * listener code without a server runtime (workers arrive in Phase 3 Task 7). Compiled only
 * under BST_TEST, so a release binary has neither the flag nor these symbols
 * (make check-release proves it with nm).
 *
 * It creates the listeners of the compiled config (one socket per distinct address and slot,
 * exactly as master will), prints one JSON line
 *   {"event":"listening","listeners":[{"addr":"127.0.0.1","port":8080,"profile":"edge",
 *     "sockets":[{"slot":0,"fd":5,"opts":{"reuseport":1,...}}]}]}
 * with every option read back by getsockopt (an option the kernel cannot read is left out),
 * and flushes it. With MS > 0 it then accepts on every socket for MS milliseconds and prints
 *   {"event":"done","accepted":[[n per slot]],"bytes":[[bytes read from each connection]],
 *    "accepted_opts":[{"quickack":0,"nodelay":1}|null]}
 * where accepted_opts is read from the first connection accepted on each listener after
 * bst_sock_apply_accepted ran on it. */
#ifdef BST_TEST
#include "core/addr.h"
#include "io/listener.h"

#include <errno.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#define MAX_HELD 4096

static bool gi(int fd, int lvl, int opt, int *v)
{
	socklen_t len = sizeof *v;
	return getsockopt(fd, lvl, opt, v, &len) == 0;
}

static void put_int_opt(FILE *f, int *first, int fd, const char *key, int lvl, int opt)
{
	int v;
	if (!gi(fd, lvl, opt, &v))
		return;
	fprintf(f, "%s\"%s\":%d", *first ? "" : ",", key, v);
	*first = 0;
}

static void dump_socket(FILE *f, int fd, int slot, bool v6)
{
	int first = 1;
	fprintf(f, "{\"slot\":%d,\"fd\":%d,\"opts\":{", slot, fd);
	put_int_opt(f, &first, fd, "reuseport", SOL_SOCKET, SO_REUSEPORT);
	put_int_opt(f, &first, fd, "acceptconn", SOL_SOCKET, SO_ACCEPTCONN);
	if (v6)
		put_int_opt(f, &first, fd, "v6only", IPPROTO_IPV6, IPV6_V6ONLY);
	put_int_opt(f, &first, fd, "fastopen", IPPROTO_TCP, TCP_FASTOPEN);
	uint8_t key[BST_TCP_KEY_LEN];
	socklen_t kl = sizeof key;
	if (getsockopt(fd, IPPROTO_TCP, 33 /* TCP_FASTOPEN_KEY */, key, &kl) == 0 && kl == sizeof key) {
		fprintf(f, "%s\"fastopen_key\":\"", first ? "" : ",");
		for (size_t i = 0; i < sizeof key; i++)
			fprintf(f, "%02x", key[i]);
		fputc('"', f);
		first = 0;
	}
	put_int_opt(f, &first, fd, "defer_accept", IPPROTO_TCP, TCP_DEFER_ACCEPT);
	put_int_opt(f, &first, fd, "busy_poll", SOL_SOCKET, SO_BUSY_POLL);
	put_int_opt(f, &first, fd, "prefer_busy_poll", SOL_SOCKET, 69 /* SO_PREFER_BUSY_POLL */);
	put_int_opt(f, &first, fd, "busy_poll_budget", SOL_SOCKET, 70 /* SO_BUSY_POLL_BUDGET */);
	put_int_opt(f, &first, fd, "nodelay", IPPROTO_TCP, TCP_NODELAY);
	char cc[BST_TCP_CA_NAME_MAX + 1] = { 0 };
	socklen_t cl = BST_TCP_CA_NAME_MAX;
	if (getsockopt(fd, IPPROTO_TCP, TCP_CONGESTION, cc, &cl) == 0) {
		for (char *p = cc; *p; p++)
			if (!((*p >= 'a' && *p <= 'z') || (*p >= '0' && *p <= '9') || *p == '-' || *p == '_'))
				*p = '?';
		fprintf(f, "%s\"congestion\":\"%s\"", first ? "" : ",", cc);
		first = 0;
	}
	put_int_opt(f, &first, fd, "notsent_lowat", IPPROTO_TCP, TCP_NOTSENT_LOWAT);
	put_int_opt(f, &first, fd, "user_timeout", IPPROTO_TCP, TCP_USER_TIMEOUT);
	put_int_opt(f, &first, fd, "keepalive", SOL_SOCKET, SO_KEEPALIVE);
	put_int_opt(f, &first, fd, "keepidle", IPPROTO_TCP, TCP_KEEPIDLE);
	put_int_opt(f, &first, fd, "keepintvl", IPPROTO_TCP, TCP_KEEPINTVL);
	put_int_opt(f, &first, fd, "keepcnt", IPPROTO_TCP, TCP_KEEPCNT);
	put_int_opt(f, &first, fd, "rcvbuf", SOL_SOCKET, SO_RCVBUF);
	put_int_opt(f, &first, fd, "sndbuf", SOL_SOCKET, SO_SNDBUF);
	put_int_opt(f, &first, fd, "pacing_rate", SOL_SOCKET, SO_MAX_PACING_RATE);
	put_int_opt(f, &first, fd, "mark", SOL_SOCKET, SO_MARK);
	put_int_opt(f, &first, fd, v6 ? "freebind" : "freebind", v6 ? IPPROTO_IPV6 : IPPROTO_IP,
		    v6 ? 78 /* IPV6_FREEBIND */ : IP_FREEBIND);
	put_int_opt(f, &first, fd, "incoming_cpu", SOL_SOCKET, SO_INCOMING_CPU);
	fputs("}}", f);
}

static uint64_t now_ms(void)
{
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (uint64_t)ts.tv_sec * 1000 + (uint64_t)ts.tv_nsec / 1000000;
}

typedef struct lst {
	const bst_cfg_listen *l;
	int *fds;
	unsigned *count;       /* accepted per slot */
	int *bytes;            /* per accepted connection */
	size_t nbytes;
	bool have_opts;
	int quickack, nodelay; /* of the first accepted connection */
} lst;

int bst_test_listeners_main(const bst_config *cfg, int slots, unsigned accept_ms)
{
	bst_err e = { .msg = "" };
	const bst_cfg_listen **ls;
	size_t n;
	if (bst_config_listeners(cfg, &ls, &n, &e) != 0) {
		fprintf(stderr, "bastion: %s\n", e.msg);
		return 1;
	}
	lst *all = calloc(n ? n : 1, sizeof *all);
	if (all == NULL)
		return 1;
	int rc = 1;
	size_t created = 0;
	for (size_t i = 0; i < n; i++) {
		all[i].l = ls[i];
		all[i].fds = calloc((size_t)slots, sizeof(int));
		all[i].count = calloc((size_t)slots, sizeof(unsigned));
		all[i].bytes = calloc(MAX_HELD, sizeof(int));
		if (all[i].fds == NULL || all[i].count == NULL || all[i].bytes == NULL)
			goto out;
		if (bst_listener_create(ls[i], slots, all[i].fds, &e) != 0) {
			fprintf(stderr, "bastion: %s\n", e.msg);
			goto out;
		}
		created = i + 1;
	}
	printf("{\"event\":\"listening\",\"listeners\":[");
	for (size_t i = 0; i < n; i++) {
		char ip[BST_ADDR_STRLEN];
		bst_addr_format(&all[i].l->addr.ip, ip, sizeof ip);
		bool v6 = all[i].l->addr.ip.family == BST_IP_V6;
		printf("%s{\"addr\":\"%s\",\"port\":%u,\"profile\":\"%s\",\"sockets\":[", i ? "," : "", ip,
		       (unsigned)all[i].l->addr.port, all[i].l->tcp ? all[i].l->tcp->name : "default");
		for (int s = 0; s < slots; s++) {
			if (s)
				putchar(',');
			dump_socket(stdout, all[i].fds[s], s, v6);
		}
		printf("]}");
	}
	printf("]}\n");
	fflush(stdout);
	if (accept_ms > 0) {
		struct pollfd *pf = calloc(n * (size_t)slots, sizeof *pf);
		int *held = calloc(MAX_HELD, sizeof *held);
		size_t nheld = 0;
		if (pf == NULL || held == NULL)
			goto out;
		for (size_t i = 0; i < n; i++)
			for (int s = 0; s < slots; s++)
				pf[i * (size_t)slots + (size_t)s] =
					(struct pollfd){ .fd = all[i].fds[s], .events = POLLIN };
		uint64_t end = now_ms() + accept_ms;
		for (uint64_t t = now_ms(); t < end; t = now_ms()) {
			int pr = poll(pf, (nfds_t)(n * (size_t)slots), (int)(end - t));
			if (pr <= 0)
				continue;
			for (size_t i = 0; i < n; i++)
				for (int s = 0; s < slots; s++) {
					if (!(pf[i * (size_t)slots + (size_t)s].revents & POLLIN))
						continue;
					int c;
					while ((c = accept4(all[i].fds[s], NULL, NULL,
							    SOCK_NONBLOCK | SOCK_CLOEXEC)) >= 0) {
						all[i].count[s]++;
						bst_sock_apply_accepted(c, all[i].l->tcp);
						char buf[64];
						ssize_t r = recv(c, buf, sizeof buf, MSG_DONTWAIT);
						if (all[i].nbytes < MAX_HELD)
							all[i].bytes[all[i].nbytes++] = r > 0 ? (int)r : 0;
						if (!all[i].have_opts) {
							all[i].have_opts = true;
							all[i].quickack = all[i].nodelay = -1;
							(void)gi(c, IPPROTO_TCP, TCP_QUICKACK, &all[i].quickack);
							(void)gi(c, IPPROTO_TCP, TCP_NODELAY, &all[i].nodelay);
						}
						if (nheld < MAX_HELD)
							held[nheld++] = c; /* open until the end: no early FIN */
						else
							close(c);
					}
				}
		}
		printf("{\"event\":\"done\",\"accepted\":[");
		for (size_t i = 0; i < n; i++) {
			printf("%s[", i ? "," : "");
			for (int s = 0; s < slots; s++)
				printf("%s%u", s ? "," : "", all[i].count[s]);
			putchar(']');
		}
		printf("],\"bytes\":[");
		for (size_t i = 0; i < n; i++) {
			printf("%s[", i ? "," : "");
			for (size_t b = 0; b < all[i].nbytes; b++)
				printf("%s%d", b ? "," : "", all[i].bytes[b]);
			putchar(']');
		}
		printf("],\"accepted_opts\":[");
		for (size_t i = 0; i < n; i++) {
			if (all[i].have_opts)
				printf("%s{\"quickack\":%d,\"nodelay\":%d}", i ? "," : "", all[i].quickack,
				       all[i].nodelay);
			else
				printf("%snull", i ? "," : "");
		}
		printf("]}\n");
		fflush(stdout);
		for (size_t h = 0; h < nheld; h++)
			close(held[h]);
		free(held);
		free(pf);
	}
	rc = 0;
out:
	for (size_t i = 0; i < n; i++) {
		if (all[i].fds != NULL && i < created)
			for (int s = 0; s < slots; s++)
				close(all[i].fds[s]);
		free(all[i].fds);
		free(all[i].count);
		free(all[i].bytes);
	}
	free(all);
	free(ls);
	return rc;
}
#else
typedef int bst_listeners_test_only_unused_; /* keeps the translation unit non-empty */
#endif

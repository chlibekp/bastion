/* A small blocking HTTPS client for the ACME job (ops/acme.h): one request per connection, a
 * deadline on every request, a cap on the response, and one pinned host.
 *
 * Everything that needs a file or a name lookup happens in bst_hc_open, before the sandbox: the
 * host is resolved once and the trust store loaded into memory. A request then needs only
 * socket, connect, read, write and epoll_pwait (on an epoll descriptor made here), which is all
 * the job's seccomp filter allows. A URL whose host or port differ from the pinned one is
 * refused rather than resolved. */
#ifndef BST_OPS_HTTP_CLIENT_H
#define BST_OPS_HTTP_CLIENT_H

#include <netinet/in.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/socket.h>

#define BST_HC_MAX_BODY (1u << 20)
#define BST_HC_MAX_HEAD 16384u

typedef struct bst_hc {
	void *ssl_ctx; /* SSL_CTX *, NULL for plain http */
	int ep;	       /* epoll descriptor for waits */
	char host[256];
	uint16_t port;
	bool tls;
	struct sockaddr_storage addr;
	socklen_t alen;
	int timeout_ms;
} bst_hc;

typedef struct bst_hc_resp {
	int status;
	char *body; /* malloc'd, NUL-terminated */
	size_t len;
	char location[1024];
	char nonce[256];
	char retry_after[64];
	char content_type[128];
	char link_up[1024]; /* Link: <...>;rel="up" */
} bst_hc_resp;

/* Splits an http(s) URL. path gets at least "/". */
bool bst_hc_parse_url(const char *url, bool *tls, char *host, size_t hcap, uint16_t *port,
		      char *path, size_t pcap);

/* Resolves url's host and prepares TLS (ca_file: a PEM bundle, NULL for the system's). 0, or -1
 * with err filled. */
int bst_hc_open(bst_hc *c, const char *url, const char *ca_file, int timeout_ms, char *err, size_t ecap);
void bst_hc_close(bst_hc *c);

/* One request. body may be NULL. 0 with r filled (any status), or -1 with err. */
int bst_hc_request(bst_hc *c, const char *method, const char *url, const char *ctype,
		   const char *body, size_t blen, bst_hc_resp *r, char *err, size_t ecap);
void bst_hc_resp_free(bst_hc_resp *r);

/* Parses a complete response (head and body) as read from the wire; exposed for tests. 0, or -1
 * with err (malformed, oversized). */
int bst_hc_parse_response(const char *buf, size_t len, bool head_only, bst_hc_resp *r, char *err,
			  size_t ecap);

/* Sleeps through epoll_pwait on c->ep (the job may not call nanosleep). */
void bst_hc_sleep(const bst_hc *c, uint64_t ms);

#endif

#include "tls/ktls.h"

#include "core/counters.h"
#include "core/log.h"

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <openssl/bio.h>
#include <stdatomic.h>
#include <stdint.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

/* The kernel's constants, spelled out: the headers are not in every libc. */
#define K_TCP_ULP 31
#define K_SOL_TLS 282
#define K_TLS_TX 1
#define K_TLS_1_2 0x0303
#define K_TLS_CIPHER_AES_GCM_128 51

static bst_counter_id c_tx = BST_COUNTER_INVALID, c_txrx = BST_COUNTER_INVALID,
		      c_user = BST_COUNTER_INVALID, c_ku = BST_COUNTER_INVALID;

void bst_tls_ktls_init(void)
{
	const char *h = "TLS connections by where the record layer runs";
	c_tx = bst_counter_register("bastion_tls_ktls_connections", h, "mode=tx");
	c_txrx = bst_counter_register("bastion_tls_ktls_connections", h, "mode=tx+rx");
	c_user = bst_counter_register("bastion_tls_ktls_connections", h, "mode=user");
	c_ku = bst_counter_register("bastion_tls_ktls_keyupdate_closed_total",
				    "connections closed by a client KeyUpdate under kTLS", NULL);
}

/* TLS 1.3 installs the write key with the server Finished and the read key after the client's:
 * once TX is in the kernel, turning the option off leaves RX in user space. */
static void tx_only_cb(const SSL *cs, int where, int ret)
{
	SSL *ssl = (SSL *)(uintptr_t)cs;
	(void)ret;
	if ((where & SSL_CB_ACCEPT_LOOP) && SSL_version(ssl) == TLS1_3_VERSION &&
	    BIO_get_ktls_send(SSL_get_wbio(ssl)))
		SSL_clear_options(ssl, SSL_OP_ENABLE_KTLS);
}

void bst_tls_ktls_ctx(SSL_CTX *ctx, const bst_cfg_tls_profile *p)
{
	if (p->ktls == BST_KTLS_OFF)
		return;
	SSL_CTX_set_options(ctx, SSL_OP_ENABLE_KTLS);
	if (p->ktls == BST_KTLS_TX)
		SSL_CTX_set_info_callback(ctx, tx_only_cb);
}

void bst_tls_ktls_note(SSL *ssl, const bst_cfg_tls_profile *p, bool *tx, bool *rx)
{
	static atomic_flag warned = ATOMIC_FLAG_INIT;
	*tx = BIO_get_ktls_send(SSL_get_wbio(ssl)) != 0;
	*rx = BIO_get_ktls_recv(SSL_get_rbio(ssl)) != 0;
	if (p->ktls == BST_KTLS_OFF)
		return;
	if (*tx) {
		bst_counter_add(*rx ? c_txrx : c_tx, 1);
		return;
	}
	bst_counter_add(c_user, 1);
	if (!atomic_flag_test_and_set(&warned))
		bst_log(BST_LOG_WARN, "tls: kernel TLS did not activate for a connection (the kernel "
					"lacks the tls module or the cipher): serving in user space");
}

void bst_tls_ktls_closed(void)
{
	bst_counter_add(c_ku, 1);
}

int bst_tls_ktls_probe(bst_err *err)
{
	int l = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0), c = -1, a = -1, rc = -1;
	struct sockaddr_in sa = { .sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_LOOPBACK) };
	socklen_t sl = sizeof sa;
	if (l < 0 || bind(l, (struct sockaddr *)&sa, sizeof sa) != 0 || listen(l, 1) != 0 ||
	    getsockname(l, (struct sockaddr *)&sa, &sl) != 0 ||
	    (c = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0)) < 0 ||
	    connect(c, (struct sockaddr *)&sa, sizeof sa) != 0 ||
	    (a = accept4(l, NULL, NULL, SOCK_CLOEXEC)) < 0) {
		bst_err_set(err, "ktls: cannot make a loopback connection to probe: %s", strerror(errno));
		goto out;
	}
	if (setsockopt(a, IPPROTO_TCP, K_TCP_ULP, "tls", sizeof "tls") != 0) {
		bst_err_set(err, "ktls: the kernel has no TLS ULP (%s); `modprobe tls`", strerror(errno));
		goto out;
	}
	struct {
		unsigned short version, cipher_type;
		unsigned char iv[8], key[16], salt[4], rec_seq[8];
	} ci;
	memset(&ci, 0, sizeof ci);
	ci.version = K_TLS_1_2;
	ci.cipher_type = K_TLS_CIPHER_AES_GCM_128;
	if (setsockopt(a, K_SOL_TLS, K_TLS_TX, &ci, sizeof ci) != 0) {
		bst_err_set(err, "ktls: the kernel refused TLS_TX with AES-128-GCM (%s); load the "
				 "crypto modules (gcm, ctr, ghash)", strerror(errno));
		goto out;
	}
	rc = 0;
out:
	if (a >= 0)
		close(a);
	if (c >= 0)
		close(c);
	if (l >= 0)
		close(l);
	return rc;
}

int bst_tls_ktls_check(const bst_config *cfg, bst_err *err)
{
	bool need = false;
	for (size_t i = 0; i < cfg->global.nservers && !need; i++) {
		const bst_cfg_tls *t = &cfg->global.servers[i]->tls;
		need = t->ctx != NULL && t->profile != NULL && t->profile->ktls != BST_KTLS_OFF &&
		       t->profile->ktls_require;
	}
	return need ? bst_tls_ktls_probe(err) : 0;
}

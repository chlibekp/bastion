/* See token.h. */
#include "http/h3/token.h"

#include <netinet/in.h>
#include <ngtcp2/ngtcp2_crypto.h>
#include <string.h>

_Static_assert(NGTCP2_CRYPTO_MAX_RETRY_TOKENLEN2 <= BST_TOKEN_MAX, "Retry token room");
_Static_assert(NGTCP2_CRYPTO_MAX_REGULAR_TOKENLEN <= BST_TOKEN_MAX, "regular token room");

socklen_t bst_quic_sockaddr(const bst_sockaddr *a, struct sockaddr_storage *ss)
{
	memset(ss, 0, sizeof *ss);
	if (a->ip.family == BST_IP_V6) {
		struct sockaddr_in6 *s6 = (struct sockaddr_in6 *)ss;
		s6->sin6_family = AF_INET6;
		s6->sin6_port = htons(a->port);
		memcpy(&s6->sin6_addr, a->ip.b, 16);
		return sizeof *s6;
	}
	if (a->ip.family == BST_IP_V4) {
		struct sockaddr_in *s4 = (struct sockaddr_in *)ss;
		s4->sin_family = AF_INET;
		s4->sin_port = htons(a->port);
		memcpy(&s4->sin_addr, a->ip.b, 4);
		return sizeof *s4;
	}
	return 0;
}

ngtcp2_ssize bst_token_retry(uint8_t *out, const bst_quic_secrets *s, uint32_t version,
			     const bst_sockaddr *peer, const ngtcp2_cid *retry_scid,
			     const ngtcp2_cid *odcid, uint64_t now_ns)
{
	struct sockaddr_storage ss;
	socklen_t sl = bst_quic_sockaddr(peer, &ss);
	if (sl == 0)
		return -1;
	return ngtcp2_crypto_generate_retry_token2(out, s->token, sizeof s->token, version,
						   (const ngtcp2_sockaddr *)&ss, sl, retry_scid, odcid,
						   now_ns);
}

int bst_token_retry_check(ngtcp2_cid *odcid, const uint8_t *tok, size_t len, const bst_quic_secrets *s,
			  uint32_t version, const bst_sockaddr *peer, const ngtcp2_cid *dcid,
			  uint64_t now_ns)
{
	struct sockaddr_storage ss;
	socklen_t sl = bst_quic_sockaddr(peer, &ss);
	if (sl == 0 || len == 0 || tok[0] != NGTCP2_CRYPTO_TOKEN_MAGIC_RETRY2)
		return -1;
	return ngtcp2_crypto_verify_retry_token2(odcid, tok, len, s->token, sizeof s->token, version,
						 (const ngtcp2_sockaddr *)&ss, sl, dcid,
						 (ngtcp2_duration)BST_TOKEN_RETRY_TTL_MS * NGTCP2_MILLISECONDS,
						 now_ns) == 0
		       ? 0
		       : -1;
}

ngtcp2_ssize bst_token_regular(uint8_t *out, const bst_quic_secrets *s, const bst_sockaddr *peer,
			       uint64_t now_ns)
{
	struct sockaddr_storage ss;
	socklen_t sl = bst_quic_sockaddr(peer, &ss);
	if (sl == 0)
		return -1;
	return ngtcp2_crypto_generate_regular_token(out, s->token, sizeof s->token,
						    (const ngtcp2_sockaddr *)&ss, sl, now_ns);
}

int bst_token_regular_check(const uint8_t *tok, size_t len, const bst_quic_secrets *s,
			    const bst_sockaddr *peer, uint64_t now_ns)
{
	struct sockaddr_storage ss;
	socklen_t sl = bst_quic_sockaddr(peer, &ss);
	if (sl == 0 || len == 0 || tok[0] != NGTCP2_CRYPTO_TOKEN_MAGIC_REGULAR)
		return -1;
	return ngtcp2_crypto_verify_regular_token(tok, len, s->token, sizeof s->token,
						  (const ngtcp2_sockaddr *)&ss, sl,
						  (ngtcp2_duration)BST_TOKEN_REGULAR_TTL_MS * NGTCP2_MILLISECONDS,
						  now_ns) == 0
		       ? 0
		       : -1;
}

int bst_token_reset(uint8_t out[NGTCP2_STATELESS_RESET_TOKENLEN], const bst_quic_secrets *s,
		    const ngtcp2_cid *cid)
{
	return ngtcp2_crypto_generate_stateless_reset_token(out, s->reset, sizeof s->reset, cid) == 0 ? 0 : -1;
}

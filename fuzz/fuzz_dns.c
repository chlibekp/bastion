/* libFuzzer harness for the stub resolver's response parser (proxy/dns.c). Properties: no crash,
 * no read past the input, no hang; on OK at most BST_DNS_MAX_ADDRS addresses of the asked family.
 * Input: one byte choosing A or AAAA, then the message. The question is fixed, and the ID is the
 * message's own, so the fuzzer reaches the answer section. */
#include "proxy/dns.h"

#include <stdlib.h>
#include <string.h>

int LLVMFuzzerTestOneInput(const uint8_t *d, size_t len)
{
	if (len < 3)
		return 0;
	uint16_t qtype = (d[0] & 1) ? BST_DNS_TYPE_AAAA : BST_DNS_TYPE_A;
	const uint8_t *m = d + 1;
	size_t n = len - 1;
	if (n > BST_DNS_MAX_MSG)
		n = BST_DNS_MAX_MSG;
	uint16_t id = (uint16_t)((m[0] << 8) | m[1]);
	uint8_t *copy = malloc(n); /* exact size: ASan catches any over-read */
	if (copy == NULL)
		return 0;
	memcpy(copy, m, n);
	bst_dns_answer a;
	bst_dns_status st = bst_dns_parse(copy, n, id, "example.com", qtype, &a);
	if (st == BST_DNS_OK) {
		if (a.naddrs > BST_DNS_MAX_ADDRS)
			abort();
		for (size_t i = 0; i < a.naddrs; i++)
			if (a.addrs[i].family != (qtype == BST_DNS_TYPE_A ? BST_IP_V4 : BST_IP_V6))
				abort();
	} else if (a.naddrs != 0) {
		abort();
	}
	uint8_t q[512];
	(void)bst_dns_query(q, sizeof q, id, (const char *)"example.com", qtype);
	free(copy);
	return 0;
}

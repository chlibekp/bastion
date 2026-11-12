/* The stub resolver's wire format (proxy/dns.c) and the upstream model's config side. Messages are
 * laid out as real resolvers send them: the question echoed, answers that point back at it with
 * compression, CNAME chains before the addresses. */
#include "config/compile.h"
#include "config/parser.h"
#include "proxy/dns.h"
#include "proxy/upstream.h"
#include "tap.h"

#include <string.h>

/* A response to the query `id`, for name, built as `dig` shows real answers. */
typedef struct msg {
	uint8_t b[BST_DNS_MAX_MSG];
	size_t n;
} msg;

static void put16(msg *m, unsigned v)
{
	m->b[m->n++] = (uint8_t)(v >> 8);
	m->b[m->n++] = (uint8_t)v;
}

static void put32(msg *m, uint32_t v)
{
	put16(m, v >> 16);
	put16(m, v & 0xffff);
}

static void put_name(msg *m, const char *name)
{
	const char *p = name;
	while (*p) {
		const char *dot = strchr(p, '.');
		size_t l = dot ? (size_t)(dot - p) : strlen(p);
		m->b[m->n++] = (uint8_t)l;
		memcpy(m->b + m->n, p, l);
		m->n += l;
		p += l + (dot ? 1 : 0);
	}
	m->b[m->n++] = 0;
}

static void header(msg *m, unsigned id, unsigned flags, unsigned an)
{
	m->n = 0;
	put16(m, id);
	put16(m, flags);
	put16(m, 1);
	put16(m, an);
	put16(m, 0);
	put16(m, 0);
}

static void question(msg *m, const char *name, unsigned type)
{
	put_name(m, name);
	put16(m, type);
	put16(m, 1);
}

/* An answer whose owner is a pointer to offset `ptr` (0xc00c is the question). */
static void rr_ptr(msg *m, unsigned ptr, unsigned type, uint32_t ttl, const void *rd, size_t rl)
{
	put16(m, 0xc000 | ptr);
	put16(m, type);
	put16(m, 1);
	put32(m, ttl);
	put16(m, (unsigned)rl);
	memcpy(m->b + m->n, rd, rl);
	m->n += rl;
}

#define ID 0x1234
#define OKF 0x8180 /* QR, RD, RA, NOERROR */

TEST(dns_query_layout)
{
	uint8_t q[512];
	size_t n = bst_dns_query(q, sizeof q, 0xbeef, "api.example.com.", BST_DNS_TYPE_AAAA);
	ASSERT_EQ(n, 12 + 17 + 4);
	ASSERT_EQ(q[0], 0xbe);
	ASSERT_EQ(q[2], 0x01); /* RD */
	ASSERT_EQ(q[5], 1);
	ASSERT(memcmp(q + 12, "\3api\7example\3com\0", 17) == 0);
	ASSERT_EQ(q[12 + 17 + 1], BST_DNS_TYPE_AAAA);
	ASSERT_EQ(bst_dns_query(q, sizeof q, 1, "bad..name", 1), 0);
	ASSERT_EQ(bst_dns_query(q, sizeof q, 1, "sp ace", 1), 0);
	ASSERT_EQ(bst_dns_query(q, 20, 1, "example.com", 1), 0);
}

TEST(dns_parse)
{
	msg m;
	header(&m, ID, OKF, 2);
	question(&m, "example.com", BST_DNS_TYPE_A);
	rr_ptr(&m, 12, BST_DNS_TYPE_A, 300, "\x5d\xb8\xd8\x22", 4);
	rr_ptr(&m, 12, BST_DNS_TYPE_A, 120, "\x0a\x00\x00\x01", 4);
	bst_dns_answer a;
	ASSERT_EQ(bst_dns_parse(m.b, m.n, ID, "EXAMPLE.com.", BST_DNS_TYPE_A, &a), BST_DNS_OK);
	ASSERT_EQ(a.naddrs, 2);
	ASSERT_EQ(a.ttl, 120);
	ASSERT_EQ(a.addrs[0].family, BST_IP_V4);
	ASSERT(memcmp(a.addrs[0].b, "\x5d\xb8\xd8\x22", 4) == 0);

	/* AAAA */
	static const uint8_t v6[16] = { 0x20, 0x01, 0x0d, 0xb8, [15] = 1 };
	header(&m, ID, OKF, 1);
	question(&m, "example.com", BST_DNS_TYPE_AAAA);
	rr_ptr(&m, 12, BST_DNS_TYPE_AAAA, 60, v6, 16);
	ASSERT_EQ(bst_dns_parse(m.b, m.n, ID, "example.com", BST_DNS_TYPE_AAAA, &a), BST_DNS_OK);
	ASSERT_EQ(a.naddrs, 1);
	ASSERT_EQ(a.addrs[0].family, BST_IP_V6);
	ASSERT(memcmp(a.addrs[0].b, v6, 16) == 0);

	/* A CNAME chain: www -> edge.cdn.net -> e1.cdn.net -> address. */
	header(&m, ID, OKF, 3);
	question(&m, "www.example.com", BST_DNS_TYPE_A);
	size_t at = m.n;
	put16(&m, 0xc00c);
	put16(&m, BST_DNS_TYPE_CNAME);
	put16(&m, 1);
	put32(&m, 3600);
	put16(&m, 14);
	size_t edge = m.n;
	put_name(&m, "edge.cdn.net"); /* 14 bytes */
	(void)at;
	put16(&m, 0xc000 | (unsigned)edge);
	put16(&m, BST_DNS_TYPE_CNAME);
	put16(&m, 1);
	put32(&m, 30);
	put16(&m, 5);
	size_t e1 = m.n;
	m.b[m.n++] = 2; /* "e1" then a pointer to "cdn.net" inside edge.cdn.net */
	m.b[m.n++] = 'e';
	m.b[m.n++] = '1';
	put16(&m, 0xc000 | (unsigned)(edge + 5));
	rr_ptr(&m, (unsigned)e1, BST_DNS_TYPE_A, 90, "\x7f\x00\x00\x02", 4);
	ASSERT_EQ(bst_dns_parse(m.b, m.n, ID, "www.example.com", BST_DNS_TYPE_A, &a), BST_DNS_OK);
	ASSERT_EQ(a.naddrs, 1);
	ASSERT_EQ(a.ttl, 30); /* the smallest along the chain */
	ASSERT(memcmp(a.addrs[0].b, "\x7f\x00\x00\x02", 4) == 0);

	/* An address owned by an unrelated name does not count. */
	header(&m, ID, OKF, 1);
	question(&m, "example.com", BST_DNS_TYPE_A);
	size_t other = m.n;
	put_name(&m, "evil.test");
	put16(&m, BST_DNS_TYPE_A);
	put16(&m, 1);
	put32(&m, 60);
	put16(&m, 4);
	memcpy(m.b + m.n, "\x01\x02\x03\x04", 4);
	m.n += 4;
	(void)other;
	ASSERT_EQ(bst_dns_parse(m.b, m.n, ID, "example.com", BST_DNS_TYPE_A, &a), BST_DNS_OK);
	ASSERT_EQ(a.naddrs, 0);

	/* NXDOMAIN and SERVFAIL */
	header(&m, ID, 0x8183, 0);
	question(&m, "example.com", BST_DNS_TYPE_A);
	ASSERT_EQ(bst_dns_parse(m.b, m.n, ID, "example.com", BST_DNS_TYPE_A, &a), BST_DNS_NXDOMAIN);
	header(&m, ID, 0x8182, 0);
	question(&m, "example.com", BST_DNS_TYPE_A);
	ASSERT_EQ(bst_dns_parse(m.b, m.n, ID, "example.com", BST_DNS_TYPE_A, &a), BST_DNS_SERVFAIL);
}

TEST(dns_compression_loop)
{
	msg m;
	header(&m, ID, OKF, 1);
	question(&m, "example.com", BST_DNS_TYPE_A);
	size_t self = m.n;
	put16(&m, 0xc000 | (unsigned)self); /* the owner points at itself */
	put16(&m, BST_DNS_TYPE_A);
	put16(&m, 1);
	put32(&m, 60);
	put16(&m, 4);
	memcpy(m.b + m.n, "\x01\x02\x03\x04", 4);
	m.n += 4;
	bst_dns_answer a;
	ASSERT_EQ(bst_dns_parse(m.b, m.n, ID, "example.com", BST_DNS_TYPE_A, &a), BST_DNS_MALFORMED);

	/* Two names pointing at each other (each pointer backwards from the other is impossible,
	 * so a forward pointer is the loop's only way in). */
	header(&m, ID, OKF, 1);
	question(&m, "example.com", BST_DNS_TYPE_A);
	put16(&m, 0xc000 | (unsigned)(m.n + 2));
	put16(&m, 0xc000 | (unsigned)(m.n - 2));
	ASSERT_EQ(bst_dns_parse(m.b, m.n, ID, "example.com", BST_DNS_TYPE_A, &a), BST_DNS_MALFORMED);

	/* A CNAME loop: a -> b -> a. */
	header(&m, ID, OKF, 2);
	question(&m, "a.test", BST_DNS_TYPE_A);
	put16(&m, 0xc00c);
	put16(&m, BST_DNS_TYPE_CNAME);
	put16(&m, 1);
	put32(&m, 60);
	put16(&m, 8);
	size_t b = m.n;
	put_name(&m, "b.test");
	put16(&m, 0xc000 | (unsigned)b);
	put16(&m, BST_DNS_TYPE_CNAME);
	put16(&m, 1);
	put32(&m, 60);
	put16(&m, 2);
	put16(&m, 0xc00c);
	ASSERT_EQ(bst_dns_parse(m.b, m.n, ID, "a.test", BST_DNS_TYPE_A, &a), BST_DNS_MALFORMED);
}

TEST(dns_txid_mismatch)
{
	msg m;
	header(&m, ID, OKF, 1);
	question(&m, "example.com", BST_DNS_TYPE_A);
	rr_ptr(&m, 12, BST_DNS_TYPE_A, 60, "\x01\x02\x03\x04", 4);
	bst_dns_answer a;
	ASSERT_EQ(bst_dns_parse(m.b, m.n, ID + 1, "example.com", BST_DNS_TYPE_A, &a), BST_DNS_IGNORE);
	ASSERT_EQ(a.naddrs, 0);
	/* the right ID for another question */
	ASSERT_EQ(bst_dns_parse(m.b, m.n, ID, "example.org", BST_DNS_TYPE_A, &a), BST_DNS_IGNORE);
	ASSERT_EQ(bst_dns_parse(m.b, m.n, ID, "example.com", BST_DNS_TYPE_AAAA, &a), BST_DNS_IGNORE);
	/* a query (QR clear) echoed back */
	m.b[2] &= 0x7f;
	ASSERT_EQ(bst_dns_parse(m.b, m.n, ID, "example.com", BST_DNS_TYPE_A, &a), BST_DNS_IGNORE);
}

TEST(dns_truncated)
{
	msg m;
	header(&m, ID, OKF | 0x0200, 0);
	question(&m, "example.com", BST_DNS_TYPE_A);
	bst_dns_answer a;
	ASSERT_EQ(bst_dns_parse(m.b, m.n, ID, "example.com", BST_DNS_TYPE_A, &a), BST_DNS_TRUNCATED);
	/* cut inside an answer at every length: never read past the end */
	header(&m, ID, OKF, 1);
	question(&m, "example.com", BST_DNS_TYPE_A);
	rr_ptr(&m, 12, BST_DNS_TYPE_A, 60, "\x01\x02\x03\x04", 4);
	for (size_t n = 0; n < m.n; n++) {
		bst_dns_status st = bst_dns_parse(m.b, n, ID, "example.com", BST_DNS_TYPE_A, &a);
		ASSERT(st == BST_DNS_MALFORMED || st == BST_DNS_IGNORE);
	}
	/* rdlength of an A record that is not 4 */
	header(&m, ID, OKF, 1);
	question(&m, "example.com", BST_DNS_TYPE_A);
	rr_ptr(&m, 12, BST_DNS_TYPE_A, 60, "\x01\x02\x03", 3);
	ASSERT_EQ(bst_dns_parse(m.b, m.n, ID, "example.com", BST_DNS_TYPE_A, &a), BST_DNS_MALFORMED);
}

TEST(dns_oversize)
{
	msg m;
	header(&m, ID, OKF, 200);
	question(&m, "example.com", BST_DNS_TYPE_A);
	for (unsigned i = 0; i < 200; i++) {
		uint8_t ip[4] = { 10, 0, (uint8_t)(i >> 8), (uint8_t)i };
		rr_ptr(&m, 12, BST_DNS_TYPE_A, 60, ip, 4);
	}
	bst_dns_answer a;
	ASSERT_EQ(bst_dns_parse(m.b, m.n, ID, "example.com", BST_DNS_TYPE_A, &a), BST_DNS_OK);
	ASSERT_EQ(a.naddrs, BST_DNS_MAX_ADDRS);
	/* an answer count far above what the message holds */
	m.b[6] = 0xff;
	m.b[7] = 0xff;
	ASSERT_EQ(bst_dns_parse(m.b, m.n, ID, "example.com", BST_DNS_TYPE_A, &a), BST_DNS_MALFORMED);
	/* a name over 255 bytes made of pointers to 63-byte labels */
	header(&m, ID, OKF, 0);
	question(&m, "example.com", BST_DNS_TYPE_A);
	char longname[300];
	memset(longname, 'a', sizeof longname);
	for (int i = 63; i < 299; i += 64)
		longname[i] = '.';
	longname[299] = 0;
	ASSERT_EQ(bst_dns_query(m.b, sizeof m.b, 1, longname, BST_DNS_TYPE_A), 0);
}

/* ---- the config side ---- */

static bst_err E;

static bst_config *compile(const char *src)
{
	static bst_arena *a;
	if (a != NULL)
		bst_arena_free(a);
	a = bst_arena_new(1 << 16);
	bst_ast *ast = bst_cfg_parse_string(src, strlen(src), "t.conf", NULL, a, &E);
	return ast == NULL ? NULL : bst_cfg_compile(ast, &E);
}

TEST(upstream_peers)
{
	bst_config *c = compile("resolver 127.0.0.1:5353;\n"
				"upstream api { server 127.0.0.1:3000 weight=2; server [::1]:3001 backup;"
				" server app.invalid:80 resolve; keepalive 4; }\n"
				"server { listen 80; }");
	ASSERT(c != NULL);
	ASSERT_EQ(c->global.nupstreams, 1);
	bst_cfg_upstream *u = c->global.upstreams[0];
	ASSERT_STR(u->name, "api");
	ASSERT_EQ(u->nservers, 3);
	ASSERT_EQ(u->npeers, 2 + BST_UP_RESOLVE_SLOTS);
	ASSERT_EQ(u->peers[0].weight, 2);
	ASSERT_EQ(u->peers[0].addr.port, 3000);
	ASSERT(u->peers[1].backup);
	ASSERT_EQ(u->peers[1].addr.ip.family, BST_IP_V6);
	ASSERT(u->peers[2].dynamic);
	ASSERT_EQ(u->peers[9].state, 9);
	ASSERT_EQ(u->keepalive, 4);
	ASSERT_EQ(u->connect_timeout_ms, BST_UP_CONNECT_TIMEOUT_MS);
	ASSERT_EQ(c->global.resolver.addrs[0].port, 5353);
	ASSERT_EQ(c->global.resolver.ttl_min_ms, 5000);
	ASSERT_EQ(bst_upstate_nslots(c), 10);
	/* no shared region here: a dynamic peer has no address, a static one has its own */
	bst_sockaddr sa;
	ASSERT(!bst_peer_addr(&u->peers[2], &sa));
	ASSERT(bst_peer_addr(&u->peers[0], &sa));
	ASSERT_EQ(sa.port, 3000);
	bst_config_free(c);
}

TEST(upstream_publish)
{
	bst_config *c = compile("resolver 127.0.0.1;\n"
				"upstream api { server app.test:8080 resolve; }\nserver { listen 80; }");
	ASSERT(c != NULL);
	ASSERT_EQ(bst_upstate_setup(c, &E), 0);
	bst_cfg_upstream *u = c->global.upstreams[0];
	unsigned g0 = bst_upstate_gen();
	bst_ip ips[2];
	ASSERT(bst_addr_parse(BST_S("10.0.0.7"), &ips[0]));
	ASSERT(bst_addr_parse(BST_S("10.0.0.8"), &ips[1]));
	bst_upstate_publish(u, &u->servers[0], ips, 2);
	ASSERT(bst_upstate_gen() != g0);
	bst_sockaddr sa;
	ASSERT(bst_peer_addr(&u->peers[1], &sa));
	ASSERT_EQ(sa.port, 8080);
	ASSERT(bst_ip_eq(&sa.ip, &ips[1]));
	ASSERT(!bst_peer_addr(&u->peers[2], &sa));
	bst_upstate_publish(u, &u->servers[0], ips, 1); /* one address went away */
	ASSERT(!bst_peer_addr(&u->peers[1], &sa));
	bst_upstate_test_reset();
	bst_config_free(c);
}

TEST(upstream_errors)
{
	ASSERT(compile("upstream api { server app.test resolve; }\nserver { listen 80; }") == NULL);
	ASSERT(strstr(E.msg, "needs a `resolver`") != NULL);
	ASSERT(compile("upstream api { server host.invalid:80; }\nserver { listen 80; }") == NULL);
	ASSERT(strstr(E.msg, "does not resolve") != NULL);
	ASSERT(compile("upstream api { keepalive 1; }\nserver { listen 80; }") == NULL);
	ASSERT(strstr(E.msg, "no server") != NULL);
	ASSERT(compile("upstream a { server 127.0.0.1; }\nupstream a { server 127.0.0.1; }\n"
		       "server { listen 80; }") == NULL);
	ASSERT(strstr(E.msg, "defined twice") != NULL);
	ASSERT(compile("upstream a { server 127.0.0.1:0; }\nserver { listen 80; }") == NULL);
	ASSERT(compile("upstream a { server 10.0.0.1 resolve; }\nresolver 127.0.0.1;\n"
		       "server { listen 80; }") == NULL);
	ASSERT(compile("resolver example.com;\nserver { listen 80; }") == NULL);
}

TAP_MAIN()

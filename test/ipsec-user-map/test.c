/*
 * Unit test for the user map of proto_ipsec (helm KI-23 item 5): the users
 * behind one address are found by IMPI in a hash table that grows with
 * them, so a registration costs the same behind a NAT address with
 * thousands of UEs as behind an address of its own.
 *
 * ipsec_user.c is compiled in directly, on the stand-ins of stub/stub.h.
 */
#include "../../modules/proto_ipsec/ipsec_user.h"
#include "../../locking.h"
#include "../../hash_func.h"
#include "stub/stub.h"
#include "../../modules/proto_ipsec/ipsec_user.c"
#include <time.h>

/* referenced by ipsec_user.c, not reached by this test */
int ipsec_ctx_tryref(struct ipsec_ctx *ctx) { (void)ctx; return 0; }

static int failed;
#define CHECK(_c, ...) do { if (!(_c)) { failed++; \
	printf("FAIL %s:%d: ", __FILE__, __LINE__); printf(__VA_ARGS__); \
	printf("\n"); } } while (0)

static void mk_ip(struct ip_addr *ip, unsigned int n)
{
	memset(ip, 0, sizeof *ip);
	ip->af = AF_INET;
	ip->len = 4;
	ip->u.addr[0] = 10;
	ip->u.addr[1] = n >> 16;
	ip->u.addr[2] = n >> 8;
	ip->u.addr[3] = n;
}

static void mk_ids(unsigned int n, char *impi_buf, str *impi, char *impu_buf, str *impu)
{
	impi->s = impi_buf;
	impi->len = sprintf(impi_buf, "0010199999%05u@ims.mnc001.mcc001.3gppnetwork.org", n);
	impu->s = impu_buf;
	impu->len = sprintf(impu_buf, "sip:0010199999%05u@ims.mnc001.mcc001.3gppnetwork.org", n);
}

static double now(void)
{
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	return ts.tv_sec + ts.tv_nsec / 1e9;
}

/* registers n users behind one address; returns the mean time of a lookup of
 * an existing user in microseconds */
static double one_address(unsigned int n, struct ipsec_user **users)
{
	struct ip_addr ip;
	struct ipsec_user *user;
	char impi_buf[128], impu_buf[128];
	str impi, impu;
	unsigned int i, rounds = 20000;
	double start;

	mk_ip(&ip, 1);
	for (i = 0; i < n; i++) {
		mk_ids(i, impi_buf, &impi, impu_buf, &impu);
		users[i] = ipsec_get_user(&ip, &impi, &impu);
		CHECK(users[i], "user %u not created", i);
	}
	start = now();
	for (i = 0; i < rounds; i++) {
		mk_ids((i * 7919U) % n, impi_buf, &impi, impu_buf, &impu);
		user = ipsec_find_user(&ip, &impi, &impu);
		CHECK(user == users[(i * 7919U) % n], "lookup %u found %p", i, (void *)user);
		if (user)
			ipsec_release_user(user);
	}
	return (now() - start) / rounds * 1e6;
}

int main(int argc, char **argv)
{
	unsigned int n = (argc > 1?atoi(argv[1]):25000), i;
	struct ipsec_user **users = calloc(n, sizeof *users), *user, *again;
	struct ip_addr ip, other;
	char impi_buf[128], impu_buf[128], impu2_buf[128];
	str impi, impu, impu2;
	double small, large;

	CHECK(ipsec_map_init() == 0, "map init");

	/* the same user is returned for the same address, IMPI and IMPU; a
	 * second IMPU of the IMPI and another address are users of their own */
	mk_ip(&ip, 1);
	mk_ip(&other, 2);
	mk_ids(1, impi_buf, &impi, impu_buf, &impu);
	impu2.s = impu2_buf;
	impu2.len = sprintf(impu2_buf, "sip:+494099999950001@example.org");
	user = ipsec_get_user(&ip, &impi, &impu);
	again = ipsec_get_user(&ip, &impi, &impu);
	CHECK(user && user == again, "same identity gave another user");
	CHECK(user && user->ref == 2, "ref %d after two gets", user?user->ref:-1);
	ipsec_release_user(again);
	again = ipsec_get_user(&ip, &impi, &impu2);
	CHECK(again && again != user, "second IMPU shares the user");
	ipsec_release_user(again);
	CHECK(!ipsec_find_user(&ip, &impi, &impu2), "released IMPU still found");
	CHECK(!ipsec_find_user(&other, &impi, &impu), "user found behind another address");
	ipsec_release_user(user);
	CHECK(!ipsec_find_user(&ip, &impi, &impu), "released user still found");
	CHECK(ipsec_map_ipv4->size == 0, "map not empty: %u nodes", ipsec_map_ipv4->size);

	/* the cost of a lookup must not follow the number of users behind the
	 * address: that is the defect (a list walked for every REGISTER) */
	small = one_address(100, users);
	for (i = 0; i < 100; i++)
		ipsec_release_user(users[i]);
	CHECK(ipsec_map_ipv4->size == 0, "map not empty after 100 users");
	large = one_address(n, users);
	printf("lookup behind one address: %.2f us with 100 users, %.2f us with %u\n",
			small, large, n);
	CHECK(large < small * 5 + 1, "lookup time grows with the users behind an address");

	/* every user is still found after the table grew, none twice */
	for (i = 0; i < n; i++) {
		mk_ids(i, impi_buf, &impi, impu_buf, &impu);
		user = ipsec_find_user(&ip, &impi, &impu);
		CHECK(user == users[i], "user %u lost", i);
		if (user)
			ipsec_release_user(user);
	}
	/* released in another order than created; the rest stays reachable */
	for (i = 0; i < n; i += 2)
		ipsec_release_user(users[i]);
	for (i = 0; i < n; i++) {
		mk_ids(i, impi_buf, &impi, impu_buf, &impu);
		user = ipsec_find_user(&ip, &impi, &impu);
		CHECK((i % 2) ? user == users[i] : user == NULL, "user %u after partial release", i);
		if (user)
			ipsec_release_user(user);
	}
	for (i = 1; i < n; i += 2)
		ipsec_release_user(users[i]);
	CHECK(ipsec_map_ipv4->size == 0, "map not empty at the end: %u nodes", ipsec_map_ipv4->size);

	printf(failed?"FAILED (%d)\n":"ok\n", failed);
	return failed != 0;
}

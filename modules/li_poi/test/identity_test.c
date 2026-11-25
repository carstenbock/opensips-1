/*
 * Vectors of the canonical form. The same vectors are in the X1 agent
 * (helm: apps/li-x1-agent/apps/li_x1_agent/test/li_x1_identity_tests.erl).
 *
 *   cc -Wall -Wextra -o /tmp/identity_test test/identity_test.c li_identity.c
 *   /tmp/identity_test
 */

#include <stdio.h>
#include <string.h>
#include "../li_identity.h"

static const struct {
	int cls;
	const char *in;
	const char *expected;
} vectors[] = {
	{LI_CLASS_IMPU, "tel:+4915100099105", "tel:+4915100099105"},
	{LI_CLASS_IMPU, "TEL:+49-151-000.99105;phone-context=x", "tel:+4915100099105"},
	{LI_CLASS_IMPU, "sip:+4915100099105@ims.mnc024.mcc262.3gppnetwork.org",
		"tel:+4915100099105"},
	{LI_CLASS_IMPU, "sip:+4915100099105@IMS.Example.org;user=phone",
		"tel:+4915100099105"},
	{LI_CLASS_IMPU,
		"sips:+49(151)00099105:secret@example.org:5061;transport=tcp?a=b",
		"tel:+4915100099105"},
	{LI_CLASS_IMPU, "sip:Alice@Example.ORG:5060;transport=udp",
		"sip:Alice@example.org"},
	{LI_CLASS_IMPU, "sip:alice;x=y@example.org", "sip:alice@example.org"},
	{LI_CLASS_IMPU, "sip:015100099105@example.org",
		"sip:015100099105@example.org"},
	{LI_CLASS_IMPU, "tel:015100099105;phone-context=+49", "tel:015100099105"},
	{LI_CLASS_IMPU, "sip:conf@[2001:DB8::1]:5060", "sip:conf@[2001:db8::1]"},
	{LI_CLASS_IMPU, "sip:example.org", "sip:example.org"},
	{LI_CLASS_IMPU, " sip:a@b ", "sip:a@b"},
	{LI_CLASS_IMPI, "262240000099105@ims.MNC024.mcc262.3gppnetwork.org",
		"262240000099105@ims.mnc024.mcc262.3gppnetwork.org"},
	{LI_CLASS_IMPI, "User@Example.org", "User@example.org"},
	{LI_CLASS_IMEI, "35293809123456", "35293809123456"},
	{LI_CLASS_IMEI, "352938091234567", "35293809123456"},
	{LI_CLASS_IMEI, "urn:gsma:imei:35293809-123456-0", "35293809123456"},
	{LI_CLASS_IMEI, "3529380912345601", "35293809123456"},
};

int main(void)
{
	char out[256];
	unsigned int i;
	int n, failed = 0;

	for (i = 0; i < sizeof(vectors) / sizeof(vectors[0]); i++) {
		n = li_canonical(vectors[i].cls, vectors[i].in,
			(int)strlen(vectors[i].in), out, sizeof(out));
		if (n != (int)strlen(vectors[i].expected) ||
				memcmp(out, vectors[i].expected, n) != 0) {
			printf("FAIL %s -> %.*s, expected %s\n", vectors[i].in,
				n < 0 ? 0 : n, out, vectors[i].expected);
			failed++;
		}
	}

	/* an identity that does not fit is refused, not cut */
	if (li_canonical(LI_CLASS_IMPU, "sip:alice@example.org", 21, out, 8) != -1) {
		printf("FAIL short buffer accepted\n");
		failed++;
	}

	printf("%u vectors, %d failed\n", i, failed);
	return failed ? 1 : 0;
}

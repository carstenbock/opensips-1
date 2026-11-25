/*
 *   cc -Wall -Wextra -o /tmp/table_test test/table_test.c li_table.c
 *   /tmp/table_test
 */

#include <stdio.h>
#include <string.h>
#include "../li_table.h"

static int failed;

static void check(const char *what, int ok)
{
	if (!ok) {
		printf("FAIL %s\n", what);
		failed++;
	}
}

int main(void)
{
	/* version 7, salt "abcd", two entries */
	unsigned char body[4 + 1 + 4 + 4 + 2 * LI_ENTRY_LEN];
	struct li_parsed t;
	struct li_entry e;
	unsigned int len = sizeof(body);

	memset(body, 0, sizeof(body));
	body[3] = 7;
	body[4] = 4;
	memcpy(body + 5, "abcd", 4);
	body[12] = 2;
	memset(body + 13, 0x11, LI_XID_LEN);
	body[13 + LI_XID_LEN] = 1;
	body[13 + LI_XID_LEN + 1] = 3;
	memset(body + 13 + LI_XID_LEN + 2, 0x22, LI_DIGEST_LEN);
	memset(body + 13 + LI_ENTRY_LEN, 0x33, LI_ENTRY_LEN);

	check("valid table", li_parse_table(body, len, &t) == 0);
	check("version", t.version == 7);
	check("salt", t.salt_len == 4 && memcmp(t.salt, "abcd", 4) == 0);
	check("count", t.count == 2);
	li_parsed_entry(&t, 0, &e);
	check("entry 0", e.xid[0] == 0x11 && e.cls == 1 && e.delivery == 3 &&
		e.digest[31] == 0x22);
	li_parsed_entry(&t, 1, &e);
	check("entry 1", e.xid[15] == 0x33 && e.digest[0] == 0x33);

	/* A frame that does not add up must not be applied in part: a table
	 * with fewer entries than announced would drop interceptions. */
	check("truncated", li_parse_table(body, len - 1, &t) == -1);
	check("trailing octet", li_parse_table(body, len + 1, &t) == -1);
	body[12] = 3;
	check("count too large", li_parse_table(body, len, &t) == -1);
	body[9] = 0xff;
	check("count overflow", li_parse_table(body, len, &t) == -1);
	body[4] = LI_MAX_SALT + 1;
	check("salt too long", li_parse_table(body, len, &t) == -1);
	check("too short", li_parse_table(body, 4, &t) == -1);

	printf("table test: %d failed\n", failed);
	return failed ? 1 : 0;
}

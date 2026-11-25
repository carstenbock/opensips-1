/*
 * Parser of the task table frame. See li_table.h.
 *
 * Plain C without OpenSIPS headers, so that the test program builds alone.
 */

#include <string.h>
#include "li_table.h"

static unsigned int be32(const unsigned char *p)
{
	return ((unsigned int)p[0] << 24) | ((unsigned int)p[1] << 16) |
		((unsigned int)p[2] << 8) | (unsigned int)p[3];
}

int li_parse_table(const unsigned char *body, unsigned int len,
	struct li_parsed *out)
{
	unsigned int pos = 0;

	if (len < 4 + 1)
		return -1;
	out->version = be32(body);
	pos = 4;
	out->salt_len = body[pos++];
	if (out->salt_len > LI_MAX_SALT || len < pos + out->salt_len + 4)
		return -1;
	memcpy(out->salt, body + pos, out->salt_len);
	pos += out->salt_len;
	out->count = be32(body + pos);
	pos += 4;
	/* the entries fill the rest of the body exactly */
	if (out->count > (len - pos) / LI_ENTRY_LEN ||
			out->count * LI_ENTRY_LEN != len - pos)
		return -1;
	out->entries = body + pos;
	return 0;
}

void li_parsed_entry(const struct li_parsed *t, unsigned int i,
	struct li_entry *out)
{
	const unsigned char *p = t->entries + (size_t)i * LI_ENTRY_LEN;

	memcpy(out->xid, p, LI_XID_LEN);
	out->cls = p[LI_XID_LEN];
	out->delivery = p[LI_XID_LEN + 1];
	memcpy(out->digest, p + LI_XID_LEN + 2, LI_DIGEST_LEN);
}

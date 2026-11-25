/*
 * The task table of the point of interception: digests of target
 * identifiers and the tasks (XIDs) they belong to. It never holds an
 * identifier.
 *
 * The X2/X3 forwarder of the pod sends the table on its Unix socket, once
 * after the connection is made and again after every change:
 *
 *   "LIT1"  u32 body_len
 *   body:   u32 version
 *           u8 salt_len, salt
 *           u32 count
 *           count * { u8 xid[16], u8 class, u8 delivery, u8 digest[32] }
 *
 * Integers are in network byte order. A digest is SHA-256 over the
 * canonical identifier (li_identity.h) followed by the salt, as in ETSI
 * TS 103 221-1 Annex D.2.3.2.
 */

#ifndef LI_TABLE_H
#define LI_TABLE_H

#define LI_XID_LEN 16
#define LI_DIGEST_LEN 32
#define LI_MAX_SALT 64
#define LI_ENTRY_LEN (LI_XID_LEN + 2 + LI_DIGEST_LEN)
/* refuse a frame beyond this: 100000 entries */
#define LI_MAX_BODY (4 + 1 + LI_MAX_SALT + 4 + 100000 * LI_ENTRY_LEN)

struct li_entry {
	unsigned char xid[LI_XID_LEN];
	unsigned char cls;
	unsigned char delivery;
	unsigned char digest[LI_DIGEST_LEN];
};

struct li_parsed {
	unsigned int version;
	unsigned char salt[LI_MAX_SALT];
	int salt_len;
	unsigned int count;
	/* points into the frame body */
	const unsigned char *entries;
};

/* 0 if body is a valid table, -1 otherwise */
int li_parse_table(const unsigned char *body, unsigned int len,
	struct li_parsed *out);

/* the i-th entry of a parsed table */
void li_parsed_entry(const struct li_parsed *t, unsigned int i,
	struct li_entry *out);

#endif

/*
 * Canonical form of a target identifier, taken before it is hashed.
 *
 * The X1 agent of the platform (li-x1-agent, li_x1_identity.erl) computes
 * the same form for the identifier of a task and hashes it with the same
 * salt. Both sides are tested with the same vectors (test/identity_test.c).
 * A change here without the same change there ends every interception
 * without an error.
 *
 *   IMPU  tel URI, or SIP URI whose user part is an E.164 number:
 *           "tel:+<digits>"         (so every alias of a number matches)
 *         other tel URI:  "tel:<number without visual separators>"
 *         other SIP URI:  "sip:<user>@<host in lower case>"
 *                         without password, parameters, port and headers
 *   IMPI  "<user>@<realm in lower case>"
 *   IMEI  the first 14 digits
 */

#ifndef LI_IDENTITY_H
#define LI_IDENTITY_H

#define LI_CLASS_IMPU 1
#define LI_CLASS_IMPI 2
#define LI_CLASS_IMEI 3

/*
 * Writes the canonical form of in[0..in_len) to out and returns its length,
 * or -1 if it does not fit into out_size. No terminating zero is written.
 */
int li_canonical(int cls, const char *in, int in_len, char *out, int out_size);

#endif

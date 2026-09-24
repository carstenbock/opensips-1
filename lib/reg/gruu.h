/*
 * Temporary GRUU construction (RFC 5627).
 *
 * Encrypted format: the historical "<time> <aor> <instance> <callid>"
 * string sealed with ChaCha20-Poly1305 under a key derived from
 * gruu_secret, so any process that holds the same secret can recover
 * the AoR without usrloc state.
 *
 * Token format (gruu_cachedb_url set): 22 base64url characters that
 * decrypt to a binding id, resolved through one cachedb entry per AoR,
 * instance and Call-ID (RFC 5627 Appendix A.2).
 *
 * Copyright (C) 2026 OpenSIPS Solutions
 *
 * This file is part of opensips, a free SIP server.
 *
 * opensips is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version
 *
 * opensips is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */

#ifndef __LIB_REG_GRUU_H__
#define __LIB_REG_GRUU_H__

#include "../../str.h"

#define TEMP_GRUU_HEADER "tgruu."
#define TEMP_GRUU_HEADER_SIZE (sizeof(TEMP_GRUU_HEADER) - 1)

/* Defined by registrar and mid_registrar. */
extern int gruu_legacy_xor;
extern int gruu_legacy_host;
extern str gruu_domain;
extern str gruu_cachedb_url;
extern str gruu_imei_namespace;

struct socket_info;

int reg_gruu_init(void);

/* Opens the per-process gruu_cachedb_url connection. Call from child_init. */
int reg_gruu_child_init(void);

/* Host of a GRUU. *user is the public-GRUU user part (ignored for a
 * temporary GRUU). *host is empty when *user already contains the domain.
 * Returns 0 on success. */
int reg_gruu_target(const str *aor, const struct socket_info *sock,
		int temporary, str *user, str *host);

/* Upper bound of a temporary GRUU user part, excluding the "tgruu." prefix.
 * Returns 0 when the contact cannot carry a temporary GRUU. */
int calc_temp_gruu_len(str *aor, str *instance, str *callid);

/* Writes the user part after "tgruu." to out, at most calc_temp_gruu_len()
 * bytes. expires is the absolute contact expiry (0 = permanent). Returns
 * the number of bytes written, or -1 on failure. */
int build_temp_gruu(str *aor, str *instance, str *callid, int expires,
		char *out);

/* user is the user part after "tgruu.". On success the three strings
 * point into a static buffer. Returns 0 on success. */
int reg_temp_gruu_decode(const str *user, str *aor, str *instance,
		str *call_id);

/* The "gr" value of the public GRUU for a stored instance ("<...>"). An
 * IMEI URN maps to a name-based UUID (TS 24.229 5.4.7A.2); any other
 * instance is returned as is. gr may point into a static buffer. */
void reg_pub_gruu_gr(const str *instance, str *gr);

#endif /* __LIB_REG_GRUU_H__ */

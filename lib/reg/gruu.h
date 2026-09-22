/*
 * Temporary GRUU construction (RFC 5627).
 *
 * The plaintext is the historical "<time> <aor> <instance> <callid>"
 * string. It is sealed with ChaCha20-Poly1305 under a key derived from
 * gruu_secret, so any process that holds the same secret can recover
 * the AoR without usrloc state.
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

struct socket_info;

int reg_gruu_init(void);

/* Host of a GRUU. *user is the public-GRUU user part (ignored for a
 * temporary GRUU). *host is empty when *user already contains the domain.
 * Returns 0 on success. */
int reg_gruu_target(const str *aor, const struct socket_info *sock,
		int temporary, str *user, str *host);

/* Base64 length of a temporary GRUU user-part, excluding the "tgruu." prefix.
 * Returns 0 when the contact cannot carry a temporary GRUU. */
int calc_temp_gruu_len(str *aor, str *instance, str *callid);

/* Static buffer holding nonce || ciphertext || tag. *len is the byte count
 * to pass to base64encode(). NULL on failure. */
char *build_temp_gruu(str *aor, str *instance, str *callid, int *len);

/* user is the base64 blob after "tgruu.". On success the three strings
 * point into a static buffer. Returns 0 on success. */
int reg_temp_gruu_decode(const str *user, str *aor, str *instance,
		str *call_id);

#endif /* __LIB_REG_GRUU_H__ */

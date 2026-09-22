/*
 * AES-128 single-block cipher (FIPS 197) for temporary GRUU tokens.
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

#ifndef __LIB_REG_AES128_H__
#define __LIB_REG_AES128_H__

#include <stdint.h>

#define AES128_KEY_LEN   16
#define AES128_BLOCK_LEN 16

typedef struct aes128_ctx {
	uint8_t rk[176];
} aes128_ctx;

void aes128_setkey(aes128_ctx *ctx, const uint8_t key[AES128_KEY_LEN]);
void aes128_encrypt(const aes128_ctx *ctx, const uint8_t in[AES128_BLOCK_LEN],
		uint8_t out[AES128_BLOCK_LEN]);
void aes128_decrypt(const aes128_ctx *ctx, const uint8_t in[AES128_BLOCK_LEN],
		uint8_t out[AES128_BLOCK_LEN]);

/* FIPS 197 Appendix C.1, both directions. Returns 0 on success. */
int aes128_selftest(void);

#endif /* __LIB_REG_AES128_H__ */

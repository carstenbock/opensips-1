/*
 * ChaCha20-Poly1305 (RFC 8439) for temporary GRUU encryption.
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

#ifndef __LIB_REG_AEAD_H__
#define __LIB_REG_AEAD_H__

#include <stddef.h>
#include <stdint.h>

#define AEAD_KEY_LEN   32
#define AEAD_NONCE_LEN 12
#define AEAD_TAG_LEN   16

int aead_chacha20_poly1305_encrypt(const uint8_t key[AEAD_KEY_LEN],
		const uint8_t nonce[AEAD_NONCE_LEN],
		const uint8_t *aad, size_t aad_len,
		const uint8_t *pt, size_t pt_len,
		uint8_t *ct, uint8_t tag[AEAD_TAG_LEN]);

int aead_chacha20_poly1305_decrypt(const uint8_t key[AEAD_KEY_LEN],
		const uint8_t nonce[AEAD_NONCE_LEN],
		const uint8_t *aad, size_t aad_len,
		const uint8_t *ct, size_t ct_len,
		const uint8_t tag[AEAD_TAG_LEN],
		uint8_t *pt);

/* RFC 8439 §2.8.2. Returns 0 on success. */
int aead_chacha20_poly1305_selftest(void);

#endif /* __LIB_REG_AEAD_H__ */

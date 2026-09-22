/*
 * ChaCha20-Poly1305 as specified in RFC 8439.
 *
 * The 26-bit limb Poly1305 arithmetic is the construction described in
 * RFC 8439 §2.5. No secret-dependent branches are taken in the MAC.
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

#include <string.h>

#include "aead.h"

static uint32_t load32_le(const uint8_t *p)
{
	return (uint32_t)p[0]
		| ((uint32_t)p[1] << 8)
		| ((uint32_t)p[2] << 16)
		| ((uint32_t)p[3] << 24);
}

static void store32_le(uint8_t *p, uint32_t v)
{
	p[0] = (uint8_t)v;
	p[1] = (uint8_t)(v >> 8);
	p[2] = (uint8_t)(v >> 16);
	p[3] = (uint8_t)(v >> 24);
}

static void store64_le(uint8_t *p, uint64_t v)
{
	int i;

	for (i = 0; i < 8; i++) {
		p[i] = (uint8_t)v;
		v >>= 8;
	}
}

static uint32_t rotl32(uint32_t x, int n)
{
	return (x << n) | (x >> (32 - n));
}

static void quarterround(uint32_t *s, int a, int b, int c, int d)
{
	s[a] += s[b]; s[d] ^= s[a]; s[d] = rotl32(s[d], 16);
	s[c] += s[d]; s[b] ^= s[c]; s[b] = rotl32(s[b], 12);
	s[a] += s[b]; s[d] ^= s[a]; s[d] = rotl32(s[d], 8);
	s[c] += s[d]; s[b] ^= s[c]; s[b] = rotl32(s[b], 7);
}

/* RFC 8439 §2.3. keystream block. counter is the 32-bit block counter. */
static void chacha20_block(const uint8_t key[32], const uint8_t nonce[12],
		uint32_t counter, uint8_t out[64])
{
	uint32_t s[16], w[16];
	int i;

	s[0] = 0x61707865;
	s[1] = 0x3320646e;
	s[2] = 0x79622d32;
	s[3] = 0x6b206574;
	s[4] = load32_le(key + 0);
	s[5] = load32_le(key + 4);
	s[6] = load32_le(key + 8);
	s[7] = load32_le(key + 12);
	s[8] = load32_le(key + 16);
	s[9] = load32_le(key + 20);
	s[10] = load32_le(key + 24);
	s[11] = load32_le(key + 28);
	s[12] = counter;
	s[13] = load32_le(nonce + 0);
	s[14] = load32_le(nonce + 4);
	s[15] = load32_le(nonce + 8);

	memcpy(w, s, sizeof w);
	for (i = 0; i < 10; i++) {
		quarterround(w, 0, 4, 8, 12);
		quarterround(w, 1, 5, 9, 13);
		quarterround(w, 2, 6, 10, 14);
		quarterround(w, 3, 7, 11, 15);
		quarterround(w, 0, 5, 10, 15);
		quarterround(w, 1, 6, 11, 12);
		quarterround(w, 2, 7, 8, 13);
		quarterround(w, 3, 4, 9, 14);
	}
	for (i = 0; i < 16; i++)
		store32_le(out + 4 * i, w[i] + s[i]);
}

static void chacha20_xor(const uint8_t key[32], const uint8_t nonce[12],
		uint32_t counter, uint8_t *out, const uint8_t *in, size_t len)
{
	uint8_t block[64];
	size_t i, n;

	while (len) {
		chacha20_block(key, nonce, counter++, block);
		n = len < 64 ? len : 64;
		for (i = 0; i < n; i++)
			out[i] = in[i] ^ block[i];
		out += n;
		in += n;
		len -= n;
	}
	memset(block, 0, sizeof block);
}

struct poly1305_ctx {
	uint32_t r[5];
	uint32_t h[5];
	uint32_t s[4];
	uint8_t buf[16];
	size_t n;
};

static void poly1305_blocks(struct poly1305_ctx *st, const uint8_t *m,
		size_t bytes, uint32_t hibit)
{
	const uint32_t r0 = st->r[0];
	const uint32_t r1 = st->r[1];
	const uint32_t r2 = st->r[2];
	const uint32_t r3 = st->r[3];
	const uint32_t r4 = st->r[4];
	const uint32_t s1 = r1 * 5;
	const uint32_t s2 = r2 * 5;
	const uint32_t s3 = r3 * 5;
	const uint32_t s4 = r4 * 5;
	uint32_t h0 = st->h[0];
	uint32_t h1 = st->h[1];
	uint32_t h2 = st->h[2];
	uint32_t h3 = st->h[3];
	uint32_t h4 = st->h[4];

	while (bytes >= 16) {
		uint64_t d0, d1, d2, d3, d4;
		uint32_t c;

		h0 += load32_le(m + 0) & 0x3ffffff;
		h1 += (load32_le(m + 3) >> 2) & 0x3ffffff;
		h2 += (load32_le(m + 6) >> 4) & 0x3ffffff;
		h3 += (load32_le(m + 9) >> 6) & 0x3ffffff;
		h4 += (load32_le(m + 12) >> 8) | hibit;

		d0 = (uint64_t)h0 * r0 + (uint64_t)h1 * s4 + (uint64_t)h2 * s3
			+ (uint64_t)h3 * s2 + (uint64_t)h4 * s1;
		d1 = (uint64_t)h0 * r1 + (uint64_t)h1 * r0 + (uint64_t)h2 * s4
			+ (uint64_t)h3 * s3 + (uint64_t)h4 * s2;
		d2 = (uint64_t)h0 * r2 + (uint64_t)h1 * r1 + (uint64_t)h2 * r0
			+ (uint64_t)h3 * s4 + (uint64_t)h4 * s3;
		d3 = (uint64_t)h0 * r3 + (uint64_t)h1 * r2 + (uint64_t)h2 * r1
			+ (uint64_t)h3 * r0 + (uint64_t)h4 * s4;
		d4 = (uint64_t)h0 * r4 + (uint64_t)h1 * r3 + (uint64_t)h2 * r2
			+ (uint64_t)h3 * r1 + (uint64_t)h4 * r0;

		c = (uint32_t)(d0 >> 26); h0 = (uint32_t)d0 & 0x3ffffff;
		d1 += c; c = (uint32_t)(d1 >> 26); h1 = (uint32_t)d1 & 0x3ffffff;
		d2 += c; c = (uint32_t)(d2 >> 26); h2 = (uint32_t)d2 & 0x3ffffff;
		d3 += c; c = (uint32_t)(d3 >> 26); h3 = (uint32_t)d3 & 0x3ffffff;
		d4 += c; c = (uint32_t)(d4 >> 26); h4 = (uint32_t)d4 & 0x3ffffff;
		h0 += c * 5; c = h0 >> 26; h0 &= 0x3ffffff;
		h1 += c;

		m += 16;
		bytes -= 16;
	}

	st->h[0] = h0;
	st->h[1] = h1;
	st->h[2] = h2;
	st->h[3] = h3;
	st->h[4] = h4;
}

static void poly1305_init(struct poly1305_ctx *st, const uint8_t key[32])
{
	uint32_t t0, t1, t2, t3;

	memset(st, 0, sizeof *st);
	t0 = load32_le(key + 0);
	t1 = load32_le(key + 4);
	t2 = load32_le(key + 8);
	t3 = load32_le(key + 12);
	st->r[0] = t0 & 0x3ffffff;
	st->r[1] = ((t0 >> 26) | (t1 << 6)) & 0x3ffff03;
	st->r[2] = ((t1 >> 20) | (t2 << 12)) & 0x3ffc0ff;
	st->r[3] = ((t2 >> 14) | (t3 << 18)) & 0x3f03fff;
	st->r[4] = (t3 >> 8) & 0x00fffff;
	st->s[0] = load32_le(key + 16);
	st->s[1] = load32_le(key + 20);
	st->s[2] = load32_le(key + 24);
	st->s[3] = load32_le(key + 28);
}

static void poly1305_update(struct poly1305_ctx *st, const uint8_t *m,
		size_t bytes)
{
	if (st->n) {
		size_t want = 16 - st->n;
		if (want > bytes)
			want = bytes;
		memcpy(st->buf + st->n, m, want);
		st->n += want;
		m += want;
		bytes -= want;
		if (st->n == 16) {
			poly1305_blocks(st, st->buf, 16, 1u << 24);
			st->n = 0;
		}
	}
	if (bytes >= 16) {
		size_t full = bytes & ~(size_t)15;
		poly1305_blocks(st, m, full, 1u << 24);
		m += full;
		bytes -= full;
	}
	if (bytes) {
		memcpy(st->buf + st->n, m, bytes);
		st->n += bytes;
	}
}

static void poly1305_finish(struct poly1305_ctx *st, uint8_t mac[16])
{
	uint32_t h0, h1, h2, h3, h4, c;
	uint32_t g0, g1, g2, g3, g4, mask;
	uint64_t f;

	if (st->n) {
		uint8_t block[16];
		size_t i;

		for (i = 0; i < st->n; i++)
			block[i] = st->buf[i];
		block[st->n] = 1;
		for (i = st->n + 1; i < 16; i++)
			block[i] = 0;
		poly1305_blocks(st, block, 16, 0);
		memset(block, 0, sizeof block);
	}

	h0 = st->h[0];
	h1 = st->h[1];
	h2 = st->h[2];
	h3 = st->h[3];
	h4 = st->h[4];

	c = h1 >> 26; h1 &= 0x3ffffff; h2 += c;
	c = h2 >> 26; h2 &= 0x3ffffff; h3 += c;
	c = h3 >> 26; h3 &= 0x3ffffff; h4 += c;
	c = h4 >> 26; h4 &= 0x3ffffff; h0 += c * 5;
	c = h0 >> 26; h0 &= 0x3ffffff; h1 += c;

	g0 = h0 + 5; c = g0 >> 26; g0 &= 0x3ffffff;
	g1 = h1 + c; c = g1 >> 26; g1 &= 0x3ffffff;
	g2 = h2 + c; c = g2 >> 26; g2 &= 0x3ffffff;
	g3 = h3 + c; c = g3 >> 26; g3 &= 0x3ffffff;
	g4 = h4 + c - (1u << 26);

	mask = (g4 >> 31) - 1u;
	g0 &= mask;
	g1 &= mask;
	g2 &= mask;
	g3 &= mask;
	g4 &= mask;
	mask = ~mask;
	h0 = (h0 & mask) | g0;
	h1 = (h1 & mask) | g1;
	h2 = (h2 & mask) | g2;
	h3 = (h3 & mask) | g3;
	h4 = (h4 & mask) | g4;

	h0 = (h0 | (h1 << 26)) & 0xffffffff;
	h1 = ((h1 >> 6) | (h2 << 20)) & 0xffffffff;
	h2 = ((h2 >> 12) | (h3 << 14)) & 0xffffffff;
	h3 = ((h3 >> 18) | (h4 << 8)) & 0xffffffff;

	f = (uint64_t)h0 + st->s[0]; h0 = (uint32_t)f;
	f = (uint64_t)h1 + st->s[1] + (f >> 32); h1 = (uint32_t)f;
	f = (uint64_t)h2 + st->s[2] + (f >> 32); h2 = (uint32_t)f;
	f = (uint64_t)h3 + st->s[3] + (f >> 32); h3 = (uint32_t)f;

	store32_le(mac + 0, h0);
	store32_le(mac + 4, h1);
	store32_le(mac + 8, h2);
	store32_le(mac + 12, h3);
}

static void poly1305_pad16(struct poly1305_ctx *st, size_t len)
{
	static const uint8_t zeros[16] = {0};
	size_t rem = len & 15;

	if (rem)
		poly1305_update(st, zeros, 16 - rem);
}

static int ct_memeq(const uint8_t *a, const uint8_t *b, size_t n)
{
	uint8_t d = 0;
	size_t i;

	for (i = 0; i < n; i++)
		d |= a[i] ^ b[i];
	return d == 0;
}

static void aead_mac(const uint8_t *otk,
		const uint8_t *aad, size_t aad_len,
		const uint8_t *ct, size_t ct_len,
		uint8_t tag[AEAD_TAG_LEN])
{
	struct poly1305_ctx ctx;
	uint8_t lens[16];

	poly1305_init(&ctx, otk);
	poly1305_update(&ctx, aad, aad_len);
	poly1305_pad16(&ctx, aad_len);
	poly1305_update(&ctx, ct, ct_len);
	poly1305_pad16(&ctx, ct_len);
	store64_le(lens, (uint64_t)aad_len);
	store64_le(lens + 8, (uint64_t)ct_len);
	poly1305_update(&ctx, lens, 16);
	poly1305_finish(&ctx, tag);
	memset(&ctx, 0, sizeof ctx);
}

int aead_chacha20_poly1305_encrypt(const uint8_t key[AEAD_KEY_LEN],
		const uint8_t nonce[AEAD_NONCE_LEN],
		const uint8_t *aad, size_t aad_len,
		const uint8_t *pt, size_t pt_len,
		uint8_t *ct, uint8_t tag[AEAD_TAG_LEN])
{
	uint8_t otk[64];
	uint8_t zeros[64];

	memset(zeros, 0, sizeof zeros);
	/* RFC 8439 §2.6: Poly1305 key is the first 32 bytes of block 0. */
	chacha20_xor(key, nonce, 0, otk, zeros, 64);
	if (pt_len)
		chacha20_xor(key, nonce, 1, ct, pt, pt_len);
	aead_mac(otk, aad, aad_len, ct, pt_len, tag);
	memset(otk, 0, sizeof otk);
	return 0;
}

int aead_chacha20_poly1305_decrypt(const uint8_t key[AEAD_KEY_LEN],
		const uint8_t nonce[AEAD_NONCE_LEN],
		const uint8_t *aad, size_t aad_len,
		const uint8_t *ct, size_t ct_len,
		const uint8_t tag[AEAD_TAG_LEN],
		uint8_t *pt)
{
	uint8_t otk[64];
	uint8_t zeros[64];
	uint8_t expect[AEAD_TAG_LEN];
	int ok;

	memset(zeros, 0, sizeof zeros);
	chacha20_xor(key, nonce, 0, otk, zeros, 64);
	aead_mac(otk, aad, aad_len, ct, ct_len, expect);
	memset(otk, 0, sizeof otk);
	ok = ct_memeq(expect, tag, AEAD_TAG_LEN);
	memset(expect, 0, sizeof expect);
	if (!ok)
		return -1;
	if (ct_len)
		chacha20_xor(key, nonce, 1, pt, ct, ct_len);
	return 0;
}

int aead_chacha20_poly1305_selftest(void)
{
	/* RFC 8439 §2.5.2 */
	static const uint8_t poly_key[32] = {
		0x85,0xd6,0xbe,0x78,0x57,0x55,0x6d,0x33,
		0x7f,0x44,0x52,0xfe,0x42,0xd5,0x06,0xa8,
		0x01,0x03,0x80,0x8a,0xfb,0x0d,0xb2,0xfd,
		0x4a,0xbf,0xf6,0xaf,0x41,0x49,0xf5,0x1b
	};
	static const uint8_t poly_msg[] =
		"Cryptographic Forum Research Group";
	static const uint8_t poly_tag[16] = {
		0xa8,0x06,0x1d,0xc1,0x30,0x51,0x36,0xc6,
		0xc2,0x2b,0x8b,0xaf,0x0c,0x01,0x27,0xa9
	};
	/* RFC 8439 §2.8.2 */
	static const uint8_t key[32] = {
		0x80,0x81,0x82,0x83,0x84,0x85,0x86,0x87,
		0x88,0x89,0x8a,0x8b,0x8c,0x8d,0x8e,0x8f,
		0x90,0x91,0x92,0x93,0x94,0x95,0x96,0x97,
		0x98,0x99,0x9a,0x9b,0x9c,0x9d,0x9e,0x9f
	};
	static const uint8_t nonce[12] = {
		0x07,0x00,0x00,0x00,0x40,0x41,0x42,0x43,
		0x44,0x45,0x46,0x47
	};
	static const uint8_t aad[12] = {
		0x50,0x51,0x52,0x53,0xc0,0xc1,0xc2,0xc3,
		0xc4,0xc5,0xc6,0xc7
	};
	static const uint8_t pt[] =
		"Ladies and Gentlemen of the class of '99: If I could offer you "
		"only one tip for the future, sunscreen would be it.";
	static const uint8_t ct_expect[] = {
		0xd3,0x1a,0x8d,0x34,0x64,0x8e,0x60,0xdb,
		0x7b,0x86,0xaf,0xbc,0x53,0xef,0x7e,0xc2,
		0xa4,0xad,0xed,0x51,0x29,0x6e,0x08,0xfe,
		0xa9,0xe2,0xb5,0xa7,0x36,0xee,0x62,0xd6,
		0x3d,0xbe,0xa4,0x5e,0x8c,0xa9,0x67,0x12,
		0x82,0xfa,0xfb,0x69,0xda,0x92,0x72,0x8b,
		0x1a,0x71,0xde,0x0a,0x9e,0x06,0x0b,0x29,
		0x05,0xd6,0xa5,0xb6,0x7e,0xcd,0x3b,0x36,
		0x92,0xdd,0xbd,0x7f,0x2d,0x77,0x8b,0x8c,
		0x98,0x03,0xae,0xe3,0x28,0x09,0x1b,0x58,
		0xfa,0xb3,0x24,0xe4,0xfa,0xd6,0x75,0x94,
		0x55,0x85,0x80,0x8b,0x48,0x31,0xd7,0xbc,
		0x3f,0xf4,0xde,0xf0,0x8e,0x4b,0x7a,0x9d,
		0xe5,0x76,0xd2,0x65,0x86,0xce,0xc6,0x4b,
		0x61,0x16
	};
	static const uint8_t tag_expect[16] = {
		0x1a,0xe1,0x0b,0x59,0x4f,0x09,0xe2,0x6a,
		0x7e,0x90,0x2e,0xcb,0xd0,0x60,0x06,0x91
	};
	struct poly1305_ctx pctx;
	uint8_t tag[16];
	uint8_t ct[sizeof ct_expect];
	uint8_t roundtrip[sizeof pt];
	size_t pt_len = sizeof pt - 1; /* drop the C string NUL */

	poly1305_init(&pctx, poly_key);
	poly1305_update(&pctx, poly_msg, sizeof poly_msg - 1);
	poly1305_finish(&pctx, tag);
	if (!ct_memeq(tag, poly_tag, 16))
		return -1;

	if (pt_len != sizeof ct_expect)
		return -1;
	if (aead_chacha20_poly1305_encrypt(key, nonce, aad, sizeof aad,
			pt, pt_len, ct, tag) != 0)
		return -1;
	if (!ct_memeq(ct, ct_expect, sizeof ct_expect))
		return -1;
	if (!ct_memeq(tag, tag_expect, 16))
		return -1;
	if (aead_chacha20_poly1305_decrypt(key, nonce, aad, sizeof aad,
			ct, pt_len, tag, roundtrip) != 0)
		return -1;
	if (!ct_memeq(roundtrip, pt, pt_len))
		return -1;
	tag[0] ^= 0x01;
	if (aead_chacha20_poly1305_decrypt(key, nonce, aad, sizeof aad,
			ct, pt_len, tag, roundtrip) == 0)
		return -1;
	return 0;
}

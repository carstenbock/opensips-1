/*
 * AES-128 single-block cipher as specified in FIPS 197.
 *
 * The S-boxes are computed from the GF(2^8) inverse and the affine map
 * (FIPS 197 §5.1.1) instead of being typed in, and the self-test checks
 * the result against Appendix C.1. The lookups are table based, so the
 * cipher is not constant-time with respect to cache timing.
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

#include "aes128.h"

static uint8_t sbox[256];
static uint8_t rsbox[256];
static int tables_ready;

static uint8_t gmul(uint8_t a, uint8_t b)
{
	uint8_t p = 0;

	while (b) {
		if (b & 1)
			p ^= a;
		a = (uint8_t)((a << 1) ^ ((a & 0x80) ? 0x1b : 0x00));
		b >>= 1;
	}
	return p;
}

static uint8_t rotl8(uint8_t x, int n)
{
	return (uint8_t)((x << n) | (x >> (8 - n)));
}

static void aes128_tables_init(void)
{
	int x, y;
	uint8_t inv, s;

	if (tables_ready)
		return;
	for (x = 0; x < 256; x++) {
		inv = 0;
		if (x) {
			for (y = 1; y < 256; y++)
				if (gmul((uint8_t)x, (uint8_t)y) == 1) {
					inv = (uint8_t)y;
					break;
				}
		}
		s = (uint8_t)(inv ^ rotl8(inv, 1) ^ rotl8(inv, 2) ^ rotl8(inv, 3)
				^ rotl8(inv, 4) ^ 0x63);
		sbox[x] = s;
		rsbox[s] = (uint8_t)x;
	}
	tables_ready = 1;
}

void aes128_setkey(aes128_ctx *ctx, const uint8_t key[AES128_KEY_LEN])
{
	static const uint8_t rcon[10] = {
		0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1b,0x36
	};
	uint8_t *w = ctx->rk;
	uint8_t t[4], tmp;
	int i;

	aes128_tables_init();
	memcpy(w, key, AES128_KEY_LEN);
	for (i = 4; i < 44; i++) {
		memcpy(t, w + (i - 1) * 4, 4);
		if (i % 4 == 0) {
			tmp = t[0];
			t[0] = (uint8_t)(sbox[t[1]] ^ rcon[i / 4 - 1]);
			t[1] = sbox[t[2]];
			t[2] = sbox[t[3]];
			t[3] = sbox[tmp];
		}
		w[i * 4 + 0] = w[(i - 4) * 4 + 0] ^ t[0];
		w[i * 4 + 1] = w[(i - 4) * 4 + 1] ^ t[1];
		w[i * 4 + 2] = w[(i - 4) * 4 + 2] ^ t[2];
		w[i * 4 + 3] = w[(i - 4) * 4 + 3] ^ t[3];
	}
}

static void add_round_key(uint8_t *st, const uint8_t *rk)
{
	int i;

	for (i = 0; i < 16; i++)
		st[i] ^= rk[i];
}

/* The state is column-major: st[c * 4 + r]. */
static void shift_rows(uint8_t *st, int inverse)
{
	uint8_t o[16];
	int r, c;

	memcpy(o, st, 16);
	for (c = 0; c < 4; c++)
		for (r = 0; r < 4; r++) {
			if (inverse)
				st[((c + r) % 4) * 4 + r] = o[c * 4 + r];
			else
				st[c * 4 + r] = o[((c + r) % 4) * 4 + r];
		}
}

static void mix_columns(uint8_t *st, int inverse)
{
	uint8_t a0, a1, a2, a3, *col;
	int c;

	for (c = 0; c < 4; c++) {
		col = st + c * 4;
		a0 = col[0]; a1 = col[1]; a2 = col[2]; a3 = col[3];
		if (!inverse) {
			col[0] = gmul(a0,2) ^ gmul(a1,3) ^ a2 ^ a3;
			col[1] = a0 ^ gmul(a1,2) ^ gmul(a2,3) ^ a3;
			col[2] = a0 ^ a1 ^ gmul(a2,2) ^ gmul(a3,3);
			col[3] = gmul(a0,3) ^ a1 ^ a2 ^ gmul(a3,2);
		} else {
			col[0] = gmul(a0,14) ^ gmul(a1,11) ^ gmul(a2,13) ^ gmul(a3,9);
			col[1] = gmul(a0,9) ^ gmul(a1,14) ^ gmul(a2,11) ^ gmul(a3,13);
			col[2] = gmul(a0,13) ^ gmul(a1,9) ^ gmul(a2,14) ^ gmul(a3,11);
			col[3] = gmul(a0,11) ^ gmul(a1,13) ^ gmul(a2,9) ^ gmul(a3,14);
		}
	}
}

static void sub_bytes(uint8_t *st, const uint8_t *box)
{
	int i;

	for (i = 0; i < 16; i++)
		st[i] = box[st[i]];
}

void aes128_encrypt(const aes128_ctx *ctx, const uint8_t in[AES128_BLOCK_LEN],
		uint8_t out[AES128_BLOCK_LEN])
{
	uint8_t st[16];
	int round;

	memcpy(st, in, 16);
	add_round_key(st, ctx->rk);
	for (round = 1; round < 10; round++) {
		sub_bytes(st, sbox);
		shift_rows(st, 0);
		mix_columns(st, 0);
		add_round_key(st, ctx->rk + round * 16);
	}
	sub_bytes(st, sbox);
	shift_rows(st, 0);
	add_round_key(st, ctx->rk + 160);
	memcpy(out, st, 16);
	memset(st, 0, sizeof st);
}

void aes128_decrypt(const aes128_ctx *ctx, const uint8_t in[AES128_BLOCK_LEN],
		uint8_t out[AES128_BLOCK_LEN])
{
	uint8_t st[16];
	int round;

	memcpy(st, in, 16);
	add_round_key(st, ctx->rk + 160);
	for (round = 9; round > 0; round--) {
		shift_rows(st, 1);
		sub_bytes(st, rsbox);
		add_round_key(st, ctx->rk + round * 16);
		mix_columns(st, 1);
	}
	shift_rows(st, 1);
	sub_bytes(st, rsbox);
	add_round_key(st, ctx->rk);
	memcpy(out, st, 16);
	memset(st, 0, sizeof st);
}

int aes128_selftest(void)
{
	static const uint8_t key[16] = {
		0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
		0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f
	};
	static const uint8_t pt[16] = {
		0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,
		0x88,0x99,0xaa,0xbb,0xcc,0xdd,0xee,0xff
	};
	static const uint8_t ct[16] = {
		0x69,0xc4,0xe0,0xd8,0x6a,0x7b,0x04,0x30,
		0xd8,0xcd,0xb7,0x80,0x70,0xb4,0xc5,0x5a
	};
	aes128_ctx ctx;
	uint8_t buf[16];
	int rc = 0;

	aes128_setkey(&ctx, key);
	aes128_encrypt(&ctx, pt, buf);
	if (memcmp(buf, ct, 16) != 0)
		rc = -1;
	aes128_decrypt(&ctx, ct, buf);
	if (memcmp(buf, pt, 16) != 0)
		rc = -1;
	memset(&ctx, 0, sizeof ctx);
	return rc;
}

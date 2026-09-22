/*
 * Temporary GRUU construction (RFC 5627).
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

#include <fcntl.h>
#include <string.h>
#include <unistd.h>

#include "../../dprint.h"
#include "../../sha256.h"
#include "../../ut.h"

#include "aead.h"
#include "gruu.h"
#include "regtime.h"

/* Set by each registrar module. Length is filled in by reg_init_globals(). */
extern int disable_gruu;
extern str gruu_secret;

#define GRUU_PLAIN_MAX 1024
#define GRUU_B64_MAX   2048

/* HKDF-SHA256 (RFC 5869) parameters. Both values are fixed so every
 * process that shares gruu_secret derives the same key. */
static const char gruu_hkdf_salt[] = "opensips-gruu-v1";
static const char gruu_hkdf_info[] = "temp-gruu";
/* Bound to the ciphertext so a blob from another context cannot be swapped in. */
static const uint8_t gruu_aad[] = "tgruu.v1";

static uint8_t gruu_key[AEAD_KEY_LEN];
static int gruu_ready;

static uint8_t gruu_raw[AEAD_NONCE_LEN + GRUU_PLAIN_MAX + AEAD_TAG_LEN];
static uint8_t gruu_bin[GRUU_B64_MAX];
static char gruu_plain[GRUU_PLAIN_MAX];

static int b64_len(int raw)
{
	return (raw / 3 + (raw % 3 ? 1 : 0)) * 4;
}

static int temp_gruu_plain_len(const str *aor, const str *instance,
		const str *callid, int *time_len)
{
	int tlen;

	if (!aor || !instance || !callid || !aor->s || !instance->s || !callid->s)
		return -1;
	if (aor->len <= 0 || callid->len <= 0 || instance->len < 2)
		return -1;

	int2str((unsigned long)get_act_time(), &tlen);
	if (tlen <= 0)
		return -1;
	if ((size_t)tlen + (size_t)aor->len + (size_t)(instance->len - 2)
			+ (size_t)callid->len + 3 > GRUU_PLAIN_MAX)
		return -1;
	if (time_len)
		*time_len = tlen;
	return tlen + aor->len + (instance->len - 2) + callid->len + 3;
}

static void gruu_derive_key(void)
{
	uint8_t prk[32];
	uint8_t msg[sizeof gruu_hkdf_info];

	sha256_hmac((const unsigned char *)gruu_hkdf_salt,
			sizeof gruu_hkdf_salt - 1,
			(const unsigned char *)gruu_secret.s, (size_t)gruu_secret.len,
			prk, 0);
	memcpy(msg, gruu_hkdf_info, sizeof gruu_hkdf_info - 1);
	msg[sizeof gruu_hkdf_info - 1] = 0x01;
	sha256_hmac(prk, sizeof prk, msg, sizeof gruu_hkdf_info, gruu_key, 0);
	memset(prk, 0, sizeof prk);
	memset(msg, 0, sizeof msg);
}

static int gruu_random(uint8_t *buf, size_t len)
{
	int fd;
	size_t off = 0;

	fd = open("/dev/urandom", O_RDONLY);
	if (fd < 0)
		return -1;
	while (off < len) {
		ssize_t n = read(fd, buf + off, len - off);

		if (n <= 0) {
			close(fd);
			return -1;
		}
		off += (size_t)n;
	}
	close(fd);
	return 0;
}

int reg_gruu_init(void)
{
	if (aead_chacha20_poly1305_selftest() != 0) {
		LM_ERR("ChaCha20-Poly1305 self-test failed\n");
		return -1;
	}

	gruu_ready = 0;
	if (gruu_secret.s && gruu_secret.len > 0) {
		if (gruu_secret.len < 16)
			LM_WARN("gruu_secret is shorter than 16 bytes\n");
		gruu_derive_key();
		gruu_ready = 1;
	}

	if (!disable_gruu && !gruu_ready) {
		LM_ERR("GRUU is enabled (disable_gruu=0) but gruu_secret is not set\n");
		return -1;
	}
	return 0;
}

int calc_temp_gruu_len(str *aor, str *instance, str *callid)
{
	int plain = temp_gruu_plain_len(aor, instance, callid, NULL);

	if (plain < 0)
		return 0;
	return b64_len(plain + AEAD_NONCE_LEN + AEAD_TAG_LEN);
}

char *build_temp_gruu(str *aor, str *instance, str *callid, int *len)
{
	int time_len = 0, plain_len, off;
	char *time_str;
	uint8_t *pt;

	if (!len)
		return NULL;
	if (!gruu_ready) {
		LM_ERR("temporary GRUU key is not initialized\n");
		return NULL;
	}

	plain_len = temp_gruu_plain_len(aor, instance, callid, &time_len);
	if (plain_len < 0)
		return NULL;

	/* int2str() keeps its result in a static buffer, so copy it before
	 * anything else can call int2str() again. */
	time_str = int2str((unsigned long)get_act_time(), &time_len);
	if (!time_str || time_len <= 0)
		return NULL;

	pt = gruu_raw + AEAD_NONCE_LEN;
	off = 0;
	memcpy(pt + off, time_str, time_len);
	off += time_len;
	pt[off++] = ' ';
	memcpy(pt + off, aor->s, aor->len);
	off += aor->len;
	pt[off++] = ' ';
	memcpy(pt + off, instance->s + 1, instance->len - 2);
	off += instance->len - 2;
	pt[off++] = ' ';
	memcpy(pt + off, callid->s, callid->len);
	off += callid->len;
	if (off != plain_len)
		return NULL;

	if (gruu_random(gruu_raw, AEAD_NONCE_LEN) != 0) {
		LM_ERR("failed to read /dev/urandom for a temporary GRUU\n");
		return NULL;
	}
	if (aead_chacha20_poly1305_encrypt(gruu_key, gruu_raw,
			gruu_aad, sizeof gruu_aad - 1,
			pt, (size_t)plain_len,
			pt, gruu_raw + AEAD_NONCE_LEN + plain_len) != 0)
		return NULL;

	*len = AEAD_NONCE_LEN + plain_len + AEAD_TAG_LEN;
	return (char *)gruu_raw;
}

static int parse_temp_gruu_plain(char *buf, int len, str *aor, str *instance,
		str *call_id)
{
	char *end, *sp;

	if (!buf || len <= 0 || !aor || !instance || !call_id)
		return -1;
	end = buf + len;

	sp = memchr(buf, ' ', len);
	if (!sp || sp + 1 >= end)
		return -1;
	aor->s = sp + 1;
	sp = memchr(aor->s, ' ', end - aor->s);
	if (!sp)
		return -1;
	aor->len = sp - aor->s;

	instance->s = sp + 1;
	if (instance->s >= end)
		return -1;
	sp = memchr(instance->s, ' ', end - instance->s);
	if (!sp)
		return -1;
	instance->len = sp - instance->s;

	call_id->s = sp + 1;
	if (call_id->s >= end)
		return -1;
	call_id->len = end - call_id->s;

	if (aor->len <= 0 || instance->len <= 0 || call_id->len <= 0)
		return -1;
	return 0;
}

static int legacy_xor_decode(uint8_t *bin, int bin_len, str *aor,
		str *instance, str *call_id)
{
	int i;

	if (!gruu_legacy_xor || !gruu_secret.s || gruu_secret.len <= 0)
		return -1;
	if (bin_len <= 0 || bin_len > GRUU_PLAIN_MAX)
		return -1;

	for (i = 0; i < bin_len; i++)
		bin[i] ^= (uint8_t)gruu_secret.s[i % gruu_secret.len];
	memcpy(gruu_plain, bin, bin_len);
	return parse_temp_gruu_plain(gruu_plain, bin_len, aor, instance, call_id);
}

int reg_temp_gruu_decode(const str *user, str *aor, str *instance,
		str *call_id)
{
	int bin_len, plain_len;

	if (!user || !user->s || user->len <= 0 || user->len > GRUU_B64_MAX)
		return -1;
	if (!aor || !instance || !call_id)
		return -1;

	memcpy(gruu_bin, user->s, user->len);
	bin_len = base64decode(gruu_bin, gruu_bin, user->len);
	if (bin_len <= 0)
		return -1;

	if (gruu_ready && bin_len >= AEAD_NONCE_LEN + AEAD_TAG_LEN) {
		plain_len = bin_len - AEAD_NONCE_LEN - AEAD_TAG_LEN;
		if (plain_len > 0 && plain_len <= GRUU_PLAIN_MAX &&
				aead_chacha20_poly1305_decrypt(gruu_key, gruu_bin,
					gruu_aad, sizeof gruu_aad - 1,
					gruu_bin + AEAD_NONCE_LEN, (size_t)plain_len,
					gruu_bin + AEAD_NONCE_LEN + plain_len,
					(uint8_t *)gruu_plain) == 0) {
			if (parse_temp_gruu_plain(gruu_plain, plain_len, aor, instance,
					call_id) == 0) {
				LM_DBG("decoded temporary GRUU aor [%.*s] instance [%.*s] "
						"callid [%.*s]\n",
						aor->len, aor->s, instance->len, instance->s,
						call_id->len, call_id->s);
				return 0;
			}
			return -1;
		}
	}

	if (!gruu_legacy_xor)
		return -1;
	if (legacy_xor_decode(gruu_bin, bin_len, aor, instance, call_id) != 0)
		return -1;
	LM_DBG("decoded legacy temporary GRUU aor [%.*s]\n", aor->len, aor->s);
	return 0;
}

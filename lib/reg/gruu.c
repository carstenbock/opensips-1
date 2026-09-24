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
#include <strings.h>
#include <unistd.h>

#include "../../cachedb/cachedb.h"
#include "../../cachedb/cachedb_cap.h"
#include "../../dprint.h"
#include "../../mem/mem.h"
#include "../../sha1.h"
#include "../../sha256.h"
#include "../../socket_info.h"
#include "../../ut.h"

#include "aead.h"
#include "aes128.h"
#include "gruu.h"
#include "regtime.h"

/* Set by each registrar module. Length is filled in by reg_init_globals()
 * for gruu_secret and by reg_gruu_init() for gruu_domain and
 * gruu_cachedb_url. */
extern int disable_gruu;
extern int reg_use_domain;
extern str gruu_secret;

#define GRUU_PLAIN_MAX 1024
#define GRUU_B64_MAX   2048

/* HKDF-SHA256 (RFC 5869) parameters. The values are fixed so every
 * process that shares gruu_secret derives the same keys. */
static const char gruu_hkdf_salt[] = "opensips-gruu-v1";
static const char gruu_hkdf_info[] = "temp-gruu";
static const char gruu_hkdf_info_token[] = "temp-gruu-token";
static const char gruu_hkdf_info_bid[] = "temp-gruu-binding";
/* Bound to the ciphertext so a blob from another context cannot be swapped in. */
static const uint8_t gruu_aad[] = "tgruu.v1";

static uint8_t gruu_key[AEAD_KEY_LEN];
static int gruu_ready;

static uint8_t gruu_imei_ns[16];
static int gruu_imei_ns_set;
static int parse_uuid(const str *s, uint8_t out[16]);

/* Token mode (RFC 5627 Appendix A.2): a binding id names one cachedb
 * entry per AoR, instance and Call-ID, and each temporary GRUU is
 * AES-128(binding id || 8 random bytes), base64url without padding. */
#define GRUU_BID_LEN        8
#define GRUU_TOKEN_B64_LEN  22
#define GRUU_BID_B64_LEN    11
#define GRUU_BIND_MARGIN    3600
#define GRUU_CDB_PREFIX     "tgruu:"

static const str gruu_cdb_prefix = str_init(GRUU_CDB_PREFIX);

static aes128_ctx gruu_tok_ctx;
static uint8_t gruu_bid_key[32];
static int gruu_token_mode;
static cachedb_funcs gruu_cdbf;
static cachedb_con *gruu_cdbc;
static int gruu_cdb_bound;

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

/* HKDF-Expand with a single output block, T(1) = HMAC(PRK, info || 0x01). */
static void gruu_hkdf_expand(const uint8_t prk[32], const char *info,
		size_t info_len, uint8_t out[32])
{
	uint8_t msg[64];

	memcpy(msg, info, info_len);
	msg[info_len] = 0x01;
	sha256_hmac(prk, 32, msg, info_len + 1, out, 0);
	memset(msg, 0, sizeof msg);
}

static void gruu_derive_keys(void)
{
	uint8_t prk[32], okm[32];

	sha256_hmac((const unsigned char *)gruu_hkdf_salt,
			sizeof gruu_hkdf_salt - 1,
			(const unsigned char *)gruu_secret.s, (size_t)gruu_secret.len,
			prk, 0);
	gruu_hkdf_expand(prk, gruu_hkdf_info, sizeof gruu_hkdf_info - 1,
			gruu_key);
	gruu_hkdf_expand(prk, gruu_hkdf_info_token,
			sizeof gruu_hkdf_info_token - 1, okm);
	aes128_setkey(&gruu_tok_ctx, okm);
	gruu_hkdf_expand(prk, gruu_hkdf_info_bid,
			sizeof gruu_hkdf_info_bid - 1, gruu_bid_key);
	memset(prk, 0, sizeof prk);
	memset(okm, 0, sizeof okm);
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
	if (aes128_selftest() != 0) {
		LM_ERR("AES-128 self-test failed\n");
		return -1;
	}

	gruu_ready = 0;
	if (gruu_secret.s && gruu_secret.len > 0) {
		if (gruu_secret.len < 16)
			LM_WARN("gruu_secret is shorter than 16 bytes\n");
		gruu_derive_keys();
		gruu_ready = 1;
	}

	if (!disable_gruu && !gruu_ready) {
		LM_ERR("GRUU is enabled (disable_gruu=0) but gruu_secret is not set\n");
		return -1;
	}

	if (gruu_cachedb_url.s)
		gruu_cachedb_url.len = strlen(gruu_cachedb_url.s);
	gruu_token_mode = gruu_cachedb_url.s && gruu_cachedb_url.len > 0;
	if (gruu_token_mode && !gruu_ready) {
		LM_ERR("gruu_cachedb_url is set but gruu_secret is not\n");
		return -1;
	}

	if (gruu_domain.s)
		gruu_domain.len = strlen(gruu_domain.s);
	/* A temporary GRUU addressed at the registrar socket is not routable
	 * through an I-CSCF. Require an explicit domain, usrloc use_domain,
	 * or the legacy socket host. */
	if (!disable_gruu && !gruu_legacy_host
			&& !(gruu_domain.s && gruu_domain.len) && !reg_use_domain) {
		LM_ERR("GRUU is enabled but neither gruu_domain nor usrloc use_domain "
				"is set. Set gruu_domain, or gruu_legacy_host=1 to keep "
				"the registrar socket as the GRUU host\n");
		return -1;
	}

	gruu_imei_ns_set = 0;
	if (gruu_imei_namespace.s && *gruu_imei_namespace.s) {
		gruu_imei_namespace.len = strlen(gruu_imei_namespace.s);
		if (parse_uuid(&gruu_imei_namespace, gruu_imei_ns) < 0) {
			LM_ERR("gruu_imei_namespace is not a UUID "
					"(xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx)\n");
			return -1;
		}
		gruu_imei_ns_set = 1;
	} else if (!disable_gruu) {
		/* SPEC-DEVIATION: TS 24.229 5.4.7A.2 -- without a namespace UUID the
		 * public GRUU of an IMEI instance carries the IMEI itself. */
		LM_WARN("gruu_imei_namespace is not set - public GRUUs of IMEI "
				"instances expose the IMEI (TS 24.229 5.4.7A.2)\n");
	}
	return 0;
}

static int parse_uuid(const str *s, uint8_t out[16])
{
	int i, n = 0, hi, lo;

	if (s->len != 36)
		return -1;
	for (i = 0; i < 36; ) {
		if (i == 8 || i == 13 || i == 18 || i == 23) {
			if (s->s[i++] != '-')
				return -1;
			continue;
		}
		hi = hex2int(s->s[i]);
		lo = hex2int(s->s[i + 1]);
		if (hi < 0 || lo < 0)
			return -1;
		out[n++] = (uint8_t)(hi << 4 | lo);
		i += 2;
	}
	return 0;
}

#define IMEI_URN_PREFIX     "urn:gsma:imei:"
#define IMEI_URN_PREFIX_LEN (sizeof(IMEI_URN_PREFIX) - 1)
#define UUID_URN_PREFIX     "urn:uuid:"
#define UUID_URN_PREFIX_LEN (sizeof(UUID_URN_PREFIX) - 1)

/* SPEC-DEVIATION: TS 24.229 5.4.7A.2 -- the S-CSCF "shall store" the gr
 * value with its instance. The UUID is recomputed from the stored instance
 * instead, which yields the same mapping without a second store. MEID URNs
 * are not mapped; the platform only serves 3GPP UEs. */
void reg_pub_gruu_gr(const str *instance, str *gr)
{
	static const char hex[] = "0123456789abcdef";
	static char buf[UUID_URN_PREFIX_LEN + 36];
	uint8_t in[16 + 14], h[20];
	const char *v;
	char *p;
	int i;

	gr->s = instance->s + 1;
	gr->len = instance->len - 2;

	/* RFC 7254: urn:gsma:imei:<8-digit TAC>-<6-digit SNR>-<spare>[;...] */
	if (!gruu_imei_ns_set || gr->len < (int)IMEI_URN_PREFIX_LEN + 15
			|| strncasecmp(gr->s, IMEI_URN_PREFIX, IMEI_URN_PREFIX_LEN))
		return;
	v = gr->s + IMEI_URN_PREFIX_LEN;
	for (i = 0; i < 15; i++) {
		if (i == 8 ? v[i] != '-' : (v[i] < '0' || v[i] > '9'))
			return;
	}

	/* RFC 9562 version 5: SHA-1 over namespace || name, name = TAC || SNR */
	memcpy(in, gruu_imei_ns, 16);
	memcpy(in + 16, v, 8);
	memcpy(in + 24, v + 9, 6);
	sha1(in, sizeof in, h);
	h[6] = (h[6] & 0x0f) | 0x50;
	h[8] = (h[8] & 0x3f) | 0x80;

	memcpy(buf, UUID_URN_PREFIX, UUID_URN_PREFIX_LEN);
	p = buf + UUID_URN_PREFIX_LEN;
	for (i = 0; i < 16; i++) {
		if (i == 4 || i == 6 || i == 8 || i == 10)
			*p++ = '-';
		*p++ = hex[h[i] >> 4];
		*p++ = hex[h[i] & 0x0f];
	}
	gr->s = buf;
	gr->len = p - buf;
}

int reg_gruu_child_init(void)
{
	if (!gruu_token_mode)
		return 0;

	if (cachedb_bind_mod(&gruu_cachedb_url, &gruu_cdbf) < 0) {
		LM_ERR("cannot bind cachedb functions for gruu_cachedb_url %s\n",
				db_url_escape(&gruu_cachedb_url));
		return -1;
	}
	if (!CACHEDB_CAPABILITY(&gruu_cdbf, CACHEDB_CAP_GET|CACHEDB_CAP_SET)) {
		LM_ERR("gruu_cachedb_url backend lacks get/set support\n");
		return -1;
	}
	gruu_cdb_bound = 1;

	/* A backend that is down at startup must not stop the registrar:
	 * temporary GRUUs fall back to the encrypted format until it is back. */
	gruu_cdbc = gruu_cdbf.init(&gruu_cachedb_url);
	if (!gruu_cdbc)
		LM_ERR("cannot connect to gruu_cachedb_url %s, will retry\n",
				db_url_escape(&gruu_cachedb_url));
	return 0;
}

static cachedb_con *gruu_cdb(void)
{
	if (!gruu_cdb_bound)
		return NULL;
	if (!gruu_cdbc)
		gruu_cdbc = gruu_cdbf.init(&gruu_cachedb_url);
	return gruu_cdbc;
}

static char gruu_sock_host[256];

static int gruu_split_aor(const str *aor, str *user, str *host)
{
	char *at;

	if (!aor || !aor->s || aor->len <= 0)
		return -1;
	at = memchr(aor->s, '@', aor->len);
	if (!at) {
		*user = *aor;
		host->s = NULL;
		host->len = 0;
		return 0;
	}
	user->s = aor->s;
	user->len = at - aor->s;
	host->s = at + 1;
	host->len = aor->len - user->len - 1;
	if (user->len <= 0 || host->len <= 0)
		return -1;
	return 0;
}

static int gruu_socket_host(const struct socket_info *sock, str *host)
{
	int n;

	if (!sock || !sock->name.s || sock->name.len <= 0
			|| !sock->port_no_str.s || sock->port_no_str.len <= 0)
		return -1;
	n = sock->name.len + 1 + sock->port_no_str.len;
	if (n >= (int)sizeof gruu_sock_host)
		return -1;
	memcpy(gruu_sock_host, sock->name.s, sock->name.len);
	gruu_sock_host[sock->name.len] = ':';
	memcpy(gruu_sock_host + sock->name.len + 1,
			sock->port_no_str.s, sock->port_no_str.len);
	host->s = gruu_sock_host;
	host->len = n;
	return 0;
}

int reg_gruu_target(const str *aor, const struct socket_info *sock,
		int temporary, str *user, str *host)
{
	str aor_user, aor_host;

	if (!user || !host)
		return -1;
	if (gruu_split_aor(aor, &aor_user, &aor_host) < 0)
		return -1;

	/* Restore the historical host: the registrar socket, except a public
	 * GRUU whose AoR already contains a domain. */
	if (gruu_legacy_host) {
		if (!temporary && aor_host.len) {
			user->s = aor->s;
			user->len = aor->len;
			host->s = NULL;
			host->len = 0;
			return 0;
		}
		*user = aor_user;
		return gruu_socket_host(sock, host);
	}

	/* An explicit domain replaces the socket and the AoR domain for both
	 * GRUUs. The user part stays the AoR user, so a domain already stored
	 * in the AoR is not written twice. */
	if (gruu_domain.s && gruu_domain.len > 0) {
		*user = aor_user;
		*host = gruu_domain;
		return 0;
	}

	if (aor_host.len) {
		if (!temporary) {
			user->s = aor->s;
			user->len = aor->len;
			host->s = NULL;
			host->len = 0;
			return 0;
		}
		*user = aor_user;
		*host = aor_host;
		return 0;
	}

	*user = aor_user;
	return gruu_socket_host(sock, host);
}

/* The encrypted format is always longer than a token, so its length is
 * the upper bound for both, including the token-to-encrypted fallback. */
int calc_temp_gruu_len(str *aor, str *instance, str *callid)
{
	int plain = temp_gruu_plain_len(aor, instance, callid, NULL);

	if (plain < 0)
		return 0;
	return b64_len(plain + AEAD_NONCE_LEN + AEAD_TAG_LEN);
}

/* "<aor>\n<instance>\n<callid>" into gruu_plain. A line feed cannot occur
 * in any of the three fields. */
static int gruu_binding_value(const str *aor, const str *instance,
		const str *callid)
{
	int off = 0;

	memcpy(gruu_plain + off, aor->s, aor->len);
	off += aor->len;
	gruu_plain[off++] = '\n';
	memcpy(gruu_plain + off, instance->s + 1, instance->len - 2);
	off += instance->len - 2;
	gruu_plain[off++] = '\n';
	memcpy(gruu_plain + off, callid->s, callid->len);
	off += callid->len;
	return off;
}

/* SPEC-DEVIATION: RFC 5627 §5.3 -- the binding id is a keyed hash of AoR,
 * instance and Call-ID. If the last contact expires and the UA registers
 * again with the same Call-ID, the earlier temporary GRUUs become valid
 * again. usrloc has no removal hook that reaches the cachedb entry from
 * every cluster node. */
static void gruu_binding_id(const char *val, int val_len,
		uint8_t bid[GRUU_BID_LEN])
{
	uint8_t mac[32];

	sha256_hmac(gruu_bid_key, sizeof gruu_bid_key,
			(const unsigned char *)val, (size_t)val_len, mac, 0);
	memcpy(bid, mac, GRUU_BID_LEN);
	memset(mac, 0, sizeof mac);
}

/* base64url without padding. out must hold calc_base64_encode_len(len). */
static int gruu_b64url(uint8_t *out, const uint8_t *in, int len)
{
	int n = calc_base64_encode_len(len);

	base64urlencode(out, (unsigned char *)in, len);
	while (n > 0 && out[n - 1] == '=')
		n--;
	return n;
}

static int gruu_cdb_key(char *buf, const uint8_t bid[GRUU_BID_LEN], str *key)
{
	uint8_t enc[calc_base64_encode_len(GRUU_BID_LEN)];
	int n;

	n = gruu_b64url(enc, bid, GRUU_BID_LEN);
	if (n != GRUU_BID_B64_LEN)
		return -1;
	memcpy(buf, gruu_cdb_prefix.s, gruu_cdb_prefix.len);
	memcpy(buf + gruu_cdb_prefix.len, enc, n);
	key->s = buf;
	key->len = gruu_cdb_prefix.len + n;
	return 0;
}

static int build_token_gruu(str *aor, str *instance, str *callid,
		int expires, char *out)
{
	uint8_t blk[AES128_BLOCK_LEN], tok[AES128_BLOCK_LEN];
	uint8_t enc[calc_base64_encode_len(AES128_BLOCK_LEN)];
	char kbuf[sizeof GRUU_CDB_PREFIX + GRUU_BID_B64_LEN];
	cachedb_con *con;
	str key, val;
	int ttl, n;

	con = gruu_cdb();
	if (!con)
		return -1;

	val.s = gruu_plain;
	val.len = gruu_binding_value(aor, instance, callid);
	gruu_binding_id(val.s, val.len, blk);
	if (gruu_cdb_key(kbuf, blk, &key) < 0)
		return -1;

	/* Every REGISTER rewrites the entry, so its lifetime follows the
	 * binding and all temporary GRUUs issued for it stay valid. */
	ttl = 0;
	if (expires) {
		ttl = expires - (int)get_act_time();
		if (ttl < 0)
			ttl = 0;
		ttl += GRUU_BIND_MARGIN;
	}
	if (gruu_cdbf.set(con, &key, &val, ttl) < 0) {
		LM_ERR("failed to store GRUU binding %.*s\n", key.len, key.s);
		return -1;
	}

	if (gruu_random(blk + GRUU_BID_LEN, AES128_BLOCK_LEN - GRUU_BID_LEN) != 0) {
		LM_ERR("failed to read /dev/urandom for a temporary GRUU\n");
		return -1;
	}
	aes128_encrypt(&gruu_tok_ctx, blk, tok);
	n = gruu_b64url(enc, tok, AES128_BLOCK_LEN);
	if (n != GRUU_TOKEN_B64_LEN)
		return -1;
	memcpy(out, enc, n);
	return n;
}

static int build_aead_gruu(str *aor, str *instance, str *callid, char *out)
{
	int time_len = 0, plain_len, off;
	char *time_str;
	uint8_t *pt;

	plain_len = temp_gruu_plain_len(aor, instance, callid, &time_len);
	if (plain_len < 0)
		return -1;

	/* int2str() keeps its result in a static buffer, so copy it before
	 * anything else can call int2str() again. */
	time_str = int2str((unsigned long)get_act_time(), &time_len);
	if (!time_str || time_len <= 0)
		return -1;

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
		return -1;

	if (gruu_random(gruu_raw, AEAD_NONCE_LEN) != 0) {
		LM_ERR("failed to read /dev/urandom for a temporary GRUU\n");
		return -1;
	}
	if (aead_chacha20_poly1305_encrypt(gruu_key, gruu_raw,
			gruu_aad, sizeof gruu_aad - 1,
			pt, (size_t)plain_len,
			pt, gruu_raw + AEAD_NONCE_LEN + plain_len) != 0)
		return -1;

	off = AEAD_NONCE_LEN + plain_len + AEAD_TAG_LEN;
	base64encode((unsigned char *)out, gruu_raw, off);
	return b64_len(off);
}

int build_temp_gruu(str *aor, str *instance, str *callid, int expires,
		char *out)
{
	int n;

	if (!out)
		return -1;
	if (!gruu_ready) {
		LM_ERR("temporary GRUU key is not initialized\n");
		return -1;
	}
	/* Also bounds the token path, whose output calc_temp_gruu_len()
	 * reserves through the encrypted length. */
	if (temp_gruu_plain_len(aor, instance, callid, NULL) < 0)
		return -1;

	if (gruu_token_mode) {
		n = build_token_gruu(aor, instance, callid, expires, out);
		if (n > 0)
			return n;
		LM_WARN("cannot issue a temporary GRUU token for [%.*s], "
				"using the encrypted format\n", aor->len, aor->s);
	}
	return build_aead_gruu(aor, instance, callid, out);
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

static int gruu_is_token(const str *user)
{
	int i;
	char c;

	if (user->len != GRUU_TOKEN_B64_LEN)
		return 0;
	for (i = 0; i < user->len; i++) {
		c = user->s[i];
		if (!((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z')
				|| (c >= '0' && c <= '9') || c == '-' || c == '_'))
			return 0;
	}
	return 1;
}

static int parse_binding_value(char *buf, int len, str *aor, str *instance,
		str *call_id)
{
	char *end = buf + len, *nl;

	aor->s = buf;
	nl = memchr(buf, '\n', len);
	if (!nl)
		return -1;
	aor->len = nl - buf;

	instance->s = nl + 1;
	nl = memchr(instance->s, '\n', end - instance->s);
	if (!nl)
		return -1;
	instance->len = nl - instance->s;

	call_id->s = nl + 1;
	call_id->len = end - call_id->s;

	if (aor->len <= 0 || instance->len <= 0 || call_id->len <= 0)
		return -1;
	return 0;
}

static int decode_token_gruu(const str *user, str *aor, str *instance,
		str *call_id)
{
	uint8_t enc[calc_base64_encode_len(AES128_BLOCK_LEN)];
	uint8_t tok[AES128_BLOCK_LEN], blk[AES128_BLOCK_LEN];
	char kbuf[sizeof GRUU_CDB_PREFIX + GRUU_BID_B64_LEN];
	cachedb_con *con;
	str key, val = STR_NULL;
	int rc;

	/* base64urldecode() needs the padding to stop inside the buffer. */
	memcpy(enc, user->s, GRUU_TOKEN_B64_LEN);
	memset(enc + GRUU_TOKEN_B64_LEN, '=', sizeof enc - GRUU_TOKEN_B64_LEN);
	if (base64urldecode(tok, enc, sizeof enc) != AES128_BLOCK_LEN)
		return -1;
	aes128_decrypt(&gruu_tok_ctx, tok, blk);
	if (gruu_cdb_key(kbuf, blk, &key) < 0)
		return -1;

	con = gruu_cdb();
	if (!con) {
		LM_ERR("no gruu_cachedb_url connection, cannot resolve a "
				"temporary GRUU token\n");
		return -1;
	}
	rc = gruu_cdbf.get(con, &key, &val);
	if (rc == -2) {
		LM_DBG("no GRUU binding %.*s\n", key.len, key.s);
		return -1;
	}
	if (rc < 0) {
		LM_ERR("failed to fetch GRUU binding %.*s\n", key.len, key.s);
		return -1;
	}
	if (!val.s || val.len <= 0 || val.len > GRUU_PLAIN_MAX) {
		if (val.s)
			pkg_free(val.s);
		return -1;
	}
	memcpy(gruu_plain, val.s, val.len);
	rc = val.len;
	pkg_free(val.s);

	return parse_binding_value(gruu_plain, rc, aor, instance, call_id);
}

int reg_temp_gruu_decode(const str *user, str *aor, str *instance,
		str *call_id)
{
	int bin_len, plain_len;

	if (!user || !user->s || user->len <= 0 || user->len > GRUU_B64_MAX)
		return -1;
	if (!aor || !instance || !call_id)
		return -1;

	/* An encrypted blob is at least 38 characters, so a 22-character
	 * base64url user part can only be a token. */
	if (gruu_token_mode && gruu_is_token(user)) {
		if (decode_token_gruu(user, aor, instance, call_id) != 0)
			return -1;
		LM_DBG("resolved temporary GRUU token aor [%.*s] instance [%.*s] "
				"callid [%.*s]\n",
				aor->len, aor->s, instance->len, instance->s,
				call_id->len, call_id->s);
		return 0;
	}

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

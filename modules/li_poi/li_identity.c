/*
 * Canonical form of a target identifier. See li_identity.h.
 *
 * Plain C without OpenSIPS headers, so that the test program builds alone.
 */

#include <string.h>
#include "li_identity.h"

static char lower(char c)
{
	return (c >= 'A' && c <= 'Z') ? (char)(c + 32) : c;
}

static int has_prefix(const char *in, int len, const char *prefix)
{
	int i, n = (int)strlen(prefix);

	if (len < n)
		return 0;
	for (i = 0; i < n; i++)
		if (lower(in[i]) != prefix[i])
			return 0;
	return 1;
}

/* RFC 3966 visual separators */
static int is_separator(char c)
{
	return c == '-' || c == '.' || c == '(' || c == ')' || c == ' ';
}

struct out {
	char *buf;
	int size;
	int len;
};

static void put(struct out *o, const char *s, int n)
{
	int i;

	for (i = 0; i < n; i++) {
		if (o->len < o->size)
			o->buf[o->len] = s[i];
		o->len++;
	}
}

/* the number without visual separators */
static void put_number(struct out *o, const char *s, int n)
{
	int i;

	for (i = 0; i < n; i++)
		if (!is_separator(s[i]))
			put(o, s + i, 1);
}

static void put_lower(struct out *o, const char *s, int n)
{
	int i;
	char c;

	for (i = 0; i < n; i++) {
		c = lower(s[i]);
		put(o, &c, 1);
	}
}

/* length of s up to the first of the stop characters */
static int until(const char *s, int n, const char *stop)
{
	int i;

	for (i = 0; i < n; i++)
		if (strchr(stop, s[i]))
			return i;
	return n;
}

/* "+" and at least one digit, nothing else, visual separators aside */
static int is_e164(const char *s, int n)
{
	int i, digits = 0;

	if (n < 2 || s[0] != '+')
		return 0;
	for (i = 1; i < n; i++) {
		if (is_separator(s[i]))
			continue;
		if (s[i] < '0' || s[i] > '9')
			return 0;
		digits++;
	}
	return digits > 0;
}

static void canonical_sip(struct out *o, const char *s, int n)
{
	const char *at, *host;
	int user_len, host_len;

	n = until(s, n, "?");
	at = memchr(s, '@', n);
	if (!at) {
		host = s;
		host_len = n;
		user_len = -1;
	} else {
		/* user without password and user parameters */
		user_len = until(s, (int)(at - s), ";:");
		host = at + 1;
		host_len = n - (int)(host - s);
	}

	if (host_len > 0 && host[0] == '[') {
		/* an IPv6 reference keeps its brackets */
		host_len = until(host, host_len, "]");
		if (host_len < n - (int)(host - s))
			host_len++;
	} else {
		host_len = until(host, host_len, ":;");
	}

	if (user_len >= 0 && is_e164(s, user_len)) {
		put(o, "tel:", 4);
		put_number(o, s, user_len);
		return;
	}
	put(o, "sip:", 4);
	if (user_len >= 0) {
		put(o, s, user_len);
		put(o, "@", 1);
	}
	put_lower(o, host, host_len);
}

int li_canonical(int cls, const char *in, int in_len, char *out, int out_size)
{
	struct out o = { out, out_size, 0 };
	const char *at;
	int i, digits;

	/* surrounding white space */
	while (in_len > 0 && (in[0] == ' ' || in[0] == '\t')) {
		in++;
		in_len--;
	}
	while (in_len > 0 && (in[in_len - 1] == ' ' || in[in_len - 1] == '\t'))
		in_len--;

	switch (cls) {
	case LI_CLASS_IMPU:
		if (has_prefix(in, in_len, "tel:")) {
			put(&o, "tel:", 4);
			put_number(&o, in + 4, until(in + 4, in_len - 4, ";"));
		} else if (has_prefix(in, in_len, "sips:")) {
			canonical_sip(&o, in + 5, in_len - 5);
		} else if (has_prefix(in, in_len, "sip:")) {
			canonical_sip(&o, in + 4, in_len - 4);
		} else {
			put(&o, in, in_len);
		}
		break;
	case LI_CLASS_IMPI:
		at = memchr(in, '@', in_len);
		if (!at) {
			put(&o, in, in_len);
		} else {
			put(&o, in, (int)(at - in) + 1);
			put_lower(&o, at + 1, in_len - (int)(at - in) - 1);
		}
		break;
	case LI_CLASS_IMEI:
		digits = 0;
		for (i = 0; i < in_len && digits < 14; i++)
			if (in[i] >= '0' && in[i] <= '9') {
				put(&o, in + i, 1);
				digits++;
			}
		break;
	default:
		return -1;
	}

	return o.len <= o.size ? o.len : -1;
}

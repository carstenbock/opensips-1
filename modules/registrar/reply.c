/*
 * Send a reply
 *
 * Copyright (C) 2001-2003 FhG Fokus
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301  USA
 *
 * History:
 * --------
 * 2003-01-18: buffer overflow patch committed (Jan on behalf of Maxim)
 * 2003-01-21: Errors reported via Error-Info header field - janakj
 * 2003-09-11: updated to new build_lump_rpl() interface (bogdan)
 * 2003-11-11: build_lump_rpl() removed, add_lump_rpl() has flags (bogdan)
 */

/*!
 * \file
 * \brief SIP registrar module - Send a reply
 * \ingroup registrar
 */

#include <stdio.h>

#include "../../ut.h"
#include "../../parser/msg_parser.h"
#include "../../parser/parse_supported.h"
#include "../../data_lump_rpl.h"
#include "../../lib/reg/common.h"
#include "../../lib/reg/gruu.h"

#include "../usrloc/usrloc.h"

#include "reg_mod.h"
#include "reply.h"


#define MAX_CONTACT_BUFFER 1024

#define E_INFO "P-Registrar-Error: "
#define E_INFO_LEN (sizeof(E_INFO) - 1)

#define CONTACT_BEGIN "Contact: "
#define CONTACT_BEGIN_LEN (sizeof(CONTACT_BEGIN) - 1)

#define Q_PARAM ";q="
#define Q_PARAM_LEN (sizeof(Q_PARAM) - 1)

#define EXPIRES_PARAM ";expires="
#define EXPIRES_PARAM_LEN (sizeof(EXPIRES_PARAM) - 1)

#define SIP_PROTO "sip:"
#define SIP_PROTO_SIZE (sizeof(SIP_PROTO) - 1)

#define PUB_GRUU ";pub-gruu="
#define PUB_GRUU_SIZE (sizeof(PUB_GRUU) - 1)

#define TEMP_GRUU ";temp-gruu="
#define TEMP_GRUU_SIZE (sizeof(TEMP_GRUU) - 1)

#define SIP_INSTANCE ";+sip.instance="
#define SIP_INSTANCE_SIZE (sizeof(SIP_INSTANCE) - 1)

#define GR_PARAM ";gr="
#define GR_PARAM_SIZE (sizeof(GR_PARAM) - 1)

#define GR_NO_VAL ";gr"
#define GR_NO_VAL_SIZE (sizeof(GR_NO_VAL) - 1)

#define CONTACT_SEP ", "
#define CONTACT_SEP_LEN (sizeof(CONTACT_SEP) - 1)

/*! \brief
 * Buffer for Contact header field
 */
static struct {
	char* buf;
	int buf_len;
	int data_len;
} contact = {0, 0, 0};


/*! \brief
 * Is this a Contact parameter build_contact() emits on its own?
 *
 * Echoing one of these a second time out of the stored attribute would produce a
 * Contact carrying two q values or two expires, which is a worse defect than the
 * omission the echo exists to fix.  gruu_emitted tells whether the GRUU block ran
 * for this contact, because that is what decides whether +sip.instance and the
 * gruu parameters have already been written.
 */
static inline int attr_param_is_builtin(str *name, int gruu_emitted)
{
	if (name->len == 1 && (name->s[0] == 'q' || name->s[0] == 'Q'))
		return 1;
	if (name->len == 7 && strncasecmp(name->s, "expires", 7) == 0)
		return 1;
	if (rcv_param.len && name->len == rcv_param.len
	        && strncasecmp(name->s, rcv_param.s, rcv_param.len) == 0)
		return 1;
	if (gruu_emitted) {
		if (name->len == 13 && strncasecmp(name->s, "+sip.instance", 13) == 0)
			return 1;
		if (name->len == 8 && strncasecmp(name->s, "pub-gruu", 8) == 0)
			return 1;
		if (name->len == 9 && strncasecmp(name->s, "temp-gruu", 9) == 0)
			return 1;
	}
	return 0;
}

/*! \brief
 * Echo the feature parameters registered against a contact.
 *
 * RFC 3840 clause 6: "when a registrar returns a 200 OK response to a REGISTER
 * request, each Contact header field value MUST include all of the feature
 * parameters associated with that URI".  Without this the registrar answers a UE
 * that offered +g.3gpp.smsip or +g.3gpp.icsi-ref with a bare Contact, and a UE
 * that waits for its capabilities to be confirmed concludes the network does not
 * support them -- for SMS over IP that means falling back to the CS domain.
 *
 * The parameters as registered are kept verbatim in c->attr, which the script
 * populates from the request's Contact via the attr_avp module parameter.  Nothing
 * is echoed when that is empty, so a deployment that does not store them keeps the
 * previous behaviour.
 *
 * Writes into dst when dst is non-NULL and returns the byte count it would write
 * either way, so calc_buf_len() and build_contact() cannot disagree about the
 * size: they share one pkg_malloc'd buffer written with unchecked memcpy, and a
 * disagreement is a heap overflow rather than a formatting bug.
 */
static inline int copy_echoed_attrs(char *dst, ucontact_t *c, int gruu_emitted)
{
	char *out = dst;
	int total = 0, i = 0, start, in_quote, j;
	str param, name;

	if (!c->attr.s || c->attr.len <= 0)
		return 0;

	while (i < c->attr.len) {
		while (i < c->attr.len && (c->attr.s[i] == ';'
		        || c->attr.s[i] == ' ' || c->attr.s[i] == '\t'))
			i++;

		/* A value may be a quoted string, and a quoted string may contain the
		 * separator -- +sip.instance carries a URN in quotes. */
		start = i;
		in_quote = 0;
		while (i < c->attr.len && (in_quote || c->attr.s[i] != ';')) {
			if (c->attr.s[i] == '"')
				in_quote = !in_quote;
			i++;
		}

		param.s = c->attr.s + start;
		param.len = i - start;
		while (param.len > 0 && (param.s[param.len - 1] == ' '
		        || param.s[param.len - 1] == '\t'))
			param.len--;
		if (param.len == 0)
			continue;

		name = param;
		for (j = 0; j < param.len; j++) {
			if (param.s[j] == '=') {
				name.len = j;
				break;
			}
		}
		if (attr_param_is_builtin(&name, gruu_emitted))
			continue;

		total += 1 /* ; */ + param.len;
		if (out) {
			*out++ = ';';
			memcpy(out, param.s, param.len);
			out += param.len;
		}
	}

	return total;
}

/*! \brief
 * Calculate the length of buffer needed to
 * print contacts
 */
static inline unsigned int calc_buf_len(ucontact_t* c,int build_gruu,
		struct sip_msg *_m)
{
	unsigned int len;
	int qlen;
	const struct socket_info *sock;

	len = 0;
	while(c) {
		if (VALID_CONTACT(c, get_act_time())) {
			if (len) len += CONTACT_SEP_LEN;
			len += 2 /* < > */ + c->c.len;
			qlen = len_q(c->q);
			if (qlen) len += Q_PARAM_LEN + qlen;
			len += EXPIRES_PARAM_LEN + INT2STR_MAX_LEN;
			if (c->received.s) {
				len += 1 /* ; */
					+ rcv_param.len
					+ 1 /* = */
					+ 1 /* dquote */
					+ c->received.len
					+ 1 /* dquote */
					;
			}
			if (build_gruu && c->instance.s) {
				str guser, ghost, gr;

				sock = (c->sock)?(c->sock):(_m->rcv.bind_address);
				if (reg_gruu_target(c->aor, sock, 0, &guser, &ghost) < 0) {
					guser.len = c->aor ? c->aor->len : 0;
					ghost.len = 0;
				}
				reg_pub_gruu_gr(&c->instance, &gr);
				/* pub gruu */
				len += PUB_GRUU_SIZE
					+ 1 /* quote */
					+ SIP_PROTO_SIZE
					+ guser.len
					+ (ghost.len ? 1 + ghost.len : 0)
					+ GR_PARAM_SIZE
					+ gr.len
					+ 1 /* quote */
					;
				if (reg_gruu_target(c->aor, sock, 1, &guser, &ghost) < 0
						|| ghost.len <= 0)
					ghost.len = sock ? sock->name.len + 1 + sock->port_no_str.len : 0;
				/* temp gruu */
				len += TEMP_GRUU_SIZE
					+ 1 /* quote */
					+ SIP_PROTO_SIZE
					+ TEMP_GRUU_HEADER_SIZE
					+ calc_temp_gruu_len(c->aor,&c->instance,&c->callid)
					+ 1 /* @ */
					+ ghost.len
					+ GR_NO_VAL_SIZE
					+ 1 /* quote */
					;
				/* sip.instance */
				len += SIP_INSTANCE_SIZE
					+ 1 /* quote */
					+ c->instance.len
					+ 1 /* quote */
					;
			}
			len += copy_echoed_attrs(NULL, c, build_gruu && c->instance.s);
		}
		c = c->next;
	}

	if (len) len += CONTACT_BEGIN_LEN + CRLF_LEN;
	return len;
}

/*! \brief
 * Allocate a memory buffer and print Contact
 * header fields into it
 */
int build_contact(ucontact_t* c,struct sip_msg *_m)
{
	char *p, *cp;
	int fl, len,grlen;
	int build_gruu = 0;
	const struct socket_info *sock;

	if (!disable_gruu && _m->supported && parse_supported(_m) == 0 &&
		(get_supported(_m) & F_SUPPORTED_GRUU))
		build_gruu=1;

	contact.data_len = calc_buf_len(c,build_gruu,_m);
	if (!contact.data_len) return 0;

	if (!contact.buf || (contact.buf_len < contact.data_len)) {
		if (contact.buf) pkg_free(contact.buf);
		contact.buf = (char*)pkg_malloc(contact.data_len);
		if (!contact.buf) {
			contact.data_len = 0;
			contact.buf_len = 0;
			LM_ERR("no pkg memory left\n");
			return -1;
		} else {
			contact.buf_len = contact.data_len;
		}
	}

	p = contact.buf;

	memcpy(p, CONTACT_BEGIN, CONTACT_BEGIN_LEN);
	p += CONTACT_BEGIN_LEN;

	fl = 0;
	while(c) {
		if (VALID_CONTACT(c, get_act_time())) {
			if (fl) {
				memcpy(p, CONTACT_SEP, CONTACT_SEP_LEN);
				p += CONTACT_SEP_LEN;
			} else {
				fl = 1;
			}

			*p++ = '<';
			memcpy(p, c->c.s, c->c.len);
			p += c->c.len;
			*p++ = '>';

			len = len_q(c->q);
			if (len) {
				memcpy(p, Q_PARAM, Q_PARAM_LEN);
				p += Q_PARAM_LEN;
				memcpy(p, q2str(c->q, 0), len);
				p += len;
			}

			memcpy(p, EXPIRES_PARAM, EXPIRES_PARAM_LEN);
			p += EXPIRES_PARAM_LEN;
			cp = int2str((int)(c->expires - get_act_time()), &len);
			memcpy(p, cp, len);
			p += len;

			if (c->received.s) {
				*p++ = ';';
				memcpy(p, rcv_param.s, rcv_param.len);
				p += rcv_param.len;
				*p++ = '=';
				*p++ = '\"';
				memcpy(p, c->received.s, c->received.len);
				p += c->received.len;
				*p++ = '\"';
			}

			if (build_gruu && c->instance.s) {
				str guser, ghost, gr;

				sock = (c->sock)?(c->sock):(_m->rcv.bind_address);
				if (reg_gruu_target(c->aor, sock, 0, &guser, &ghost) < 0) {
					LM_ERR("failed to select GRUU host\n");
					contact.data_len = 0;
					rerrno = R_INTERNAL;
					return -1;
				}
				/* build pub GRUU. Copy the host before the next
				 * reg_gruu_target() call, which reuses a static buffer. */
				memcpy(p,PUB_GRUU,PUB_GRUU_SIZE);
				p += PUB_GRUU_SIZE;
				*p++ = '\"';
				memcpy(p,SIP_PROTO,SIP_PROTO_SIZE);
				p += SIP_PROTO_SIZE;
				memcpy(p, guser.s, guser.len);
				p += guser.len;
				if (ghost.len) {
					*p++ = '@';
					memcpy(p, ghost.s, ghost.len);
					p += ghost.len;
				}
				memcpy(p,GR_PARAM,GR_PARAM_SIZE);
				p += GR_PARAM_SIZE;
				reg_pub_gruu_gr(&c->instance, &gr);
				memcpy(p, gr.s, gr.len);
				p += gr.len;
				*p++ = '\"';

				if (reg_gruu_target(c->aor, sock, 1, &guser, &ghost) < 0
						|| ghost.len <= 0) {
					LM_ERR("failed to select temporary GRUU host\n");
					contact.data_len = 0;
					rerrno = R_INTERNAL;
					return -1;
				}
				/* build temp GRUU */
				memcpy(p,TEMP_GRUU,TEMP_GRUU_SIZE);
				p += TEMP_GRUU_SIZE;
				*p++ = '\"';
				memcpy(p,SIP_PROTO,SIP_PROTO_SIZE);
				p += SIP_PROTO_SIZE;
				memcpy(p,TEMP_GRUU_HEADER,TEMP_GRUU_HEADER_SIZE);
				p += TEMP_GRUU_HEADER_SIZE;

				grlen = build_temp_gruu(c->aor,&c->instance,&c->callid,
						(int)c->expires,p);
				if (grlen < 0) {
					LM_ERR("failed to build temporary GRUU\n");
					contact.data_len = 0;
					rerrno = R_INTERNAL;
					return -1;
				}
				p += grlen;
				*p++ = '@';
				memcpy(p, ghost.s, ghost.len);
				p += ghost.len;
				memcpy(p,GR_NO_VAL,GR_NO_VAL_SIZE);
				p += GR_NO_VAL_SIZE;
				*p++ = '\"';

				/* build +sip.instance, "<...>" as the UE sent it (RFC 5626 4.1) */
				memcpy(p,SIP_INSTANCE,SIP_INSTANCE_SIZE);
				p += SIP_INSTANCE_SIZE;
				*p++ = '\"';
				memcpy(p,c->instance.s,c->instance.len);
				p += c->instance.len;
				*p++ = '\"';
			}

			/* Must mirror the accounting in calc_buf_len() exactly. */
			p += copy_echoed_attrs(p, c, build_gruu && c->instance.s);
		}

		c = c->next;
	}

	memcpy(p, CRLF, CRLF_LEN);
	p += CRLF_LEN;

	contact.data_len = p - contact.buf;

	LM_DBG("created Contact HF: %.*s\n", contact.data_len, contact.buf);
	return 0;
}


#define RETRY_AFTER "Retry-After: "
#define RETRY_AFTER_LEN (sizeof(RETRY_AFTER) - 1)

static int add_retry_after(struct sip_msg* _m)
{
	char* buf, *ra_s;
 	int ra_len;

 	ra_s = int2str(retry_after, &ra_len);
 	buf = (char*)pkg_malloc(RETRY_AFTER_LEN + ra_len + CRLF_LEN);
 	if (!buf) {
 		LM_ERR("no pkg memory left\n");
 		return -1;
 	}
 	memcpy(buf, RETRY_AFTER, RETRY_AFTER_LEN);
 	memcpy(buf + RETRY_AFTER_LEN, ra_s, ra_len);
 	memcpy(buf + RETRY_AFTER_LEN + ra_len, CRLF, CRLF_LEN);
 	add_lump_rpl(_m, buf, RETRY_AFTER_LEN + ra_len + CRLF_LEN,
 		     LUMP_RPL_HDR | LUMP_RPL_NODUP);
 	return 0;
}

#define PATH "Path: "
#define PATH_LEN (sizeof(PATH) - 1)

static int add_path(struct sip_msg* _m, str* _p)
{
	char* buf;

 	buf = (char*)pkg_malloc(PATH_LEN + _p->len + CRLF_LEN);
 	if (!buf) {
 		LM_ERR("no pkg memory left\n");
 		return -1;
 	}
 	memcpy(buf, PATH, PATH_LEN);
 	memcpy(buf + PATH_LEN, _p->s, _p->len);
 	memcpy(buf + PATH_LEN + _p->len, CRLF, CRLF_LEN);
 	add_lump_rpl(_m, buf, PATH_LEN + _p->len + CRLF_LEN,
 		     LUMP_RPL_HDR | LUMP_RPL_NODUP);
 	return 0;
}

#define UNSUPPORTED "Unsupported: "
#define UNSUPPORTED_LEN (sizeof(UNSUPPORTED) - 1)

static int add_unsupported(struct sip_msg* _m, str* _p)
{
	char* buf;

 	buf = (char*)pkg_malloc(UNSUPPORTED_LEN + _p->len + CRLF_LEN);
 	if (!buf) {
 		LM_ERR("no pkg memory left\n");
 		return -1;
 	}
 	memcpy(buf, UNSUPPORTED, UNSUPPORTED_LEN);
 	memcpy(buf + UNSUPPORTED_LEN, _p->s, _p->len);
 	memcpy(buf + UNSUPPORTED_LEN + _p->len, CRLF, CRLF_LEN);
 	add_lump_rpl(_m, buf, UNSUPPORTED_LEN + _p->len + CRLF_LEN,
 		     LUMP_RPL_HDR | LUMP_RPL_NODUP);
 	return 0;
}

/*! \brief
 * Send a reply
 */
int send_reply(struct sip_msg* _m, unsigned int _flags)
{
	str unsup = str_init(SUPPORTED_PATH_STR);
	long code;
	str msg = str_init(MSG_200); /* makes gcc shut up */
	char* buf;

	if (contact.data_len > 0) {
		add_lump_rpl( _m, contact.buf, contact.data_len, LUMP_RPL_HDR|LUMP_RPL_NODUP|LUMP_RPL_NOFREE);
		contact.data_len = 0;
	}

	if (rerrno == R_FINE && (_flags&REG_SAVE_PATH_FLAG) && _m->path_vec.s) {
		if ( (_flags&REG_SAVE_PATH_OFF_FLAG)==0 ) {
			if (parse_supported(_m)<0 && (_flags&REG_SAVE_PATH_STRICT_FLAG)) {
				rerrno = R_PATH_UNSUP;
				if (add_unsupported(_m, &unsup) < 0)
					return -1;
				if (add_path(_m, &_m->path_vec) < 0)
					return -1;
			}
			else if (get_supported(_m) & F_SUPPORTED_PATH) {
				if (add_path(_m, &_m->path_vec) < 0)
					return -1;
			} else if ((_flags&REG_SAVE_PATH_STRICT_FLAG)) {
				rerrno = R_PATH_UNSUP;
				if (add_unsupported(_m, &unsup) < 0)
					return -1;
				if (add_path(_m, &_m->path_vec) < 0)
					return -1;
			}
		}
	}

	if (pn_enable)
		pn_append_rpl_fcaps(_m);

	code = rerr_codes[rerrno];
	switch (code) {
	case 200: init_str(&msg, MSG_200); break;
	case 400: init_str(&msg, MSG_400); break;
	case 420: init_str(&msg, MSG_420); break;
	case 500: init_str(&msg, MSG_500); break;
	case 503: init_str(&msg, MSG_503); break;
	case 555: init_str(&msg, MSG_555); break;
	}

	if (code != 200) {
		buf = (char*)pkg_malloc(E_INFO_LEN + error_info[rerrno].len + CRLF_LEN + 1);
		if (!buf) {
			LM_ERR("no pkg memory left\n");
			return -1;
		}
		memcpy(buf, E_INFO, E_INFO_LEN);
		memcpy(buf + E_INFO_LEN, error_info[rerrno].s, error_info[rerrno].len);
		memcpy(buf + E_INFO_LEN + error_info[rerrno].len, CRLF, CRLF_LEN);
		add_lump_rpl( _m, buf, E_INFO_LEN + error_info[rerrno].len + CRLF_LEN,
			LUMP_RPL_HDR|LUMP_RPL_NODUP);

		if (code >= 500 && code < 600 && retry_after) {
			if (add_retry_after(_m) < 0) {
				return -1;
			}
		}
	}

	if (sigb.reply(_m, code, &msg, NULL) == -1) {
		LM_ERR("failed to send %ld %.*s\n", code, msg.len,msg.s);
		return -1;
	} else return 0;
}


/*! \brief
 * Release contact buffer if any
 */
void free_contact_buf(void)
{
	if (contact.buf) {
		pkg_free(contact.buf);
		contact.buf = 0;
		contact.buf_len = 0;
		contact.data_len = 0;
	}
}

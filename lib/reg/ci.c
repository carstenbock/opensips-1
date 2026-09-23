/*
 * Contact info packing functions
 *
 * Copyright (C) 2016-2017 OpenSIPS Solutions
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

#include "../../trim.h"
#include "../../ut.h"
#include "../../mem/mem.h"
#include "../../parser/parse_methods.h"
#include "../../parser/parse_allow.h"
#include "../../timer.h"

#include "common.h"
#include "gruu.h"

/* pub-gruu / temp-gruu copied off the reply Contact and linked after the
 * request Contact's parameter list for the duration of one save(). */
static param_t *gruu_extra = NULL;
static param_t **gruu_link = NULL;

static int ci_param_name_eq(const param_t *p, const char *lit, int len)
{
	return p->name.len == len && p->name.s
			&& strncasecmp(p->name.s, lit, len) == 0;
}

static int ci_list_has(param_t *list, const char *lit, int len)
{
	for(; list; list = list->next) {
		if(ci_param_name_eq(list, lit, len))
			return 1;
	}
	return 0;
}

void reg_ci_detach_gruu(void)
{
	param_t *p, *next;

	if(gruu_link)
		*gruu_link = NULL;
	gruu_link = NULL;
	for(p = gruu_extra; p; p = next) {
		next = p->next;
		pkg_free(p->name.s);
		if(p->body.s)
			pkg_free(p->body.s);
		pkg_free(p);
	}
	gruu_extra = NULL;
}

static param_t *clone_gruu_param(const param_t *src)
{
	param_t *n;

	n = pkg_malloc(sizeof(*n));
	if(n == NULL)
		return NULL;
	memset(n, 0, sizeof(*n));
	n->type = src->type;
	if(pkg_str_dup(&n->name, (str *)&src->name) < 0) {
		pkg_free(n);
		return NULL;
	}
	if(src->body.s && src->body.len && pkg_str_dup(&n->body, (str *)&src->body) < 0) {
		pkg_free(n->name.s);
		pkg_free(n);
		return NULL;
	}
	return n;
}

/* Keep the request Contact's feature tags and append any GRUU the registrar
 * put on the reply. The nodes are clones: the reply Contact is freed when
 * save() returns, and the request list must not keep pointers into it. */
static void chain_reply_gruu(param_t **dst, param_t *src)
{
	param_t *copy, *last = NULL, *p, *tail;

	reg_ci_detach_gruu();
	if(src == NULL)
		return;

	for(p = src; p; p = p->next) {
		if(!ci_param_name_eq(p, "pub-gruu", 8) && !ci_param_name_eq(p, "temp-gruu", 9))
			continue;
		if(p->body.len <= 0)
			continue;
		if(ci_list_has(*dst, p->name.s, p->name.len))
			continue;
		copy = clone_gruu_param(p);
		if(copy == NULL) {
			LM_ERR("failed to copy GRUU contact parameter\n");
			return;
		}
		if(gruu_extra == NULL)
			gruu_extra = copy;
		else
			last->next = copy;
		last = copy;
	}
	if(gruu_extra == NULL)
		return;

	if(*dst == NULL) {
		*dst = gruu_extra;
		gruu_link = dst;
		return;
	}
	tail = *dst;
	while(tail->next)
		tail = tail->next;
	gruu_link = &tail->next;
	tail->next = gruu_extra;
}


static param_t *new_gruu_param(const char *name, int name_len, str *body)
{
	param_t *n;
	str s;

	n = pkg_malloc(sizeof(*n));
	if(n == NULL)
		return NULL;
	memset(n, 0, sizeof(*n));
	s.s = (char *)name;
	s.len = name_len;
	if(pkg_str_dup(&n->name, &s) < 0) {
		pkg_free(n);
		return NULL;
	}
	n->body = *body;
	return n;
}

/* Same layout as the reply Contact (registrar reply.c). The value keeps its
 * SIP quotes: usrloc joins stored parameters with ';', and the ';gr' inside
 * an unquoted GRUU would split into a parameter of its own on reload. */
int reg_ci_attach_gruu(ucontact_info_t *ci, str *aor)
{
	static const char sip_proto[] = "sip:";
	static const char gr_param[] = ";gr=";
	static const char gr_no_val[] = ";gr";
	str guser, ghost, pub = STR_NULL, tmp = STR_NULL;
	param_t *pub_p = NULL, *tmp_p = NULL, *tail;
	char *p;
	int glen;

	if(ci == NULL || ci->instance.len < 3 || ci->callid == NULL)
		return 0;
	if(ci_list_has(ci->params, "pub-gruu", 8)
			|| ci_list_has(ci->params, "temp-gruu", 9))
		return 0;

	if(reg_gruu_target(aor, ci->sock, 0, &guser, &ghost) < 0) {
		LM_ERR("failed to select GRUU host\n");
		return -1;
	}
	pub.s = pkg_malloc(2 + sizeof(sip_proto) - 1 + guser.len
			+ (ghost.len ? 1 + ghost.len : 0) + sizeof(gr_param) - 1
			+ ci->instance.len - 2);
	if(pub.s == NULL)
		goto oom;
	p = pub.s;
	*p++ = '"';
	memcpy(p, sip_proto, sizeof(sip_proto) - 1);
	p += sizeof(sip_proto) - 1;
	memcpy(p, guser.s, guser.len);
	p += guser.len;
	if(ghost.len) {
		*p++ = '@';
		memcpy(p, ghost.s, ghost.len);
		p += ghost.len;
	}
	memcpy(p, gr_param, sizeof(gr_param) - 1);
	p += sizeof(gr_param) - 1;
	memcpy(p, ci->instance.s + 1, ci->instance.len - 2);
	p += ci->instance.len - 2;
	*p++ = '"';
	pub.len = p - pub.s;

	glen = calc_temp_gruu_len(aor, &ci->instance, ci->callid);
	if(glen > 0) {
		if(reg_gruu_target(aor, ci->sock, 1, &guser, &ghost) < 0
				|| ghost.len <= 0) {
			LM_ERR("failed to select temporary GRUU host\n");
			goto error;
		}
		tmp.s = pkg_malloc(2 + sizeof(sip_proto) - 1 + TEMP_GRUU_HEADER_SIZE
				+ glen + 1 + ghost.len + sizeof(gr_no_val) - 1);
		if(tmp.s == NULL)
			goto oom;
		p = tmp.s;
		*p++ = '"';
		memcpy(p, sip_proto, sizeof(sip_proto) - 1);
		p += sizeof(sip_proto) - 1;
		memcpy(p, TEMP_GRUU_HEADER, TEMP_GRUU_HEADER_SIZE);
		p += TEMP_GRUU_HEADER_SIZE;
		glen = build_temp_gruu(aor, &ci->instance, ci->callid,
				(int)ci->expires, p);
		if(glen < 0) {
			LM_ERR("failed to build temporary GRUU\n");
			goto error;
		}
		p += glen;
		*p++ = '@';
		memcpy(p, ghost.s, ghost.len);
		p += ghost.len;
		memcpy(p, gr_no_val, sizeof(gr_no_val) - 1);
		p += sizeof(gr_no_val) - 1;
		*p++ = '"';
		tmp.len = p - tmp.s;
	}

	if((pub_p = new_gruu_param("pub-gruu", 8, &pub)) == NULL)
		goto oom;
	pub.s = NULL;
	if(tmp.s) {
		if((tmp_p = new_gruu_param("temp-gruu", 9, &tmp)) == NULL)
			goto oom;
		tmp.s = NULL;
		pub_p->next = tmp_p;
	}

	/* pack_ci() detached any earlier chain, so this one starts empty. */
	reg_ci_detach_gruu();
	gruu_extra = pub_p;
	if(ci->params == NULL) {
		ci->params = gruu_extra;
		gruu_link = &ci->params;
	} else {
		tail = ci->params;
		while(tail->next)
			tail = tail->next;
		gruu_link = &tail->next;
		tail->next = gruu_extra;
	}
	return 0;

oom:
	LM_ERR("no more pkg memory\n");
error:
	if(pub.s)
		pkg_free(pub.s);
	if(tmp.s)
		pkg_free(tmp.s);
	if(pub_p) {
		pkg_free(pub_p->name.s);
		pkg_free(pub_p->body.s);
		pkg_free(pub_p);
	}
	return -1;
}

/*! \brief
 * Fills the common part (for all contacts) of the info structure
 */
ucontact_info_t *pack_ci(struct sip_msg* _m, contact_t* _c, unsigned int _e,
             unsigned int _f, unsigned int _nat_flag, unsigned int _reg_flags,
			 str *ownership_tag, struct ct_match *cmatch)
{
	static ucontact_info_t ci;
	static str no_ua = str_init("n/a");
	static str callid;
	static str path_received = {0,0};
	static str path;
	static str received = {0,0};
	static int received_searched;
	static unsigned int allowed, allow_parsed;
	static struct sip_msg *m = 0;
	static int_str attr_avp_value;

	struct usr_avp *avp_attr;
	int_str val;

	ci.contact_id = 0;

	if (_m) {
		/* A previous save() may still have GRUU nodes linked onto its
		 * request Contact. Drop them before this message's parameter list
		 * is read. */
		reg_ci_detach_gruu();
		memset(&ci, 0, sizeof ci);

		/* Get callid of the message */
		callid = _m->callid->body;
		trim_trailing(&callid);
		if (callid.len > CALLID_MAX_SIZE) {
			rerrno = R_CALLID_LEN;
			LM_ERR("callid too long\n");
			goto error;
		}
		ci.callid = &callid;

		/* Get CSeq number of the message */
		if (str2int(&get_cseq(_m)->number, (unsigned int*)&ci.cseq) < 0) {
			rerrno = R_INV_CSEQ;
			LM_ERR("failed to convert cseq number\n");
			goto error;
		}

		ci.sock = _m->rcv.bind_address;

		/* additional info from message */
		if (parse_headers(_m, HDR_USERAGENT_F, 0) != -1 && _m->user_agent &&
		_m->user_agent->body.len>0 && _m->user_agent->body.len<UA_MAX_SIZE) {
			ci.user_agent = &_m->user_agent->body;
		} else {
			ci.user_agent = &no_ua;
		}

		/* extract Path headers */
		if (_reg_flags & REG_SAVE_PATH_FLAG) {
			if (build_path_vector(_m, &path, &path_received, _reg_flags) < 0) {
				rerrno = R_PARSE_PATH;
				goto error;
			}
			if (path.len && path.s) {
				ci.path = &path;
				/* save in msg too for reply */
				if (set_path_vector(_m, &path) < 0) {
					rerrno = R_PARSE_PATH;
					goto error;
				}
			}
		}

		ci.last_modified = get_act_time();

		/* set flags */
		ci.flags  = _f;
		ci.cflags =  getb0flags(_m);

		/* get received */
		if (path_received.len && path_received.s) {
			ci.cflags |= _nat_flag;
			ci.received = path_received;
		}

		if (parse_headers(_m, HDR_CONTACT_F, 0) != -1) {
			ci.params = get_first_contact(_m)->params;
		} else {
			if(_c && _c->params) {
				ci.params = _c->params;
			}
		}		

		if (ownership_tag)
			ci.shtag = *ownership_tag;

		ci.cmatch = cmatch;

		allow_parsed = 0; /* not parsed yet */
		received_searched = 0; /* not searched yet */
		m = _m; /* remember the message */
	}

	if (_c) {
		/* if doing param-based Contact matching, force an URI update */
		if (cmatch && cmatch->mode == CT_MATCH_PARAMS)
			ci.c = &_c->uri;

		/* Calculate q value of the contact */
		if (calc_contact_q(_c->q, &ci.q) < 0) {
			rerrno = R_INV_Q;
			LM_ERR("failed to calculate q\n");
			goto error;
		}

		/* set expire time, with an optional random deviation */
		ci.expires = randomize_expires(_e);

		if (pn_enable && _reg_flags & REG_SAVE__PN_ON_FLAG) {
			ci.flags |= FL_PN_ON;
			if (_e > pn_trigger_interval)
				ci.refresh_time = _e - pn_trigger_interval;
		} else {
			ci.flags &= ~FL_PN_ON;
		}

		/* Get methods of contact */
		if (_c->methods) {
			if (parse_methods(&(_c->methods->body), &ci.methods) < 0) {
				rerrno = R_PARSE;
				LM_ERR("failed to parse contact methods\n");
				goto error;
			}
		} else {
			/* check on Allow hdr */
			if (allow_parsed == 0) {
				if (m && parse_allow( m ) != -1) {
					allowed = get_allow_methods(m);
				} else {
					allowed = ALL_METHODS;
				}
				allow_parsed = 1;
			}
			ci.methods = allowed;
		}

		if (_c->instance)
			ci.instance = _c->instance->body;

		/* get received */
		if (ci.received.len==0) {
			if (_c->received) {
				ci.received = _c->received->body;
			} else {
				if (!received_searched) {
					memset(&val, 0, sizeof(int_str));
					if (rcv_avp_name>=0
								&& search_first_avp(rcv_avp_type, rcv_avp_name, &val, 0)
								&& val.s.len > 0) {
						if (val.s.len>RECEIVED_MAX_SIZE) {
							rerrno = R_CONTACT_LEN;
							LM_ERR("received too long\n");
							goto error;
						}
						received = val.s;
					} else {
						received.s = 0;
						received.len = 0;
					}
					received_searched = 1;
				}
				ci.received = received;
			}
		}

		/* GRUU is added by the registrar on the reply Contact. The request
		 * Contact still carries the feature tags. Keep both. */
		if (_c)
			chain_reply_gruu(&ci.params, _c->params);

		/* additional information (script pvar) */
		if (attr_avp_name != -1) {
			avp_attr = search_first_avp(attr_avp_type, attr_avp_name,
										&attr_avp_value, NULL);
			if (avp_attr) {
				ci.attr = &attr_avp_value.s;

				LM_DBG("Attributes: %.*s\n", ci.attr->len, ci.attr->s);
			}
		}
	}

	return &ci;
error:
	return 0;
}

void print_ci(ucontact_info_t *ci)
{
	LM_DBG(" ----- UCI DUMP (%p) ------\n", ci);
	LM_DBG("received: %.*s, path: %.*s\n", ci->received.len, ci->received.s,
	       ci->path ? ci->path->len : 0, ci->path ? ci->path->s : NULL);
	LM_DBG("expires: %lld, expires_in: %lld, expires_out: %lld\n", (long long)ci->expires,
	       (long long)ci->expires_in, (long long)ci->expires_out);
	LM_DBG("q: %d, instance: %.*s, callid: %.*s\n", ci->q, ci->instance.len,
	       ci->instance.s, ci->callid ? ci->callid->len : 0,
	       ci->callid ? ci->callid->s : NULL);
	LM_DBG("cseq: %d, flags: %d, cflags: %d\n", ci->cseq, ci->flags,
	       ci->cflags);
	LM_DBG("user_agent: %.*s, sock: %p, methods: %d\n",
	       ci->user_agent ? ci->user_agent->len : 0,
	       ci->user_agent ? ci->user_agent->s : NULL, ci->sock, ci->methods);
	LM_DBG("last_modified: %lld, attr: %.*s\n", (long long)ci->last_modified,
	       ci->attr ? ci->attr->len : 0, ci->attr ? ci->attr->s : NULL);
}

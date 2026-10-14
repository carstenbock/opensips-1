/*
 * Rebuild a binding from S-CSCF restoration information (3GPP TS 23.380)
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
 */

/*!
 * \file
 * \brief SIP registrar module - restore a binding without a REGISTER
 * \ingroup registrar
 *
 * An S-CSCF that lost its registrations gets them back from the HSS as
 * SCSCF-Restoration-Info (TS 29.229 6.3.46): the Contact header field, the
 * Path, the Call-ID and the CSeq of the registration. save() takes all of
 * these from the current message, which is an INVITE or another request of
 * the restored user at that point, so the binding is built here from the
 * stored values instead. It is written through usrloc like any other, so
 * cluster replication, the usrloc events and the database write-back see a
 * normal binding.
 */

#include <string.h>

#include "../../str.h"
#include "../../dprint.h"
#include "../../ut.h"
#include "../../mem/mem.h"
#include "../../parser/msg_parser.h"
#include "../../parser/parse_methods.h"
#include "../../parser/contact/parse_contact.h"
#include "../../usr_avp.h"
#include "../../lib/reg/common.h"
#include "../../lib/reg/regtime.h"
#include "../usrloc/usrloc.h"
#include "reg_mod.h"
#include "restore.h"

static str restore_ua = str_init("n/a (IMS restoration)");

/* The ucontact_info of one contact of the stored Contact header field. The
 * strings point into contact, callid and path, which outlive the usrloc
 * write. */
static int restore_pack_ci(ucontact_info_t *ci, contact_t *c, str *callid,
		int cseq, str *path, int expires, struct sip_msg *msg, int flags,
		str *attr)
{
	memset(ci, 0, sizeof *ci);

	ci->callid = callid;
	ci->cseq = cseq;
	ci->user_agent = &restore_ua;
	ci->last_modified = get_act_time();
	ci->expires = get_act_time() + expires;
	ci->flags = (flags & REG_SAVE_MEMORY_FLAG) ? FL_MEM : FL_NONE;
	/* The socket the restoring request came in on: an S-CSCF pod has one,
	 * and the GRUU host is taken from it when no gruu_domain is set. */
	ci->sock = msg->rcv.bind_address;
	if (path->len > 0)
		ci->path = path;
	ci->params = c->params;
	if (c->instance)
		ci->instance = c->instance->body;
	if (attr && attr->len > 0)
		ci->attr = attr;

	if (calc_contact_q(c->q, &ci->q) < 0) {
		LM_ERR("invalid q value in the stored contact\n");
		return -1;
	}
	if (c->methods) {
		if (parse_methods(&c->methods->body, &ci->methods) < 0) {
			LM_ERR("invalid methods parameter in the stored contact\n");
			return -1;
		}
	} else {
		ci->methods = ALL_METHODS;
	}

	return 0;
}

int restore_contact(struct sip_msg *msg, void *domain, str *aor_uri,
		str *contact, str *path, str *callid, int *cseq, int *expires,
		void *save_flags)
{
	struct save_flags *sf = (struct save_flags *)save_flags;
	struct ct_match cmatch = {.mode = CT_MATCH_NONE};
	udomain_t *d = (udomain_t *)domain;
	ucontact_info_t ci;
	contact_t *contacts = NULL, *c;
	urecord_t *r = NULL;
	ucontact_t *uc;
	struct usr_avp *avp_attr;
	int_str attr_val;
	str attr = STR_NULL;
	str aor, ct_copy = STR_NULL;
	char *ct_buf;
	int flags = sf ? sf->flags : 0;
	int restored = 0;

	if (*expires <= 0) {
		LM_ERR("restoration of <%.*s> with expires %d - nothing to restore\n",
			aor_uri->len, aor_uri->s, *expires);
		return -1;
	}
	if (contact->len <= 0 || callid->len <= 0) {
		LM_ERR("restoration of <%.*s> without contact or Call-ID\n",
			aor_uri->len, aor_uri->s);
		return -1;
	}

	if (extract_aor(aor_uri, &aor, 0, 0, reg_use_domain) < 0 || aor.len == 0) {
		LM_ERR("failed to extract the AoR from <%.*s>\n",
			aor_uri->len, aor_uri->s);
		return -1;
	}

	/* parse_contacts() mangles its input and advances ct_copy.s past what
	 * it parsed, so the buffer is freed through ct_buf */
	if (pkg_str_dup(&ct_copy, contact) < 0) {
		LM_ERR("no more pkg memory\n");
		return -1;
	}
	ct_buf = ct_copy.s;
	if (parse_contacts(&ct_copy, &contacts) < 0 || !contacts) {
		LM_ERR("failed to parse the stored contact [%.*s]\n",
			contact->len, contact->s);
		goto error_free;
	}

	/* Same script attributes as save() stores for the binding */
	if (attr_avp_name != -1) {
		avp_attr = search_first_avp(attr_avp_type, attr_avp_name,
			&attr_val, NULL);
		if (avp_attr)
			attr = attr_val.s;
	}

	update_act_time();

	ul.lock_udomain(d, &aor);
	if (ul.get_urecord(d, &aor, &r) > 0) {
		if (ul.insert_urecord(d, &aor, &r, 0) < 0) {
			LM_ERR("failed to insert the record of <%.*s>\n", aor.len, aor.s);
			goto error_unlock;
		}
	}

	for (c = contacts; c; c = c->next) {
		if (restore_pack_ci(&ci, c, callid, *cseq, path, *expires, msg,
				flags, &attr) < 0)
			goto error_release;

		if ((flags & REG_SAVE_STORE_GRUU_FLAG) && !disable_gruu
				&& reg_ci_attach_gruu(&ci, &aor) < 0)
			LM_ERR("failed to store the GRUUs of AoR <%.*s>\n", aor.len, aor.s);

		if (r->contacts == NULL || ul.get_ucontact(r, &c->uri, callid,
				*cseq + 1, &cmatch, &uc) != 0) {
			if (ul.insert_ucontact(r, &c->uri, &ci, &cmatch, 0, &uc) < 0) {
				LM_ERR("failed to insert contact <%.*s> of <%.*s>\n",
					c->uri.len, c->uri.s, aor.len, aor.s);
				reg_ci_detach_gruu();
				goto error_release;
			}
		} else if (ul.update_ucontact(r, uc, &ci, &cmatch, 0) < 0) {
			LM_ERR("failed to update contact <%.*s> of <%.*s>\n",
				c->uri.len, c->uri.s, aor.len, aor.s);
			reg_ci_detach_gruu();
			goto error_release;
		}
		reg_ci_detach_gruu();
		restored++;
	}

	ul.release_urecord(r, 0);
	ul.unlock_udomain(d, &aor);
	free_contacts(&contacts);
	pkg_free(ct_buf);

	LM_DBG("restored %d contact(s) of <%.*s>, expires in %d s\n",
		restored, aor.len, aor.s, *expires);
	return 1;

error_release:
	ul.release_urecord(r, 0);
error_unlock:
	ul.unlock_udomain(d, &aor);
error_free:
	if (contacts)
		free_contacts(&contacts);
	pkg_free(ct_buf);
	return -1;
}

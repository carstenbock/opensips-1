/*
 * pua_reginfo module - Presence-User-Agent Handling of reg events
 *
 * Copyright (C) 2011, 2023 Carsten Bock, carsten@ng-voice.com
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
#include "usrloc_cb.h"
#include "pua_reginfo.h"
#include "../../lib/str_buffer.h"
#include <libxml/parser.h>
#include "../pua/pua.h"
#include "../presence/bind_presence.h"
#include "../../qvalue.h"
#include "../../lib/csv.h"
#include "../../trim.h"

/*
Contact: <sip:carsten@10.157.87.36:44733;transport=udp>;expires=600000;+g.oma.sip-im;language="en,fr";+g.3gpp.smsip;+g.oma.sip-im.large-message;audio;+g.3gpp.icsi-ref="urn%3Aurn-7%3A3gpp-application.ims.iari.gsma-vs";+g.3gpp.cs-voice.
Call-ID: 9ad9f89f-164d-bb86-1072-52e7e9eb5025.
*/

/*<?xml version="1.0"?>
<reginfo xmlns="urn:ietf:params:xml:ns:reginfo" version="0" state="full">
.<registration aor="sip:carsten@ng-voice.com" id="0xb33fa860" state="active">
..<contact id="0xb33fa994" state="active" event="registered" expires="3600">
...<uri>sip:carsten@10.157.87.36:43582;transport=udp</uri>
...<unknown-param name="+g.3gpp.cs-voice"></unknown-param>
...<unknown-param name="+g.3gpp.icsi-ref">urn0X0.0041FB74E7B54P-1022urn-70X0P+03gpp-application.ims.iari.gsma-vs</unknown-param>
...<unknown-param name="audio"></unknown-param>
...<unknown-param name="+g.oma.sip-im.large-message"></unknown-param>
...<unknown-param name="+g.3gpp.smsip"></unknown-param>
...<unknown-param name="language">en,fr</unknown-param>
...<unknown-param name="+g.oma.sip-im"></unknown-param>
...<unknown-param name="expires">600000</unknown-param>
..</contact>
.</registration>
</reginfo> */

/** Formats ::str string for use in printf-like functions.
 * This is a macro that prepares a ::str string for use in functions which 
 * use printf-like formatting strings. This macro is necessary  because 
 * ::str strings do not have to be zero-terminated and thus it is necessary 
 * to provide printf-like functions with the number of characters in the 
 * string manually. Here is an example how to use the macro: 
 * \code printf("%.*s\n", STR_FMT(var));\endcode Note well that the correct 
 * sequence in the formatting string is %.*, see the man page of printf for 
 * more details.
 */
#define STR_FMT(_pstr_)	\
  ((_pstr_ != (str *)0) ? (_pstr_)->len : 0), \
  ((_pstr_ != (str *)0) ? (_pstr_)->s : "")

static int _pua_reginfo_self_op = 0;

static pres_ev_t *reginfo_event = NULL;

void pua_reginfo_update_self_op(int v)
{
	_pua_reginfo_self_op = v;
}

#define VERSION_HOLDER "00000000000"

str reginfo_key_etag = str_init("reginfo_etag");


static str xml_start = str_init("<?xml version=\"1.0\"?>\n");

static str r_full = str_init("full");
static str r_reginfo_s = str_init(
		"<reginfo xmlns=\"urn:ietf:params:xml:ns:reginfo\" version=\"%s\" "
		"state=\"%.*s\">\n"); // before 74 but calculated 76
/* RFC 5628 §5. The gr namespace is declared only when a contact carries a GRUU. */
static str r_reginfo_s_gr = str_init(
		"<reginfo xmlns=\"urn:ietf:params:xml:ns:reginfo\" "
		"xmlns:gr=\"urn:ietf:params:xml:ns:gruuinfo\" version=\"%s\" "
		"state=\"%.*s\">\n");
static str r_reginfo_e = str_init("</reginfo>\n");

static str r_active = str_init("active");
static str r_terminated = str_init("terminated");
static str registration_s = str_init(
		"\t<registration aor=\"%.*s\" id=\"%p\" state=\"%.*s\">\n");
static str registration_e = str_init("\t</registration>\n");

//richard: we only use reg unreg refrsh and expire
static str r_registered = str_init("registered");
static str r_refreshed = str_init("refreshed");
static str r_expired = str_init("expired");
static str r_unregistered = str_init("unregistered");
static str contact_s =
		str_init("\t\t<contact id=\"%p\" state=\"%.*s\" event=\"%.*s\" "
						"expires=\"%d\" callid=\"%.*s\">\n");

static str contact_s_q =
		str_init("\t\t<contact id=\"%p\" state=\"%.*s\" "
						"event=\"%.*s\" expires=\"%d\" q=\"%.3f\" callid=\"%.*s\">\n");
static str contact_e = str_init("\t\t</contact>\n");		// 13, but 14

static str uri_s = str_init("\t\t\t<uri>");
static str uri_e = str_init("</uri>\n");

static str unknown_param_open = str_init("\t\t\t<unknown-param name=\"");
static str unknown_param_mid = str_init("\">");
static str unknown_param_close = str_init("</unknown-param>\n");
static str unknown_param_empty_end = str_init("\"></unknown-param>\n");

static str gr_pub_open = str_init("\t\t\t<gr:pub-gruu uri=\"");
static str gr_temp_open = str_init("\t\t\t<gr:temp-gruu uri=\"");
static str gr_close = str_init("\"/>\n");

/* RFC 3840 media feature tags. Prefixed tags (+g.3gpp.*, +sip.instance, ...)
 * are recognised by the leading '+', so they are not listed here. */
static str media_feature_tags[] = {
	str_init("actor"),
	str_init("application"),
	str_init("audio"),
	str_init("automata"),
	str_init("class"),
	str_init("control"),
	str_init("data"),
	str_init("description"),
	str_init("duplex"),
	str_init("events"),
	str_init("extensions"),
	str_init("isfocus"),
	str_init("language"),
	str_init("methods"),
	str_init("mobility"),
	str_init("priority"),
	str_init("schemes"),
	str_init("sip.byeless"),
	str_init("sip.ice"),
	str_init("sip.rendering"),
	str_init("text"),
	str_init("type"),
	str_init("video"),
	{NULL, 0},
};

static int param_name_eq(const str *name, const char *lit, int len)
{
	return name->len == len && strncasecmp(name->s, lit, len) == 0;
}

/* q and expires are attributes of <contact>. pub-gruu and temp-gruu are
 * RFC 5628 elements. Everything else that is an RFC 3840 feature tag is an
 * <unknown-param> (TS 24.229 §5.4.1.2.2F, RFC 3680). */
static int is_feature_tag(const str *name)
{
	str *tag;

	if(name->len <= 0 || name->s == NULL)
		return 0;
	if(param_name_eq(name, "q", 1) || param_name_eq(name, "expires", 7)
			|| param_name_eq(name, "pub-gruu", 8)
			|| param_name_eq(name, "temp-gruu", 9))
		return 0;
	if(name->s[0] == '+')
		return 1;
	for(tag = media_feature_tags; tag->s != NULL; tag++) {
		if(name->len == tag->len && strncasecmp(name->s, tag->s, tag->len) == 0)
			return 1;
	}
	return 0;
}

static int is_gruu_param(const str *name)
{
	return param_name_eq(name, "pub-gruu", 8) || param_name_eq(name, "temp-gruu", 9);
}

/* SIP quoting is not part of the parameter value. */
static str param_value(const param_t *param)
{
	str v = param->body;

	if(v.len >= 2 && v.s[0] == '"' && v.s[v.len - 1] == '"') {
		v.s++;
		v.len -= 2;
	}
	return v;
}

static void append_xml_escaped(str_buffer *buffer, const str *v, int attr)
{
	static str amp = str_init("&amp;");
	static str lt = str_init("&lt;");
	static str gt = str_init("&gt;");
	static str quot = str_init("&quot;");
	str one;
	int i;
	char c;

	for(i = 0; i < v->len; i++) {
		c = v->s[i];
		if(c == '&')
			str_buffer_append_str(buffer, &amp);
		else if(c == '<')
			str_buffer_append_str(buffer, &lt);
		else if(c == '>')
			str_buffer_append_str(buffer, &gt);
		else if(attr && c == '"')
			str_buffer_append_str(buffer, &quot);
		else {
			one.s = v->s + i;
			one.len = 1;
			str_buffer_append_str(buffer, &one);
		}
	}
}

static int record_has_gruu(ucontact_t *c)
{
	param_t *param;

	for(; c; c = c->next) {
		for(param = c->params; param; param = param->next) {
			if(is_gruu_param(&param->name) && param->body.len > 0)
				return 1;
		}
	}
	return 0;
}

static void process_xml_for_contact(str_buffer *buffer, ucontact_t *ptr, int expires, str state, str event)
{
	param_t *param;	
	if(ptr->q != -1) {
		float q = (float)ptr->q / 1000;

		str_buffer_append_str_fmt(buffer, &contact_s_q, ptr,
				STR_FMT(&state), STR_FMT(&event), expires, q, STR_FMT(&ptr->callid));
	} else {
		// XXX: before was it contact_s_q but no q so changed to contact_s
		str_buffer_append_str_fmt(buffer, &contact_s, ptr,
				STR_FMT(&state), STR_FMT(&event), expires, STR_FMT(&ptr->callid));
	}

	LM_DBG("Appending contact address: <%.*s>\n", STR_FMT(&ptr->c));

	str_buffer_append_str(buffer, &uri_s);
	str_buffer_append_str(buffer, &ptr->c);
	str_buffer_append_str(buffer, &uri_e);

	param = ptr->params;
	while(param) {
		str value;

		if(is_gruu_param(&param->name)) {
			/* RFC 5628 §5: child elements, not unknown-param. */
			value = param_value(param);
			if(value.len > 0) {
				str_buffer_append_str(buffer,
						param_name_eq(&param->name, "pub-gruu", 8)
								? &gr_pub_open : &gr_temp_open);
				append_xml_escaped(buffer, &value, 1);
				str_buffer_append_str(buffer, &gr_close);
			}
		} else if(is_feature_tag(&param->name)) {
			/* RFC 3680: the element content is the parameter value. '<' and
			 * '>' are escaped; SIP quotes are not added around it. */
			value = param_value(param);
			LM_DBG("Feature tag [%.*s] body [%.*s]\n",
					param->name.len, param->name.s, value.len, value.s);
			str_buffer_append_str(buffer, &unknown_param_open);
			append_xml_escaped(buffer, &param->name, 1);
			if(value.len > 0) {
				str_buffer_append_str(buffer, &unknown_param_mid);
				append_xml_escaped(buffer, &value, 0);
				str_buffer_append_str(buffer, &unknown_param_close);
			} else {
				str_buffer_append_str(buffer, &unknown_param_empty_end);
			}
		}

		param = param->next;
	}

	str_buffer_append_str(buffer, &contact_e);
}

str build_reginfo_full(urecord_t *record, ucontact_t *contact, str aor[], unsigned int aor_count, int type, int * count)
{
	str_buffer *buffer = NULL;
	str x = STR_NULL;
	str state = STR_NULL;
	str event = STR_NULL;
	ucontact_t *ptr;
	time_t cur_time = time(0);
	int expires = 0;
	int i = 0;

	buffer = new_str_buffer();
	if(!buffer) {
		LM_ERR("Error allocating str_buffer\n");
		return x;
	}
	str_buffer_append_str(buffer, &xml_start);
	str_buffer_append_str_fmt(buffer,
			record_has_gruu(record->contacts) ? &r_reginfo_s_gr : &r_reginfo_s,
			VERSION_HOLDER, STR_FMT(&r_full));

	ptr = record->contacts;
	LM_DBG("Records %p\n", ptr);
	while(ptr) {
		if(ptr == contact) {
			switch(type) {
					//richard we only use registered and refreshed and expired and unregistered
				case UL_CONTACT_INSERT:
				case UL_CONTACT_UPDATE:
					state = r_active;
					break;
				case UL_CONTACT_EXPIRE:
				case UL_CONTACT_DELETE:
					state = r_terminated;
					break;
				default:
					state = r_active;
			}
		} else {
			if (VALID_CONTACT(ptr, cur_time)) {
				state = r_active;
			} else {
				state = r_terminated;
			}
		}
		ptr = ptr->next;
	}

	for (i = 0; i < aor_count; i++) {
		/* Registration Node */
		LM_DBG("Registration Node for AOR %.*s [%.*s]\n", aor[i].len, aor[i].s, STR_FMT(&state));
		str_buffer_append_str_fmt(buffer, &registration_s,
				STR_FMT(&aor[i]), record, STR_FMT(&state));

		ptr = record->contacts;
		LM_DBG("Records %p\n", ptr);
		*count = 0;
		while(ptr) {
			expires = (int)(ptr->expires - cur_time);
			LM_DBG("  Contact %.*s (Expires %i, now %i, in %i)\n", ptr->c.len, ptr->c.s, (int)ptr->expires, (int)cur_time, expires);
			*count = *count + 1;
			if(ptr == contact) {
				switch(type) {
						//richard we only use registered and refreshed and expired and unregistered
					case UL_CONTACT_INSERT:
						state = r_active;
						event = r_registered;
						break;
					case UL_CONTACT_UPDATE:
						state = r_active;
						event = r_refreshed;
						break;
					case UL_CONTACT_EXPIRE:
						state = r_terminated;
						event = r_expired;
						expires = 0;
						break;
					case UL_CONTACT_DELETE:
						state = r_terminated;
						event = r_unregistered;
						expires = 0;
						break;
					default:
						state = r_active;
						event = r_registered;
				}
			} else {
				if (VALID_CONTACT(ptr, cur_time)) {
					state = r_active;
					event = r_registered;
				} else {
					state = r_terminated;
					event = r_expired;
					expires = 0;
				}
			}

			process_xml_for_contact(buffer, ptr, expires, state, event);
			ptr = ptr->next;
		}

		str_buffer_append_str(buffer, &registration_e);
	}

	str_buffer_append_str(buffer, &r_reginfo_e);

	if(str_buffer_has_error(buffer)) {
		LM_ERR("str_buffer had memory allocating errors while building\n");
	} else if(!str_buffer_to_str(buffer, &x)) {
		LM_ERR("no more pkg memory\n");
	}

	free_str_buffer(buffer);

	LM_DBG("Returned full reg-info: [%.*s]\n", STR_FMT(&x));

	return x;
}

void reginfo_usrloc_cb(void *binding, ul_cb_type type, ul_cb_extra *_) {
	ucontact_t *contact = (ucontact_t*)binding;
	urecord_t *record = NULL;
	event_t ev;
	str body = {NULL, 0};
	publ_info_t publ;
	presentity_t presentity;
	str content_type;
	str uri = {NULL, 0};
	struct sip_uri pres_uri;
	char etag_buf[MD5_LEN];
	str etag = {NULL, 0};
	int_str_t * key_value;
	int_str_t new_value;

	char *at = NULL;
	char id_buf[512];
	int id_buf_len;
	int count = 0, i = 0;
	str aorlist[20];
	unsigned int aor_count = 0;
	csv_record *pai_list = NULL;
	str s, str_dup;

	/* Get the URecord for the contact */
	LM_ERR("Searching urecord for contact-AOR %.*s (Contact %.*s), type %i\n",
		contact->aor->len, contact->aor->s,
		contact->c.len, contact->c.s, (int)type);
	ul.get_urecord(ul_domain, contact->aor, &record);
	if (record == NULL) {
		LM_DBG("Unable to get urecord for contact-AOR %.*s (Contact %.*s)\n",
			contact->aor->len, contact->aor->s,
			contact->c.len, contact->c.s);
		return;
	}

	if(_pua_reginfo_self_op == 1) {
		LM_DBG("operation triggered by own action for aor: %.*s (%d)\n",
				record->aor.len, record->aor.s, type);
		return;
	}

	/* Debug Output: */
	LM_DBG("AOR: %.*s (%.*s)\n", record->aor.len, record->aor.s, record->domain->len,
			record->domain->s);
	
	if (ul_identities_key.len > 0) {
		key_value = ul.get_urecord_key(record, &ul_identities_key);
		if (key_value && key_value->is_str) {
			LM_DBG("Got associated identities: %.*s\n", key_value->s.len, key_value->s.s);
			pai_list = parse_csv_record(&key_value->s);
			while(pai_list) {
				str_dup = pai_list->s;
				trim(&str_dup);
				if (str_dup.s[0] == '<') {
					// Strip tags <>:
					str_dup.s += 1;
					str_dup.len -= 2;
				}
				if (pkg_nt_str_dup(&s, &str_dup) < 0) {
					LM_ERR("Out of memory\n");
					goto error;
				}				
				LM_DBG("  Identity %.*s\n", s.len, s.s);
				aorlist[aor_count] = s;
				aor_count += 1;
				pai_list = pai_list->next;
				if (aor_count >= 20) break;
			}
		} else {
			LM_INFO("Looking for identities, but no info found in usrloc - not updating presence\n");
			return;
		}
	}

	/* Create AOR to be published */
	/* Search for @ in the AOR. In case no domain was provided, we will add the "default_domain" */
	at = memchr(record->aor.s, '@', record->aor.len);
	if(!at) {
		uri.len = record->aor.len + reginfo_default_domain.len + 6;
		uri.s = (char *)pkg_malloc(sizeof(char) * uri.len);
		if(uri.s == NULL) {
			LM_ERR("Error allocating memory for URI!\n");
			goto error;
		}
		memset(uri.s, 0, uri.len);
		if(record->aor.len > 0)
			uri.len = snprintf(uri.s, uri.len, "sip:%.*s@%.*s", record->aor.len,
					record->aor.s, reginfo_default_domain.len, reginfo_default_domain.s);
		else
			uri.len = snprintf(uri.s, uri.len, "sip:%.*s", reginfo_default_domain.len,
					reginfo_default_domain.s);
	} else {
		uri.len = record->aor.len + 6;
		uri.s = (char *)pkg_malloc(sizeof(char) * uri.len);
		if(uri.s == NULL) {
			LM_ERR("Error allocating memory for URI!\n");
			goto error;
		}
		uri.len = snprintf(
				uri.s, uri.len, "sip:%.*s", record->aor.len, record->aor.s);
	}

	if (parse_uri(uri.s, uri.len, &pres_uri)<0){
		LM_ERR("bad uri <%.*s>\n", uri.len, uri.s);
		goto error;
	}
	
	if (aor_count == 0) {
		aorlist[0] = uri;
		aor_count = 1;
	}
	
	/* Build the XML-Body: */
	body = build_reginfo_full(record, contact, aorlist, aor_count, type, &count);
	if(body.s == NULL) {
		LM_ERR("Error on creating XML-Body for publish\n");
		goto error;
	}

	LM_DBG("XML-Body (%i entries):\n%.*s\n", count, body.len, body.s);

	if (pres.update_presentity != NULL) {
		if (reginfo_event == NULL) {
			/* now search it back as we need the internal event structure */
			memset(&ev, 0, sizeof(event_t));
			ev.parsed = EVENT_REG;
			ev.text.s = "reg";
			ev.text.len = 3;
			reginfo_event = pres.search_event( &ev );
			if (reginfo_event==NULL) {
				LM_CRIT("BUG: failed to get back the registered REG-INFO event!\n");
				goto error;
			}		
		}

		/* now we have all the necessary values */
		/* fill in the fields of the structure */
		memset(&presentity, 0, sizeof(presentity_t));
		presentity.domain = pres_uri.host;
		presentity.user   = pres_uri.user;
		presentity.event = reginfo_event;
		if ((type & (UL_CONTACT_DELETE|UL_CONTACT_EXPIRE)) && (count == 0))	{
			presentity.expires = 0;
		} else {
			/* The document must outlive the binding. A fixed 3600 dropped
			 * the row while the contact was still registered, and the next
			 * publish then failed its etag lookup. */
			ucontact_t *c;
			time_t now = time(NULL);
			time_t remain = 0;

			for (c = record->contacts; c; c = c->next) {
				time_t left;

				if (c->expires == 0)
					left = 3600;
				else if (c->expires > now)
					left = c->expires - now;
				else
					continue;
				if (left > remain)
					remain = left;
			}
			presentity.expires = remain > 0 ? (int)remain : 3600;
		}
		presentity.received_time = (int)time(NULL);
		key_value = ul.get_urecord_key(record, &reginfo_key_etag);
		/* An empty string is still a str. Treating it as an existing etag
		 * makes update_presentity look up "" and insert nothing, so another
		 * P-CSCF has no row to fall back to. */
		if (key_value && key_value->is_str && key_value->s.len > 0) {
			presentity.old_etag = key_value->s;
		} else {
			id_buf_len = snprintf(id_buf, sizeof(id_buf), "%.*s;%i",
					record->aor.len, record->aor.s, count);
			etag.s = id_buf;
			etag.len = id_buf_len;
			MD5StringArray(etag_buf, &etag, 1);

			presentity.etag_new = 1;
			presentity.new_etag.s = etag_buf;
			presentity.new_etag.len = MD5_LEN;
		}
		LM_DBG("etag_new = %i, new_etag %.*s, old_etag %.*s\n", presentity.etag_new,
		  presentity.new_etag.len, presentity.new_etag.s,
		  presentity.old_etag.len, presentity.old_etag.s);
		
		presentity.body = body;

		/* query the database and update or insert */
		if(pres.update_presentity(&presentity) <0)
		{
			LM_ERR("when updating presentity\n");
			goto error;
		}

		/* update_presentity rotates the etag (etag_not_new is 0 for reg)
		 * and fills new_etag. Write that value only after it succeeds.
		 * Writing it beforehand stored "" on an update and the next publish
		 * could not insert. An expires=0 delete leaves "" so the next
		 * registration starts a new presentity. */
		memset(&new_value, 0, sizeof(int_str_t));
		new_value.is_str = 1;
		if (presentity.expires == 0) {
			new_value.s.s = "";
			new_value.s.len = 0;
		} else if (presentity.new_etag.s && presentity.new_etag.len > 0) {
			new_value.s = presentity.new_etag;
		}
		if (presentity.expires == 0 ||
				(presentity.new_etag.s && presentity.new_etag.len > 0))
			ul.put_urecord_key(record, &reginfo_key_etag, &new_value);

		LM_DBG("etag_new = %i, new_etag %.*s, old_etag %.*s\n", presentity.etag_new,
		  presentity.new_etag.len, presentity.new_etag.s,
		  presentity.old_etag.len, presentity.old_etag.s);
	}

	if (publish_reginfo && pua.send_publish != NULL) {
		content_type.s = "application/reginfo+xml";
		content_type.len = 23;


		memset(&publ, 0, sizeof(publ_info_t));

		publ.pres_uri = &uri;
		publ.body = &body;
		id_buf_len = snprintf(id_buf, sizeof(id_buf), "REGINFO_PUBLISH.%.*s@%.*s",
				record->aor.len, record->aor.s, record->domain->len, record->domain->s);
		publ.id.s = id_buf;
		publ.id.len = id_buf_len;
		publ.content_type = content_type;
		publ.expires = 3600;

		/* make UPDATE_TYPE, as if this "publish dialog" is not found
		by pua it will fallback to INSERT_TYPE anyway */
		publ.flag |= UPDATE_TYPE;
		publ.source_flag |= REGINFO_PUBLISH;
		publ.event |= REGINFO_EVENT;
		publ.extra_headers = NULL;

		if(outbound_proxy.s && outbound_proxy.len)
			publ.outbound_proxy = outbound_proxy;

		if(pua.send_publish(&publ) < 0) {
			LM_ERR("Error while sending publish\n");
		}
	}
error:
	for (i = 0; i < aor_count; i++)
		pkg_free(aorlist[i].s);
	if(body.s)
		pkg_free(body.s);

	return;
}

int w_reginfo_update(struct sip_msg *msg, str * aor) {
	urecord_t *record = NULL;

	/* Let's lock that domain for this AOR: */
	ul.lock_udomain(ul_domain, aor);
	/* Get the URecord for the contact */
	LM_DBG("Searching urecord for contact-AOR %.*s\n",
		aor->len, aor->s);
	ul.get_urecord(ul_domain, aor, &record);
	if (record == NULL) {
		LM_DBG("Unable to get urecord for contact-AOR %.*s\n",
			aor->len, aor->s);
		/* Let's lock that domain for this AOR: */
		ul.unlock_udomain(ul_domain, aor);
		return -1;
	}
	if (record->contacts) {
		if (record->contacts->next)
			reginfo_usrloc_cb((void*)record->contacts, UL_CONTACT_UPDATE, NULL);
		else
			reginfo_usrloc_cb((void*)record->contacts, UL_CONTACT_INSERT, NULL);
	} else {
		LM_DBG("Registered, but no contacts. Not updating Reg-Info-State");
	}

	/* Let's lock that domain for this AOR: */
	ul.unlock_udomain(ul_domain, aor);
	return 1;
}
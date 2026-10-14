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

#ifndef REG_RESTORE_H
#define REG_RESTORE_H

#include "../../parser/msg_parser.h"

/*! \brief
 * Insert (or refresh) the bindings of the Contact header field value
 * "contact" under the AoR of "aor_uri", with the given Path, Call-ID, CSeq
 * and remaining lifetime in seconds. Returns 1 on success, -1 on error.
 */
int restore_contact(struct sip_msg *msg, void *domain, str *aor_uri,
		str *contact, str *path, str *callid, int *cseq, int *expires,
		void *save_flags);

#endif /* REG_RESTORE_H */

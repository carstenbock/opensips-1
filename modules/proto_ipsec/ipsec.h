/*
 * Copyright (C) 2024 - OpenSIPS Solutions
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
 */

#ifndef _IPSEC_H_
#define _IPSEC_H_

#include <libmnl/libmnl.h>
#include <linux/netlink.h>
#include <linux/xfrm.h>

#include "../../locking.h"
#include "ipsec_user.h"
#include "../../parser/parse_security.h"

enum ipsec_dir {
	IPSEC_POLICY_IN = XFRM_POLICY_IN,
	IPSEC_POLICY_OUT = XFRM_POLICY_OUT,
};

enum ipsec_state {
	IPSEC_STATE_NEW = 0,
	IPSEC_STATE_TMP,
	IPSEC_STATE_OK,
	IPSEC_STATE_INVALID,
};

/*
 * IPSec mode according to 3GPP TS 33.203 Annex H/M:
 * - IPSEC_MODE_TRANSPORT: mod=trans (standard transport mode)
 * - IPSEC_MODE_UDP_ENCAP_TUNNEL: mod=UDP-enc-tun (NAT-T mode with UDP encapsulation)
 */
enum ipsec_mode {
	IPSEC_MODE_TRANSPORT = 0,
	IPSEC_MODE_UDP_ENCAP_TUNNEL,
};

/* NAT-T encapsulation port (RFC 3948) */
#define IPSEC_NAT_T_PORT 4500

/*
 * Hardware Offload support for IPSec
 * Modern NICs (e.g., Mellanox ConnectX, Intel QAT) can offload
 * ESP encryption/decryption to hardware for better performance.
 */
extern int ipsec_hw_offload_ifindex;  /* Interface index for HW offload, 0 = disabled */
extern int ipsec_hw_offload_enabled;  /* Runtime flag if offload is active */

/* Initialize hardware offload (resolve interface name to index) */
int ipsec_hw_offload_init(const char *ifname);

#define VALID_IPSEC_STATE(_s) \
	((_s) == IPSEC_STATE_TMP || \
	 (_s) == IPSEC_STATE_OK)

#define ipsec_socket mnl_socket

#include "../../str.h"
#include "../../socket_info.h"
#include "../../lib/list.h"

struct ipsec_spi;
struct ipsec_endpoint {
	struct ip_addr ip;
	unsigned int spi_s, spi_c;
	unsigned short port_s, port_c;
};

struct ipsec_ctx {
	/* read-only values */
	str ck, ik;
	struct ipsec_spi *spi_s, *spi_c;
	struct socket_info *server, *client;
	struct ipsec_algorithm_desc *alg, *ealg;
	struct ipsec_endpoint me;
	struct ipsec_endpoint ue;
	enum ipsec_mode mode;  /* transport or UDP-enc-tun (NAT-T) */

	/* dynamic values - should be locked */
	gen_lock_t lock;
	struct ipsec_user *user;
	enum ipsec_state state;
	struct list_head list;
	int ref;
	/*
	 * Set while no kernel SAs are installed for this ctx: before
	 * ipsec_sa_add_all() and after ipsec_sa_rm_all().  The kernel keeps
	 * exactly one XFRM policy per (selector, dir) and policies are deleted by
	 * selector, so the SAs of a ctx must be removed at most once: a second
	 * removal would delete the policies of a later ctx that reuses the same
	 * ports.  A ctx with this flag set is ignored by all lookups.
	 */
	int sa_removed;
	/* the registration reference (see the ownership model in ipsec.c) is held */
	int reg_ref;
	/* old set of security associations: superseded by a newer set, kept on
	 * the lifetime list until it expires (TS 24.229 5.2.2.2) */
	int old;
	/* created by a challenge to a REGISTER that was received unprotected */
	int initial;
	/* lifetime list (ipsec_tmp_contexts) and the tick the set expires at;
	 * both protected by ipsec_tmp_contexts_lock */
	struct list_head tmp;
	time_t expire;
};

/* a set that has its SAs in the kernel and may be used for traffic */
#define IPSEC_CTX_LIVE(_ctx) \
	(VALID_IPSEC_STATE((_ctx)->state) && !(_ctx)->sa_removed)

#define IPSEC_CTX_REF_COUNT_UNSAFE(_ctx, _c) \
	do { \
		LM_DBG("REF: ctx=%p ref=%d +%d = %d\n", (_ctx), (_ctx)->ref, (_c), (_ctx)->ref + (_c)); \
		(_ctx)->ref += (_c); \
	} while (0)
#define IPSEC_CTX_REF_COUNT(_ctx, _c) \
	do { \
		lock_get(&(_ctx)->lock); \
		IPSEC_CTX_REF_COUNT_UNSAFE(_ctx, _c); \
		lock_release(&(_ctx)->lock); \
	} while (0)
#define IPSEC_CTX_REF(_ctx) IPSEC_CTX_REF_COUNT(_ctx, 1);
#define IPSEC_CTX_REF_UNSAFE(_ctx) IPSEC_CTX_REF_COUNT_UNSAFE(_ctx, 1);
#define IPSEC_CTX_UNREF(_ctx) ipsec_ctx_release(_ctx)
#define IPSEC_CTX_UNREF_UNSAFE(_ctx) ipsec_ctx_release_unsafe(_ctx)

#define IPSEC_USER_SELECTOR 1387164160
#define IPSEC_POLICY_PRIORITY 1024

int ipsec_spi_match(struct ipsec_spi *spi, unsigned int ispi);

#define IPSEC_DEFAULT_MIN_SPI 65536
#define IPSEC_DEFAULT_MAX_SPI 262144
#define IPSEC_DEFAULT_TMP_TOUT 30
/* SIP level lifetime left to an old set once the new set is in use:
 * 64*T1 (TS 24.229 5.2.2.2), with T1 = 500 ms */
#define IPSEC_OLD_SA_LIFETIME 32
#define IPSEC_DEFAULT_PORT 5062

extern unsigned int ipsec_min_spi;
extern unsigned int ipsec_max_spi;
extern int ipsec_tmp_timeout;
extern unsigned int ipsec_reconcile_interval;
extern unsigned int ipsec_reconcile_grace;

int ipsec_init(void);
void ipsec_destroy(void);
struct ipsec_socket *ipsec_sock_new(void);
void ipsec_sock_close(struct ipsec_socket *sock);
int ipsec_sa_add(struct ipsec_socket *sock, struct ipsec_ctx *ctx,
		enum ipsec_dir dir, int client);
void ipsec_sa_rm(struct ipsec_socket *sock, struct ipsec_ctx *ctx,
		enum ipsec_dir dir, int client);
int ipsec_sa_add_all(struct ipsec_socket *sock, struct ipsec_ctx *ctx);
void ipsec_sa_rm_all(struct ipsec_socket *sock, struct ipsec_ctx *ctx);

/* ctx */
struct ipsec_ctx *ipsec_ctx_new(sec_agree_body_t *sa, struct ip_addr *ip,
		struct socket_info *ss, struct socket_info *sc, str *ck, str *ik,
		unsigned int spi_pc, unsigned int spi_ps, enum ipsec_mode mode);
struct ipsec_ctx *ipsec_ctx_find(struct ipsec_user *user, unsigned short port,
		unsigned int spi_pc);
void ipsec_ctx_push(struct ipsec_ctx *ctx);
struct ipsec_ctx *ipsec_ctx_get(void);
int ipsec_ctx_tryref(struct ipsec_ctx *ctx);
void ipsec_ctx_push_user(struct ipsec_user *user, struct ipsec_ctx *ctx, enum ipsec_state state);
void ipsec_ctx_add_tmp(struct ipsec_ctx *ctx, int lifetime);
int ipsec_ctx_collisions(struct ipsec_user *user, struct ipsec_ctx *prot,
		unsigned short ue_port_c, unsigned short ue_port_s,
		unsigned short port_ps, unsigned short port_pc);
void ipsec_ctx_challenge_user(struct ipsec_user *user, struct ipsec_ctx *prot,
		unsigned short ue_port_c, unsigned short ue_port_s,
		unsigned short port_ps, unsigned short port_pc);
int ipsec_ctx_confirm(struct ipsec_ctx *ctx);
void ipsec_ctx_unregister(struct ipsec_ctx *ctx);
void ipsec_ctx_release_user(struct ipsec_ctx *ctx);
void ipsec_ctx_release(struct ipsec_ctx *ctx);
int ipsec_ctx_release_unsafe(struct ipsec_ctx *ctx);
void ipsec_ctx_extend_tmp(struct ipsec_ctx *ctx);

/*
 * NAT-T UDP Encapsulation Socket Management
 *
 * For NAT-T (mod=UDP-enc-tun), we need separate UDP sockets configured
 * with UDP_ENCAP socket option. These sockets are used by the kernel
 * for ESP-in-UDP encapsulation/decapsulation.
 *
 * The encap sockets:
 * - Use SO_REUSEPORT to bind to the same port as SIP sockets
 * - Are configured with setsockopt(UDP_ENCAP, UDP_ENCAP_ESPINUDP)
 * - Are created on-demand when NAT-T mode is first used
 */

/* NAT-T encap socket entry (one per IP:port) */
struct ipsec_encap_socket {
	int fd;                      /* Socket file descriptor */
	struct ip_addr ip;           /* Bound IP address */
	unsigned short port;         /* Bound port */
	struct ipsec_encap_socket *next;
};

/* Initialize NAT-T encap socket subsystem */
int ipsec_encap_init(void);

/* Cleanup NAT-T encap sockets */
void ipsec_encap_destroy(void);

/* Get or create encap socket for given IP:port, returns fd or -1 on error */
int ipsec_encap_get_socket(struct ip_addr *ip, unsigned short port);

#endif /* _IPSEC_H_ */

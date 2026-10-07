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

#define _GNU_SOURCE       /* for SO_REUSEPORT */
#define _ISOC11_SOURCE    /* fix static_assert on older OSes */
#include <assert.h>
#include <unistd.h>       /* for close() */
#include <net/if.h>       /* for if_nametoindex */
#include <sys/socket.h>   /* for socket operations */
#include <netinet/in.h>   /* for sockaddr_in */

/* UDP_ENCAP constants - avoid including conflicting headers */
#ifndef UDP_ENCAP
#define UDP_ENCAP 100
#endif
#ifndef UDP_ENCAP_ESPINUDP
#define UDP_ENCAP_ESPINUDP 2  /* RFC 3948 */
#endif

/* SO_REUSEPORT may not be defined on all systems */
#ifndef SO_REUSEPORT
#define SO_REUSEPORT 15
#endif

#include "ipsec.h"
#include "ipsec_user.h"
#include "ipsec_algo.h"
#include "../../dprint.h"
#include "../../context.h"
#include "../../mem/mem.h"
#include <time.h>
#include <errno.h>
#include <string.h>

/*
 * Socket - IPSec Netlink/MNL socket
 */

void ipsec_ctx_timer(unsigned int ticks, void* param);

struct ipsec_socket *ipsec_sock_new(void)
{
	struct mnl_socket *sock = mnl_socket_open(NETLINK_XFRM);
	if (!sock) {
		LM_ERR("could not create ipsec socket\n");
		return NULL;
	}
	if (mnl_socket_bind(sock, 0, MNL_SOCKET_AUTOPID) < 0) {
		LM_ERR("could not bind ipsec socket\n");
		mnl_socket_close(sock);
		return NULL;
	}
	return sock;
}

void ipsec_sock_close(struct mnl_socket *sock)
{
	if (sock)
		mnl_socket_close(sock);
}

/*
 * SPI management
 */

struct list_head *ipsec_tmp_contexts;
gen_lock_t *ipsec_tmp_contexts_lock;

struct ipsec_spi {
	unsigned int spi;
	struct list_head free;
};

static unsigned int ipsec_seq;
static unsigned int ipsec_spi_no;
static struct ipsec_spi *ipsec_spi_map;
static struct list_head *ipsec_spi_free;
static gen_lock_t *ipsec_spi_lock;

unsigned int ipsec_min_spi = IPSEC_DEFAULT_MIN_SPI;
unsigned int ipsec_max_spi = IPSEC_DEFAULT_MAX_SPI;
unsigned int ipsec_reconcile_interval = 30;
unsigned int ipsec_reconcile_grace = 30;
static unsigned int ipsec_reconcile_tick;

static int ipsec_ctx_idx = -1;

int ipsec_init_spi(void)
{
	unsigned int tmp, spi, r;
	unsigned int *ipsec_spi_shuffle;

	if ((int)ipsec_min_spi < 0) {
		LM_ERR("negative min_spi(%d) not allowed\n", (int)ipsec_min_spi);
		return -1;
	}

	if ((int)ipsec_max_spi < 0) {
		LM_ERR("negative max_spi(%d) not allowed\n", (int)ipsec_max_spi);
		return -1;
	}

	if (ipsec_min_spi > ipsec_max_spi) {
		LM_WARN("min_spi(%u) > max_spi(%u), swapping them\n",
				ipsec_min_spi, ipsec_max_spi);
		tmp = ipsec_max_spi;
		ipsec_max_spi = ipsec_min_spi;
		ipsec_min_spi = tmp;
	}
	if (ipsec_min_spi == 0) {
		LM_ERR("SPI 0 is not allowed!\n");
		return -1;
	}
	ipsec_spi_lock = lock_alloc();
	if (!ipsec_spi_lock || !lock_init(ipsec_spi_lock)) {
		LM_ERR("oom for IPSec SPI lock\n");
		return -1;
	}

	ipsec_spi_free = shm_malloc(sizeof *ipsec_spi_free);
	if (!ipsec_spi_free) {
		LM_ERR("oom for IPSec SPI free map\n");
		return -1;
	}
	INIT_LIST_HEAD(ipsec_spi_free);
	/* spi is in [ipsec_min_spi, ipsec_max_spi] interval */;
	ipsec_spi_no = ipsec_max_spi - ipsec_min_spi + 1;
	ipsec_spi_map = shm_malloc(ipsec_spi_no * sizeof (*ipsec_spi_map));
	if (!ipsec_spi_map) {
		LM_ERR("oom for IPSec SPI map\n");
		return -1;
	}
	memset(ipsec_spi_map, 0, ipsec_spi_no * sizeof (*ipsec_spi_map));
	/* initialize them in order */
	for (spi = 0; spi < ipsec_spi_no; spi++) {
		INIT_LIST_HEAD(&ipsec_spi_map[spi].free);
		ipsec_spi_map[spi].spi = spi + ipsec_min_spi;
	}

	/* now we create a new array with them suffled */
	ipsec_spi_shuffle = pkg_malloc(ipsec_spi_no * sizeof (*ipsec_spi_shuffle));
	if (!ipsec_spi_shuffle) {
		LM_ERR("oom for IPSec SPI shuffle map\n");
		return -1;
	}
	for (spi = 0; spi < ipsec_spi_no; spi++)
		ipsec_spi_shuffle[spi] = spi;
	/* now apply Fisher-Yates shuffling */
	for (spi =  ipsec_spi_no - 1; spi > 0; spi--) {
		r = rand() % (spi + 1);
		tmp = ipsec_spi_shuffle[r];
		ipsec_spi_shuffle[r] = ipsec_spi_shuffle[spi];
		ipsec_spi_shuffle[spi] = tmp;
	}

	/* now add them in the free array in the (reversed) order they were shuffled */
	for (spi = 0; spi < ipsec_spi_no; spi++)
		list_add(&ipsec_spi_map[ipsec_spi_shuffle[spi]].free, ipsec_spi_free);

	/* the first element in the shuffle is the last one added in the free list */
	pkg_free(ipsec_spi_shuffle);

	return 0;
}

static void ipsec_allocate_spi(struct ipsec_spi *spi)
{
	list_del(&spi->free);
	LM_DBG("allocated SPI %u\n", spi->spi);
}

static struct ipsec_spi *ipsec_alloc_known_spi(unsigned int uspi)
{
	struct ipsec_spi *spi;
	if (uspi < ipsec_min_spi || uspi > ipsec_max_spi + 1) {
		LM_ERR("SPI %u out of range [%u, %u]\n", uspi, ipsec_min_spi, ipsec_max_spi);
		return NULL;
	}
	lock_get(ipsec_spi_lock);

	spi = &ipsec_spi_map[uspi - ipsec_min_spi];
	if (!list_is_valid(&spi->free)) {
		LM_ERR("SPI %u is not free\n", uspi);
		spi = NULL;
	} else {
		ipsec_allocate_spi(spi);
	}

	lock_release(ipsec_spi_lock);
	return spi;
}

int ipsec_spi_match(struct ipsec_spi *spi, unsigned int ispi)
{
	return spi->spi == ispi;
}

static struct ipsec_spi *ipsec_alloc_spi(unsigned int reserved_spi1,
		unsigned int reserved_spi2)
{
	struct ipsec_spi *spi = NULL;
	struct list_head *it;

	lock_get(ipsec_spi_lock);
	list_for_each(it, ipsec_spi_free) {
		spi = list_entry(it, struct ipsec_spi, free);
		if (!ipsec_spi_match(spi, reserved_spi1) && !ipsec_spi_match(spi, reserved_spi2))
			break;
		spi = NULL;
	}
	if (spi) {
		/* unlink from free */
		ipsec_allocate_spi(spi);
	} else {
		LM_CRIT("no more SPI available\n");
	}
	lock_release(ipsec_spi_lock);
	return spi;
}

static void ipsec_spi_release(struct ipsec_spi *spi)
{
	lock_get(ipsec_spi_lock);
	if (!list_is_valid(&spi->free)) {
		list_add_tail(&spi->free, ipsec_spi_free);
		LM_DBG("released SPI %u\n", spi->spi);
	} else {
		LM_BUG("releasing already released SPI %u\n", spi->spi);
	}
	lock_release(ipsec_spi_lock);
}

/*
 * Hash map
 */

/*
 * Init - initializing IPSec structures
 */

int ipsec_init(void)
{
	if (ipsec_init_spi() < 0)
		return -1;

	ipsec_seq = rand();
	ipsec_ctx_idx = context_register_ptr(CONTEXT_GLOBAL, (context_destroy_f)ipsec_ctx_release);

	ipsec_tmp_contexts = shm_malloc(sizeof *ipsec_tmp_contexts);
	if (!ipsec_tmp_contexts) {
		LM_ERR("oom for temporary contexts\n");
		return -1;
	}
	INIT_LIST_HEAD(ipsec_tmp_contexts);
	ipsec_tmp_contexts_lock = lock_alloc();
	if (!ipsec_tmp_contexts_lock || !lock_init(ipsec_tmp_contexts_lock)) {
		LM_ERR("could not allocate tmp lock\n");
		return -1;
	}

	/* Initialize NAT-T encap socket subsystem */
	if (ipsec_encap_init() < 0) {
		LM_ERR("could not initialize NAT-T encap socket subsystem\n");
		return -1;
	}

	if (register_timer("IPSec timer", ipsec_ctx_timer, NULL, 1,
			TIMER_FLAG_SKIP_ON_DELAY)<0 ) {
		LM_ERR("failed to register timer, halting...");
		return -1;
	}

	return 0;
}

void ipsec_destroy(void)
{
	if (ipsec_tmp_contexts_lock)
		lock_destroy(ipsec_tmp_contexts_lock);
	if (ipsec_tmp_contexts)
		shm_free(ipsec_tmp_contexts);
	if (ipsec_spi_lock)
		lock_destroy(ipsec_spi_lock);
	shm_free(ipsec_spi_map);
	/* Cleanup NAT-T encap sockets */
	ipsec_encap_destroy();
}

/*
 * NAT-T UDP Encapsulation Sockets
 *
 * For NAT Traversal (mod=UDP-enc-tun), the kernel needs UDP sockets
 * configured with UDP_ENCAP option to handle ESP-in-UDP encapsulation.
 *
 * These sockets are separate from the SIP sockets and are only used
 * by the kernel for ESP packet encapsulation/decapsulation.
 */

static struct ipsec_encap_socket *ipsec_encap_sockets = NULL;
static gen_lock_t *ipsec_encap_lock = NULL;

int ipsec_encap_init(void)
{
	ipsec_encap_lock = lock_alloc();
	if (!ipsec_encap_lock || !lock_init(ipsec_encap_lock)) {
		LM_ERR("could not allocate NAT-T encap socket lock\n");
		return -1;
	}
	ipsec_encap_sockets = NULL;
	LM_DBG("NAT-T encap socket subsystem initialized\n");
	return 0;
}

void ipsec_encap_destroy(void)
{
	struct ipsec_encap_socket *es, *next;

	if (!ipsec_encap_lock)
		return;

	lock_get(ipsec_encap_lock);
	for (es = ipsec_encap_sockets; es; es = next) {
		next = es->next;
		if (es->fd >= 0) {
			LM_DBG("Closing NAT-T encap socket fd=%d for %s:%hu\n",
					es->fd, ip_addr2a(&es->ip), es->port);
			close(es->fd);
		}
		shm_free(es);
	}
	ipsec_encap_sockets = NULL;
	lock_release(ipsec_encap_lock);

	lock_destroy(ipsec_encap_lock);
	lock_dealloc(ipsec_encap_lock);
	ipsec_encap_lock = NULL;
}

/*
 * Create and configure a NAT-T encap UDP socket
 * - Binds to IP:port with SO_REUSEPORT
 * - Configures UDP_ENCAP option for ESP-in-UDP
 */
static int ipsec_encap_create_socket(struct ip_addr *ip, unsigned short port)
{
	int fd, opt, af;
	union sockaddr_union su;

	af = ip->af;

	/* Create UDP socket */
	fd = socket(af, SOCK_DGRAM, IPPROTO_UDP);
	if (fd < 0) {
		LM_ERR("Failed to create NAT-T encap socket: %s\n", strerror(errno));
		return -1;
	}

	/* Enable SO_REUSEADDR */
	opt = 1;
	if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
		LM_WARN("Failed to set SO_REUSEADDR on encap socket: %s\n", strerror(errno));
	}

	/* Enable SO_REUSEPORT - critical for binding to same port as SIP socket */
	opt = 1;
	if (setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &opt, sizeof(opt)) < 0) {
		LM_ERR("Failed to set SO_REUSEPORT on encap socket: %s\n", strerror(errno));
		close(fd);
		return -1;
	}

	/* Prepare sockaddr */
	memset(&su, 0, sizeof(su));
	if (af == AF_INET) {
		su.sin.sin_family = AF_INET;
		su.sin.sin_port = htons(port);
		memcpy(&su.sin.sin_addr, ip->u.addr, ip->len);
	} else if (af == AF_INET6) {
		su.sin6.sin6_family = AF_INET6;
		su.sin6.sin6_port = htons(port);
		memcpy(&su.sin6.sin6_addr, ip->u.addr, ip->len);
	} else {
		LM_ERR("Unsupported address family %d\n", af);
		close(fd);
		return -1;
	}

	/* Bind socket */
	if (bind(fd, &su.s, sockaddru_len(su)) < 0) {
		LM_ERR("Failed to bind NAT-T encap socket to %s:%hu: %s\n",
				ip_addr2a(ip), port, strerror(errno));
		close(fd);
		return -1;
	}

	/*
	 * Configure UDP_ENCAP for ESP-in-UDP (RFC 3948)
	 * This tells the kernel this socket handles ESP encapsulated packets
	 */
	opt = UDP_ENCAP_ESPINUDP;
	if (setsockopt(fd, IPPROTO_UDP, UDP_ENCAP, &opt, sizeof(opt)) < 0) {
		LM_ERR("Failed to set UDP_ENCAP on socket for %s:%hu: %s\n",
				ip_addr2a(ip), port, strerror(errno));
		LM_ERR("Make sure your kernel supports IPSec NAT-T (CONFIG_XFRM)\n");
		close(fd);
		return -1;
	}

	LM_INFO("Created NAT-T encap socket fd=%d for %s:%hu\n",
			fd, ip_addr2a(ip), port);

	return fd;
}

/*
 * Get or create a NAT-T encap socket for the given IP:port
 * Returns the socket fd, or -1 on error
 */
int ipsec_encap_get_socket(struct ip_addr *ip, unsigned short port)
{
	struct ipsec_encap_socket *es;
	int fd;

	if (!ipsec_encap_lock) {
		LM_ERR("NAT-T encap subsystem not initialized\n");
		return -1;
	}

	lock_get(ipsec_encap_lock);

	/* Search for existing socket */
	for (es = ipsec_encap_sockets; es; es = es->next) {
		if (es->port == port && ip_addr_cmp(&es->ip, ip)) {
			fd = es->fd;
			lock_release(ipsec_encap_lock);
			LM_DBG("Reusing NAT-T encap socket fd=%d for %s:%hu\n",
					fd, ip_addr2a(ip), port);
			return fd;
		}
	}

	/* Create new socket */
	fd = ipsec_encap_create_socket(ip, port);
	if (fd < 0) {
		lock_release(ipsec_encap_lock);
		return -1;
	}

	/* Store in list */
	es = shm_malloc(sizeof(*es));
	if (!es) {
		LM_ERR("Out of memory for encap socket entry\n");
		close(fd);
		lock_release(ipsec_encap_lock);
		return -1;
	}
	memset(es, 0, sizeof(*es));
	es->fd = fd;
	memcpy(&es->ip, ip, sizeof(*ip));
	es->port = port;
	es->next = ipsec_encap_sockets;
	ipsec_encap_sockets = es;

	lock_release(ipsec_encap_lock);
	return fd;
}

/*
 * Hardware Offload support
 */
int ipsec_hw_offload_ifindex = 0;
int ipsec_hw_offload_enabled = 0;

int ipsec_hw_offload_init(const char *ifname)
{
	unsigned int ifindex;

	if (!ifname || !ifname[0]) {
		ipsec_hw_offload_ifindex = 0;
		ipsec_hw_offload_enabled = 0;
		return 0;
	}

	ifindex = if_nametoindex(ifname);
	if (ifindex == 0) {
		LM_ERR("Hardware offload: interface '%s' not found: %s\n",
				ifname, strerror(errno));
		return -1;
	}

	ipsec_hw_offload_ifindex = ifindex;
	ipsec_hw_offload_enabled = 1;
	LM_INFO("Hardware offload enabled on interface '%s' (index %u)\n",
			ifname, ifindex);
	return 0;
}

/*
 * SA - an unidirectional IPSec tunnel
 */

void ipsec_fill_selector(struct xfrm_selector *sel,
		struct ip_addr *src_ip, unsigned short src_port,
		struct ip_addr *dst_ip, unsigned short dst_port)
{
	/* selector - this handles both IPv4 and IPv6 */
	sel->family = src_ip->af;
	memcpy(&sel->saddr, &src_ip->u, src_ip->len);
	memcpy(&sel->daddr, &dst_ip->u, dst_ip->len);
	sel->prefixlen_s = src_ip->len * 8;
	sel->prefixlen_d = dst_ip->len * 8;
	sel->sport = htons(src_port);
	sel->dport = htons(dst_port);
	sel->sport_mask = ~0;
	sel->dport_mask = ~0;
	sel->user = IPSEC_USER_SELECTOR;
	sel->proto = 0; /* to avoid adding two SAs for both TCP and UDP,
							   we allow any protocol in the selector */
}

void ipsec_sa_rm(struct ipsec_socket *sock, struct ipsec_ctx *ctx,
		enum ipsec_dir dir, int client)
{
	char buf[MNL_SOCKET_BUFFER_SIZE];
	struct nlmsghdr *nlh;
	struct xfrm_usersa_id *sa_id;
	struct xfrm_userpolicy_id *policy_id;
	xfrm_address_t saddr;
	struct ipsec_endpoint *src, *dst;
	unsigned short src_port, dst_port;
	unsigned int spi;

	if (dir == IPSEC_POLICY_IN) {
		src = &ctx->ue;
		dst = &ctx->me;
	} else {
		src = &ctx->me;
		dst = &ctx->ue;
	}
	if (!client) {
		src_port = src->port_c;
		dst_port = dst->port_s;
		spi = dst->spi_s;
	} else {
		src_port = src->port_s;
		dst_port = dst->port_c;
		spi = dst->spi_c;
	}

	/* remove sa */
	memset(buf, 0, sizeof buf);
	nlh = mnl_nlmsg_put_header(buf);
	if (!nlh) {
		LM_ERR("could not store SA header\n");
		goto error;
	}
	nlh->nlmsg_flags = NLM_F_REQUEST;
	nlh->nlmsg_type = XFRM_MSG_DELSA;
	nlh->nlmsg_seq = ++ipsec_seq;

	sa_id = mnl_nlmsg_put_extra_header(nlh, sizeof (struct xfrm_usersa_id));
	if (!sa_id) {
		LM_ERR("could not get sa_id\n");
		goto error;
	}
	sa_id->spi = htonl(spi);
	sa_id->proto = IPPROTO_ESP;
	sa_id->family = dst->ip.af;
	memcpy(&sa_id->daddr, &dst->ip.u, dst->ip.len);
	memcpy(&saddr, &src->ip.u, src->ip.len);

	mnl_attr_put(nlh, XFRMA_SRCADDR, sizeof saddr, &saddr);

	if (mnl_socket_sendto(sock, nlh, nlh->nlmsg_len) < 0)
		LM_ERR("communicating with kernel for removing SA: %s\n", strerror(errno));

	/* remove policy */
	memset(buf, 0, sizeof buf);
	nlh = mnl_nlmsg_put_header(buf);
	if (!nlh) {
		LM_ERR("could not store policy header\n");
		goto error;
	}
	nlh->nlmsg_flags = NLM_F_REQUEST;
	nlh->nlmsg_type = XFRM_MSG_DELPOLICY;
	nlh->nlmsg_seq = ++ipsec_seq;

	policy_id = mnl_nlmsg_put_extra_header(nlh, sizeof (struct xfrm_userpolicy_id));
	if (!policy_id) {
		LM_ERR("could not get policy_id\n");
		goto error;
	}
	policy_id->dir = dir;
	policy_id->index = 0;
	ipsec_fill_selector(&policy_id->sel, &src->ip, src_port, &dst->ip, dst_port);

	if (mnl_socket_sendto(sock, nlh, nlh->nlmsg_len) < 0) {
		LM_ERR("communicating with kernel for removing policy: %s\n", strerror(errno));
		goto error;
	}

	LM_DBG("removed %s:%hu -> %s:%hu SA (SPI %u)\n",
			ip_addr2a(&src->ip), src_port, ip_addr2a(&dst->ip), dst_port, spi);
	return;
error:
	LM_ERR("failed to remove %s:%hu -> %s:%hu SA (SPI %u)\n",
			ip_addr2a(&src->ip), src_port, ip_addr2a(&dst->ip), dst_port, spi);
}

/* identical to (struct xfrm_algo), except the max key size is known */
struct xfrm_algo_osips {
	char alg_name[64];
	unsigned int alg_key_len;
	char alg_key[IPSEC_ALGO_MAX_KEY_SIZE];
};
static_assert(sizeof(struct xfrm_algo_osips) == sizeof(struct xfrm_algo)
		+ IPSEC_ALGO_MAX_KEY_SIZE, "ERROR!  Unexpected 'xfrm_algo' size!");

/*
 * NAT-T (NAT Traversal) support according to:
 * - 3GPP TS 33.203 Annex M: IPsec NAT traversal
 * - 3GPP TS 24.229: IP multimedia call control protocol
 * - RFC 3948: UDP Encapsulation of IPsec ESP Packets
 *
 * When NAT-T mode (mod=UDP-enc-tun) is used:
 * - ESP packets are encapsulated in UDP (port 4500 typically)
 * - Tunnel mode is used instead of transport mode
 * - XFRMA_ENCAP attribute is added to the SA
 */

/*
 * Hardware Offload support for IPSec
 *
 * Modern NICs can offload ESP processing to hardware:
 * - Mellanox/NVIDIA ConnectX-6 Dx and later
 * - Intel QuickAssist Technology (QAT)
 * - Marvell OCTEON
 *
 * When hw_offload_interface is configured, the module will:
 * 1. Try to create SA with XFRMA_OFFLOAD_DEV attribute
 * 2. If hardware offload fails, fall back to software processing
 *
 * XFRM_OFFLOAD_PACKET: Full packet offload (crypto + encap)
 * XFRM_OFFLOAD_INBOUND: Offload inbound direction
 */
#ifndef XFRM_OFFLOAD_INBOUND
#define XFRM_OFFLOAD_INBOUND 1
#endif
#ifndef XFRM_OFFLOAD_PACKET
#define XFRM_OFFLOAD_PACKET 2
#endif

/*
 * Structure for XFRM hardware offload (xfrm_user_offload)
 * This is defined in linux/xfrm.h but may not be available on older kernels
 */
#ifndef XFRMA_OFFLOAD_DEV
#define XFRMA_OFFLOAD_DEV 26
#endif

struct xfrm_user_offload_osips {
	int ifindex;
	__u8 flags;
};

/*
 * Internal SA add function with optional hardware offload
 * Parameter use_hw_offload: 1 = try hardware offload, 0 = software only
 * Returns: 0 on success, -1 on error
 */
static int _ipsec_sa_add(struct mnl_socket *sock, struct ipsec_ctx *ctx,
		enum ipsec_dir dir, int client, int use_hw_offload)
{
	char buf[MNL_SOCKET_BUFFER_SIZE];
	struct nlmsghdr *nlh;
	struct xfrm_usersa_info *sa_info;
	struct xfrm_userpolicy_info *policy_info;
	struct xfrm_algo_osips ia, ie;
	struct xfrm_user_tmpl tmpl;
	struct xfrm_encap_tmpl encap;
	struct xfrm_user_offload_osips offload;
	unsigned short dst_port;
	unsigned short src_port;
	unsigned int spi;
	struct ipsec_endpoint *src, *dst;
	int xfrm_mode;

	if (dir == IPSEC_POLICY_IN) {
		src = &ctx->ue;
		dst = &ctx->me;
	} else {
		src = &ctx->me;
		dst = &ctx->ue;
	}
	if (!client) {
		src_port = src->port_c;
		dst_port = dst->port_s;
		spi = dst->spi_s;
	} else {
		src_port = src->port_s;
		dst_port = dst->port_c;
		spi = dst->spi_c;
	}

	/*
	 * According to 3GPP TS 33.203, Annex H
	 * The changes compared to RFC 3329 [21] are:
	 *	"alg" parameter: Addition of "aes-gmac" and "null". Removal of "hmac-md5-96"
	 *	"ealg" parameter: Addition of "aes-cbc" and "aes-gcm". Removal of "des-ede3-cbc"
	 *	"mod" parameter: Addition of "UDP-enc-tun"
	 *
	 * "Hmac-sha-1-96" and "aes-cbc" are not recommended.
	 */
	if (ctx->ik.len && ctx->ik.len != (IPSEC_ALGO_KEY_SIZE / 8) * 2) {
		LM_ERR("invalid authentication key size %d, expected %d\n",
			  ctx->ik.len, ((IPSEC_ALGO_KEY_SIZE / 8) * 2));
		goto error;
	}
	if (ctx->ck.len && ctx->ck.len != (IPSEC_ALGO_KEY_SIZE / 8) * 2) {
		LM_ERR("invalid encryption key size %d, expected %d\n",
			  ctx->ck.len, ((IPSEC_ALGO_KEY_SIZE / 8) * 2));
		goto error;
	}
	memset(&ia, 0, sizeof ia);

	if (ctx->alg->deprecated) {
		LM_WARN("%s\n", ctx->alg->deprecated);
		ctx->alg->deprecated = NULL;
	}
	if (ctx->alg->key_len == IPSEC_ALGO_NULL_KEY_SIZE) {
		if (memcmp(ctx->ealg->name, "aes-gcm", sizeof("aes-gcm"))) {
			LM_ERR("null algorithm should only be used with aes-gcm encryption algorithm\n");
			goto error;
		}
	}

	strncpy(ia.alg_name, ctx->alg->xfrm_name, sizeof ia.alg_name - 1);
	ia.alg_key_len = ctx->alg->key_len;
	if (ctx->alg->key_len != 0 && hex2string(ctx->ik.s, ctx->ik.len, ia.alg_key) < 0) {
		LM_ERR("could not hexa decode integrity key [%.*s]\n", ctx->ik.len, ctx->ik.s);
		goto error;
	}

	memset(&ie, 0, sizeof ie);

	if (ctx->ealg->deprecated) {
		LM_WARN("%s\n", ctx->ealg->deprecated);
		ctx->ealg->deprecated = NULL;
	}
	strncpy(ie.alg_name, ctx->ealg->xfrm_name, sizeof ie.alg_name - 1);
	ie.alg_key_len = ctx->ealg->key_len;
	if (ctx->ealg->key_len != 0 && hex2string(ctx->ck.s, ctx->ck.len, ie.alg_key) < 0) {
		LM_ERR("could not hexa decode confidentialitty key [%.*s]\n", ctx->ck.len, ctx->ck.s);
		goto error;
	}

	/* SA message */
	memset(buf, 0, sizeof buf);
	nlh = mnl_nlmsg_put_header(buf);
	if (!nlh) {
		LM_ERR("could not store SA header\n");
		goto error;
	}
	nlh->nlmsg_flags = NLM_F_REQUEST|NLM_F_CREATE|NLM_F_EXCL;
	nlh->nlmsg_type = XFRM_MSG_NEWSA;
	nlh->nlmsg_seq = ++ipsec_seq;

	sa_info = mnl_nlmsg_put_extra_header(nlh, sizeof (struct xfrm_usersa_info));
	if (!sa_info) {
		LM_ERR("could not get sa_info\n");
		goto error;
	}
	/* selector */
	ipsec_fill_selector(&sa_info->sel, &src->ip, src_port, &dst->ip, dst_port);

	/* id */
	sa_info->id.spi = htonl(spi);
	sa_info->id.proto = IPPROTO_ESP;
	memcpy(&sa_info->id.daddr, &dst->ip.u, dst->ip.len);

	memcpy(&sa_info->saddr, &src->ip.u, src->ip.len);

	sa_info->lft.soft_byte_limit = XFRM_INF;
	sa_info->lft.hard_byte_limit = XFRM_INF;
	sa_info->lft.soft_packet_limit = XFRM_INF;
	sa_info->lft.hard_packet_limit = XFRM_INF;

	sa_info->seq = ipsec_seq;
	sa_info->reqid = htonl(spi);
	sa_info->family = dst->ip.af;
	sa_info->replay_window = 32;

	/*
	 * Set mode according to NAT-T configuration:
	 * - Transport mode (mod=trans): Standard IPsec transport mode
	 * - Tunnel mode (mod=UDP-enc-tun): NAT-T with UDP encapsulation
	 *   as per 3GPP TS 33.203 Annex M
	 */
	if (ctx->mode == IPSEC_MODE_UDP_ENCAP_TUNNEL) {
		xfrm_mode = XFRM_MODE_TUNNEL;
		sa_info->flags |= XFRM_STATE_NOPMTUDISC;
	} else {
		xfrm_mode = XFRM_MODE_TRANSPORT;
	}
	sa_info->mode = xfrm_mode;

	mnl_attr_put(nlh, XFRMA_ALG_AUTH,
			sizeof(struct xfrm_algo) + ia.alg_key_len, &ia);
	mnl_attr_put(nlh, XFRMA_ALG_CRYPT,
			sizeof(struct xfrm_algo) + ie.alg_key_len, &ie);

	/*
	 * NAT-T UDP Encapsulation (3GPP TS 33.203 Annex M, RFC 3948)
	 * When mod=UDP-enc-tun is negotiated, ESP packets are encapsulated
	 * in UDP datagrams to traverse NAT devices.
	 *
	 * For NAT-T to work, the kernel needs:
	 * 1. XFRMA_ENCAP attribute in the SA with encap type and ports
	 * 2. A UDP socket bound to the local port with UDP_ENCAP option set
	 *
	 * We create separate UDP sockets (with SO_REUSEPORT) for ESP encap
	 * that don't interfere with the regular SIP sockets.
	 */
	if (ctx->mode == IPSEC_MODE_UDP_ENCAP_TUNNEL) {
		/*
		 * Create encap socket for the local endpoint (receiver side)
		 * For INBOUND: local is dst (our server/client port)
		 * For OUTBOUND: we still need the socket on our port for responses
		 */
		int encap_fd = ipsec_encap_get_socket(&dst->ip, dst_port);
		if (encap_fd < 0) {
			LM_ERR("Failed to create NAT-T encap socket for %s:%hu\n",
					ip_addr2a(&dst->ip), dst_port);
			goto error;
		}

		memset(&encap, 0, sizeof(encap));
		encap.encap_type = UDP_ENCAP_ESPINUDP;
		encap.encap_sport = htons(src_port);
		encap.encap_dport = htons(dst_port);
		/* OA (Original Address) - set to zero, kernel fills if needed */
		mnl_attr_put(nlh, XFRMA_ENCAP, sizeof(encap), &encap);
		LM_DBG("NAT-T encapsulation: sport=%hu dport=%hu (encap socket fd=%d)\n",
				src_port, dst_port, encap_fd);
	}

	/*
	 * Hardware Offload (XFRMA_OFFLOAD_DEV)
	 * If enabled, request the kernel to offload ESP processing to the NIC.
	 * Supported by: Mellanox ConnectX-6 Dx+, Intel QAT, etc.
	 */
	if (use_hw_offload && ipsec_hw_offload_ifindex > 0) {
		memset(&offload, 0, sizeof(offload));
		offload.ifindex = ipsec_hw_offload_ifindex;
		/* XFRM_OFFLOAD_PACKET: full packet offload (crypto + encap)
		 * XFRM_OFFLOAD_INBOUND: set for inbound direction */
		offload.flags = XFRM_OFFLOAD_PACKET;
		if (dir == IPSEC_POLICY_IN)
			offload.flags |= XFRM_OFFLOAD_INBOUND;
		mnl_attr_put(nlh, XFRMA_OFFLOAD_DEV, sizeof(offload), &offload);
		LM_DBG("Hardware offload requested on ifindex %d, dir=%s\n",
				ipsec_hw_offload_ifindex,
				(dir == IPSEC_POLICY_IN) ? "IN" : "OUT");
	}

	if (mnl_socket_sendto(sock, nlh, nlh->nlmsg_len) < 0) {
		LM_ERR("communicating with kernel for new SA: %s\n", strerror(errno));
		goto error;
	}

	/* Policy message */
	memset(buf, 0, sizeof buf);
	nlh = mnl_nlmsg_put_header(buf);
	if (!nlh) {
		LM_ERR("could not store policy header\n");
		goto policy_error;
	}
	nlh->nlmsg_flags = NLM_F_REQUEST|NLM_F_CREATE|NLM_F_EXCL;
	nlh->nlmsg_type = XFRM_MSG_NEWPOLICY;
	nlh->nlmsg_seq = ++ipsec_seq;

	policy_info = mnl_nlmsg_put_extra_header(nlh, sizeof (struct xfrm_userpolicy_info));
	if (!policy_info) {
		LM_ERR("could not get policy_info\n");
		goto policy_error;
	}
	/* selector */
	ipsec_fill_selector(&policy_info->sel, &src->ip, src_port, &dst->ip, dst_port);

	policy_info->lft.soft_byte_limit = XFRM_INF;
	policy_info->lft.hard_byte_limit = XFRM_INF;
	policy_info->lft.soft_packet_limit = XFRM_INF;
	policy_info->lft.hard_packet_limit = XFRM_INF;
	policy_info->priority = IPSEC_POLICY_PRIORITY;
	policy_info->index = 0; /* currently not used */
	policy_info->dir = dir;
	policy_info->action = XFRM_POLICY_ALLOW;
	policy_info->flags = 0; /* XFRM_POLICY_LOCALOK|XFRM_POLICY_ICMP */
	policy_info->share = XFRM_SHARE_ANY;

	/* template */
	memset(&tmpl, 0, sizeof tmpl);
	tmpl.id.spi = htonl(spi);
	tmpl.id.proto = IPPROTO_ESP;
	memcpy(&tmpl.id.daddr, &dst->ip.u, dst->ip.len);
	tmpl.family = dst->ip.af;
	memcpy(&tmpl.saddr, &src->ip.u, src->ip.len);
	tmpl.reqid = htonl(spi);
	tmpl.mode = xfrm_mode;  /* Transport or Tunnel mode based on NAT-T */
	tmpl.share = XFRM_SHARE_ANY;
	tmpl.optional = 0;
	tmpl.aalgos = 0xffffffff;
	tmpl.ealgos = 0xffffffff;
	tmpl.calgos = 0xffffffff;

	mnl_attr_put(nlh, XFRMA_TMPL, sizeof(struct xfrm_user_tmpl), &tmpl);

	if (mnl_socket_sendto(sock, nlh, nlh->nlmsg_len) < 0) {
		LM_ERR("communicating with kernel for SA policy: %s\n", strerror(errno));
		goto policy_error;
	}

	LM_DBG("created %s:%hu -> %s:%hu SA (SPI %u)%s\n",
			ip_addr2a(&src->ip), src_port, ip_addr2a(&dst->ip), dst_port, spi,
			(use_hw_offload && ipsec_hw_offload_ifindex > 0) ? " [HW offload]" : "");
	return 0;
policy_error:
	ipsec_sa_rm(sock, ctx, dir, client);
error:
	LM_ERR("failed to create %s:%hu -> %s:%hu SA (SPI %u)%s\n",
			ip_addr2a(&src->ip), src_port, ip_addr2a(&dst->ip), dst_port, spi,
			(use_hw_offload && ipsec_hw_offload_ifindex > 0) ? " [HW offload]" : "");
	return -1;
}

/*
 * Public SA add function with automatic hardware offload fallback
 *
 * If hardware offload is enabled (hw_offload_interface configured):
 * 1. First attempts to create SA with hardware offload
 * 2. If that fails, falls back to software-only SA
 *
 * This ensures compatibility with NICs that don't support offload
 * or when offload resources are exhausted.
 */
int ipsec_sa_add(struct mnl_socket *sock, struct ipsec_ctx *ctx,
		enum ipsec_dir dir, int client)
{
	int ret;

	/* If hardware offload is enabled, try it first */
	if (ipsec_hw_offload_enabled && ipsec_hw_offload_ifindex > 0) {
		ret = _ipsec_sa_add(sock, ctx, dir, client, 1);
		if (ret == 0) {
			return 0;  /* Hardware offload succeeded */
		}

		/* Hardware offload failed, try software fallback */
		LM_WARN("Hardware offload failed for SA, falling back to software processing\n");
	}

	/* Software-only SA (no offload) */
	return _ipsec_sa_add(sock, ctx, dir, client, 0);
}

/*
 * CTX - structure that describes an IPSec tunnel
 *
 * Ownership model - who holds a reference (ctx->ref) and who drops it:
 *
 *  creator       ipsec_ctx_new() returns the ctx with one reference.
 *                ipsec_create() hands it to the processing context of the
 *                401 (ipsec_ctx_push()), which drops it when it is
 *                destroyed; ipsec_usrloc_restore() drops it itself once the
 *                ctx is linked to its user.
 *  registration  taken by ipsec_ctx_push_user() (ctx->reg_ref) when the ctx
 *                is linked into user->sas.  It stands for "this set belongs
 *                to a (pending) registration" and is dropped exactly once,
 *                by ipsec_ctx_unregister(): when the usrloc contact is
 *                deleted/expires, or when the lifetime of the set runs out.
 *  lifetime list held while the ctx is linked into ipsec_tmp_contexts
 *                (ctx->tmp), taken by ipsec_ctx_push_user(TMP) and
 *                ipsec_ctx_add_tmp() and dropped by whoever unlinks it: the
 *                timer, or ipsec_ctx_confirm() when the 200 OK turns a
 *                temporary set into an established one.
 *  transaction   taken by ipsec_handle_register_req() for the REGISTER that
 *                arrived over the set, dropped by tm with the transaction.
 *  processing    the lookups (ipsec_get_ctx_user(), ipsec_ctx_find(),
 *                ipsec_get_ctx_ip_port()) return a referenced ctx; the caller
 *                drops it or hands it over to the processing context.
 *
 * user->sas itself holds no reference: a ctx stays linked there until it is
 * freed, so that the ports of a set which a transaction still uses remain
 * visible to the next registration.  Each linked ctx holds one reference on
 * its user (user->ref), dropped when it is unlinked.
 *
 * Kernel SAs are installed by ipsec_sa_add_all() and removed exactly once
 * (ctx->sa_removed): when the lifetime of the set expires, when it has to
 * make room for a new set using the same ports, or with the last reference.
 *
 * Lock order: user map -> user -> lifetime list -> ctx.  Nothing is freed
 * and no netlink I/O is done with the lifetime list locked.
 */

#define IPSEC_GET_CTX() ((struct ipsec_ctx *)context_get_ptr(CONTEXT_GLOBAL, \
		current_processing_ctx, ipsec_ctx_idx))
#define IPSEC_PUT_CTX(_p) context_put_ptr(CONTEXT_GLOBAL, \
		current_processing_ctx, ipsec_ctx_idx, (_p))

void ipsec_sa_rm_all(struct ipsec_socket *sock, struct ipsec_ctx *ctx)
{
	int removed;

	/*
	 * Kernel XFRM allows exactly one policy per (selector, dir) and
	 * policies are deleted by selector: removing the SAs of a ctx twice
	 * would delete the policies of a later ctx that reuses the same
	 * ports.  The flag makes the removal happen at most once.
	 */
	lock_get(&ctx->lock);
	removed = ctx->sa_removed;
	ctx->sa_removed = 1;
	lock_release(&ctx->lock);
	if (removed)
		return;
	ipsec_sa_rm(sock, ctx, IPSEC_POLICY_IN, 0);
	ipsec_sa_rm(sock, ctx, IPSEC_POLICY_OUT, 0);
	ipsec_sa_rm(sock, ctx, IPSEC_POLICY_IN, 1);
	ipsec_sa_rm(sock, ctx, IPSEC_POLICY_OUT, 1);
}

int ipsec_sa_add_all(struct ipsec_socket *sock, struct ipsec_ctx *ctx)
{
	if (ipsec_sa_add(sock, ctx, IPSEC_POLICY_IN, 0) < 0) {
		LM_ERR("could not add UE(uc)->P(ps) SA\n");
		return -5;
	}
	if (ipsec_sa_add(sock, ctx, IPSEC_POLICY_OUT, 0) < 0) {
		LM_ERR("could not add P(ps)->UE(uc) SA\n");
		goto release_sa1;
	}
	if (ipsec_sa_add(sock, ctx, IPSEC_POLICY_IN, 1) < 0) {
		LM_ERR("could not add UE(us)->P(pc) SA\n");
		goto release_sa2;
	}
	if (ipsec_sa_add(sock, ctx, IPSEC_POLICY_OUT, 1) < 0) {
		LM_ERR("could not add P(pc)->UE(us) SA\n");
		goto release_sa3;
	}
	lock_get(&ctx->lock);
	ctx->sa_removed = 0;
	lock_release(&ctx->lock);
	return 0;

release_sa3:
	ipsec_sa_rm(sock, ctx, IPSEC_POLICY_IN, 1);
release_sa2:
	ipsec_sa_rm(sock, ctx, IPSEC_POLICY_OUT, 0);
release_sa1:
	ipsec_sa_rm(sock, ctx, IPSEC_POLICY_IN, 0);
	return -5;
}

static void ipsec_ctx_free(struct ipsec_ctx *ctx)
{
	struct ipsec_socket *sock = ipsec_sock_new();
	if (sock) {
		ipsec_sa_rm_all(sock, ctx);
		ipsec_sock_close(sock);
	}
	if (ctx->user)
		ipsec_ctx_release_user(ctx);
	ipsec_spi_release(ctx->spi_s);
	ipsec_spi_release(ctx->spi_c);
	lock_destroy(&ctx->lock);
	shm_free(ctx);
}

struct ipsec_ctx *ipsec_ctx_new(sec_agree_body_t *sa, struct ip_addr *ip,
		struct socket_info *ss, struct socket_info *sc, str *ck, str *ik,
		unsigned int spi_pc, unsigned int spi_ps, enum ipsec_mode mode)
{
	struct ipsec_spi *spi_s, *spi_c;
	struct ipsec_ctx *ctx;
	struct ipsec_algorithm_desc *alg, *ealg;
	str null_ealg = str_init("null"), *ealg_str;

	if (sc->address.af != ip->af) {
		LM_ERR("local AF %d differs from remote AF %d\n", sc->address.af, ip->af);
		return NULL;
	}

	alg = ipsec_parse_algorithm(&sa->ts3gpp.alg_str, IPSEC_ALGO_TYPE_AUTH);
	if (!alg) {
		LM_BUG("unknown authentication algorithm %.*s\n",
				sa->ts3gpp.alg_str.len, sa->ts3gpp.alg_str.s);
		return NULL;
	}
	ealg_str = (sa->ts3gpp.ealg_str.len?&sa->ts3gpp.ealg_str:&null_ealg);
	ealg = ipsec_parse_algorithm(ealg_str, IPSEC_ALGO_TYPE_ENC);
	if (!ealg) {
		LM_BUG("unknown encryption algorithm %.*s\n",
				ealg_str->len, ealg_str->s);
		return NULL;
	}

	/* allocate SPIs */
	if (!spi_pc)
		spi_c = ipsec_alloc_spi(sa->ts3gpp.spi_c, sa->ts3gpp.spi_s);
	else
		spi_c = ipsec_alloc_known_spi(spi_pc);
	if (!spi_c) {
		LM_ERR("could not allocate new spi-c\n");
		return NULL;
	}
	if (!spi_ps)
		spi_s = ipsec_alloc_spi(sa->ts3gpp.spi_c, sa->ts3gpp.spi_s);
	else
		spi_s = ipsec_alloc_known_spi(spi_ps);
	if (!spi_s) {
		LM_ERR("could not allocate new spi-s\n");
		ipsec_spi_release(spi_c);
		return NULL;
	}
	ctx = shm_malloc(sizeof(*ctx) + ck->len + ik->len);
	if (!ctx) {
		LM_ERR("oom for a new IPSec ctx\n");
		return NULL;
	}
	memset(ctx, 0, sizeof *ctx);
	ctx->spi_s = spi_s;
	ctx->spi_c = spi_c;
	if (!lock_init(&ctx->lock)) {
		LM_ERR("could not init IPSec ctx lock\n");
		goto error;
	}
	INIT_LIST_HEAD(&ctx->list);
	INIT_LIST_HEAD(&ctx->tmp);
	ctx->ref = 1;
	ctx->sa_removed = 1; /* until ipsec_sa_add_all() */
	ctx->server = ss;
	ctx->client = sc;
	ctx->alg = alg;
	ctx->ealg = ealg;
	ctx->mode = mode;
	/* own information - shortcut */
	memcpy(&ctx->me.ip, &sc->address, sizeof(struct ip_addr));
	ctx->me.spi_s = spi_s->spi;
	ctx->me.spi_c = spi_c->spi;
	ctx->me.port_s = ss->port_no;
	ctx->me.port_c = sc->port_no;
	memcpy(&ctx->ue.ip, ip, sizeof *ip);
	ctx->ue.spi_s = sa->ts3gpp.spi_s;
	ctx->ue.spi_c = sa->ts3gpp.spi_c;
	ctx->ue.port_s = sa->ts3gpp.port_s;
	ctx->ue.port_c = sa->ts3gpp.port_c;
	ctx->ck.s = (char *)(ctx + 1);
	memcpy(ctx->ck.s, ck->s, ck->len);
	ctx->ck.len = ck->len;
	ctx->ik.s = ctx->ck.s + ctx->ck.len;
	memcpy(ctx->ik.s, ik->s, ik->len);
	ctx->ik.len = ik->len;
	return ctx;
error:
	ipsec_ctx_free(ctx);
	return NULL;
}

void ipsec_ctx_push(struct ipsec_ctx *ctx)
{
	/* push the context in msg */
	IPSEC_PUT_CTX(ctx);
}

struct ipsec_ctx *ipsec_ctx_get(void)
{
	return IPSEC_GET_CTX();
}

/* takes a reference, unless the ctx is already being freed */
int ipsec_ctx_tryref(struct ipsec_ctx *ctx)
{
	int ok;

	lock_get(&ctx->lock);
	ok = (ctx->ref > 0 && VALID_IPSEC_STATE(ctx->state));
	if (ok)
		IPSEC_CTX_REF_UNSAFE(ctx);
	lock_release(&ctx->lock);
	return ok;
}

/*
 * Returns the (referenced) ctx of a usrloc contact.  The P-CSCF SPI is
 * unique among the contexts, the UE port alone is not: a UE may reuse its
 * ports for a later set.
 */
struct ipsec_ctx *ipsec_ctx_find(struct ipsec_user *user, unsigned short port,
		unsigned int spi_pc)
{
	struct list_head *it;
	struct ipsec_ctx *ctx = NULL;
	lock_get(&user->lock);
	list_for_each(it, &user->sas) {
		ctx = list_entry(it, struct ipsec_ctx, list);
		if (ctx->ue.port_c == port && ctx->me.spi_c == spi_pc &&
				ipsec_ctx_tryref(ctx))
			break;
		ctx = NULL;
	}
	lock_release(&user->lock);
	return ctx;
}

int ipsec_ctx_release_unsafe(struct ipsec_ctx *ctx)
{
	int free = 0;

	if (!ctx)
		return 0;

	if (ctx->ref > 0) {
		LM_DBG("REF: ctx=%p ref=%d -1 = %d\n", ctx, ctx->ref, ctx->ref - 1);
		free = (--(ctx->ref) == 0);
	} else {
		LM_BUG("invalid ref %d for ctx %p\n", ctx->ref, ctx);
	}
	return free;
}

void ipsec_ctx_release(struct ipsec_ctx *ctx)
{
	int free = 0;

	LM_DBG("Releasing IPSec ctx %p (state %d), ref %d\n", ctx, ctx?ctx->state:0, ctx?ctx->ref:0);

	if (!ctx || ctx->ref <= 0) {
		LM_DBG("ctx %p is NULL or has invalid ref %d\n", ctx, ctx?ctx->ref:0);
		return;
	}

	/* a ctx that never got linked to a user (state NEW) is released like
	 * any other - only one that is being freed already is left alone */
	if (ctx->state == IPSEC_STATE_INVALID) {
		LM_DBG("ctx %p is not in a valid state %d\n", ctx, ctx->state);
		return;
	}

	lock_get(&ctx->lock);
	free = ipsec_ctx_release_unsafe(ctx);
	if (free) ctx->state = IPSEC_STATE_INVALID; /* mark as invalid */
	lock_release(&ctx->lock);
	if (free) {
		LM_DBG("IPSec ctx %p released\n", ctx);
		if (ctx->user) {
			ipsec_ctx_release_user(ctx);
			ctx->user = NULL; /* avoid double release */
		}
		/* nobody can list it any more: ipsec_ctx_tryref() fails */
		if (!list_empty(&ctx->tmp))
			LM_BUG("freeing ctx %p which is still on the lifetime list\n", ctx);
		ipsec_ctx_free(ctx);
	} else {
		LM_DBG("IPSec ctx %p not released, ref=%d\n", ctx, ctx->ref);
	}
		
}

void ipsec_ctx_push_user(struct ipsec_user *user, struct ipsec_ctx *ctx, enum ipsec_state state)
{
	/* add to the user */
	lock_get(&user->lock);
	ctx->user = user;
	user->ref++;
	list_add_tail(&ctx->list, &user->sas);
	lock_release(&user->lock);

	/* add to temporarily list, with the state the timer expects there */
	lock_get(ipsec_tmp_contexts_lock);
	lock_get(&ctx->lock);
	/* first is the registration reference, second the one of the lifetime list */
	IPSEC_CTX_REF_COUNT_UNSAFE(ctx, (state == IPSEC_STATE_TMP?2:1));
	ctx->reg_ref = 1;
	ctx->state = state;
	lock_release(&ctx->lock);
	if (state == IPSEC_STATE_TMP) {
		ctx->expire = get_ticks() + ipsec_tmp_timeout;
		list_add_tail(&ctx->tmp, ipsec_tmp_contexts);
	}
	lock_release(ipsec_tmp_contexts_lock);
}

/*
 * Limits the SIP level lifetime of a set: puts the ctx on the lifetime list
 * (which takes its own reference) or, if it is already there, shortens its
 * lifetime.  When the lifetime is over the timer removes the SAs and drops
 * the registration reference.
 */
void ipsec_ctx_add_tmp(struct ipsec_ctx *ctx, int lifetime)
{
	time_t expire = get_ticks() + lifetime;

	lock_get(ipsec_tmp_contexts_lock);
	if (!list_empty(&ctx->tmp)) {
		if (ctx->expire > expire)
			ctx->expire = expire;
	} else if (ipsec_ctx_tryref(ctx)) {
		ctx->expire = expire;
		list_add_tail(&ctx->tmp, ipsec_tmp_contexts);
	}
	lock_release(ipsec_tmp_contexts_lock);
}

/* one (UE port, P-CSCF port) pair is one selector in each direction */
static int ipsec_ctx_same_ports(struct ipsec_ctx *ctx,
		unsigned short ue_port, unsigned short port)
{
	return (ctx->ue.port_c == ue_port && ctx->me.port_s == port) ||
		(ctx->ue.port_s == ue_port && ctx->me.port_c == port);
}

static int ipsec_ctx_collides(struct ipsec_ctx *ctx,
		unsigned short ue_port_c, unsigned short ue_port_s,
		unsigned short port_ps, unsigned short port_pc)
{
	return ipsec_ctx_same_ports(ctx, ue_port_c, port_ps) ||
		ipsec_ctx_same_ports(ctx, ue_port_s, port_pc);
}

/*
 * Tells whether a new set with the given ports could be installed next to
 * the existing sets of the user (the kernel takes one XFRM policy per
 * selector):
 *   0 - yes
 *   1 - only after removing an old (superseded) set, or the temporary set
 *       that protected the REGISTER
 *   2 - only after removing an established set that is in use
 * Temporary sets do not count otherwise: a new challenge deletes them.
 */
int ipsec_ctx_collisions(struct ipsec_user *user, struct ipsec_ctx *prot,
		unsigned short ue_port_c, unsigned short ue_port_s,
		unsigned short port_ps, unsigned short port_pc)
{
	struct list_head *it;
	struct ipsec_ctx *ctx;
	int ret = 0, c;

	lock_get(&user->lock);
	list_for_each(it, &user->sas) {
		ctx = list_entry(it, struct ipsec_ctx, list);
		if (!IPSEC_CTX_LIVE(ctx) ||
				(ctx->state == IPSEC_STATE_TMP && ctx != prot))
			continue;
		if (!ipsec_ctx_collides(ctx, ue_port_c, ue_port_s, port_ps, port_pc))
			continue;
		c = (ctx->state == IPSEC_STATE_OK && !ctx->old)?2:1;
		if (c > ret)
			ret = c;
	}
	lock_release(&user->lock);
	return ret;
}

/*
 * A 401 (Unauthorized) to a REGISTER of this user is about to set up a new
 * temporary set of security associations with the given ports.  "prot" is
 * the set that protected the REGISTER, NULL if it came unprotected.
 */
void ipsec_ctx_challenge_user(struct ipsec_user *user, struct ipsec_ctx *prot,
		unsigned short ue_port_c, unsigned short ue_port_s,
		unsigned short port_ps, unsigned short port_pc)
{
	struct list_head *it;
	struct ipsec_ctx *ctx;
	struct ipsec_socket *sock = ipsec_sock_new();

	if (!sock)
		return;
	lock_get(&user->lock);
	list_for_each(it, &user->sas) {
		ctx = list_entry(it, struct ipsec_ctx, list);
		if (!IPSEC_CTX_LIVE(ctx))
			continue;
		if (ctx->state == IPSEC_STATE_TMP && ctx != prot) {
			/*
			 * 3GPP TS 24.229 5.2.2.2: a 401 to a REGISTER deletes any
			 * temporary set of security associations towards the UE.
			 * The ctx is freed by the timer, which holds the reference
			 * of its lifetime list entry.
			 */
			ipsec_sa_rm_all(sock, ctx);
			ipsec_ctx_add_tmp(ctx, 0);
			continue;
		}
		/*
		 * 3GPP TS 24.229 5.2.2.2, TS 33.203 7.4.2a: the established sets
		 * (and the set the 401 is sent on) are kept; what becomes of them
		 * is decided when the 200 OK arrives (ipsec_ctx_confirm()) or the
		 * temporary set expires.
		 */
		if (!ipsec_ctx_collides(ctx, ue_port_c, ue_port_s, port_ps, port_pc))
			continue;
		/*
		 * SPEC-DEVIATION: TS 33.203 7.1 rule 3, TS 24.229 5.2.2.2 -- a
		 * REGISTER whose protected ports are already bound to a set of
		 * this user is not rejected, and that set is deleted at the 401
		 * instead of being kept until the new set is established: the
		 * kernel takes one XFRM policy per selector, and a UE that lost
		 * its SAs (or a P-CSCF with a single protected client port, see
		 * ipsec_create()) comes back with the very same ports
		 */
		LM_INFO("removing SAs of ctx %p (UE ports %hu/%hu, own ports %hu/%hu):"
				" new set uses the same ports\n", ctx, ctx->ue.port_c,
				ctx->ue.port_s, ctx->me.port_c, ctx->me.port_s);
		ipsec_sa_rm_all(sock, ctx);
		ipsec_ctx_add_tmp(ctx, 0);
	}
	lock_release(&user->lock);
	ipsec_sock_close(sock);
}

/*
 * The 200 OK to a REGISTER received over this set is being processed.
 * Returns:
 *   1 - the temporary set became an established one
 *   0 - the set was established already (registration refresh)
 *  -1 - the set is not usable any more (expired, deleted or superseded)
 */
int ipsec_ctx_confirm(struct ipsec_ctx *ctx)
{
	struct list_head *it;
	struct ipsec_ctx *old;
	struct ipsec_user *user;
	struct ipsec_socket *sock;
	int ret = -1;

	/* the state changes together with the lifetime list, so that the timer
	 * either expires the temporary set or does not see it at all */
	lock_get(ipsec_tmp_contexts_lock);
	lock_get(&ctx->lock);
	user = ctx->user;
	if (!user || !IPSEC_CTX_LIVE(ctx) || ctx->old) {
		ret = -1;
	} else if (ctx->state == IPSEC_STATE_OK) {
		ret = 0;
	} else if (!list_empty(&ctx->tmp)) {
		list_del(&ctx->tmp);
		INIT_LIST_HEAD(&ctx->tmp);
		ctx->state = IPSEC_STATE_OK;
		/* reference of the lifetime list; the caller holds its own */
		if (IPSEC_CTX_UNREF_UNSAFE(ctx))
			LM_BUG("ctx %p confirmed without a reference\n", ctx);
		ret = 1;
	}
	lock_release(&ctx->lock);
	lock_release(ipsec_tmp_contexts_lock);
	if (ret != 1)
		return ret;

	sock = ipsec_sock_new();
	lock_get(&user->lock);
	list_for_each(it, &user->sas) {
		old = list_entry(it, struct ipsec_ctx, list);
		if (old == ctx || !IPSEC_CTX_LIVE(old) || old->state != IPSEC_STATE_OK)
			continue;
		if (ctx->initial) {
			/*
			 * 3GPP TS 33.203 7.4.2a, TS 24.229 table 5.2.2-1: the
			 * REGISTER that started this authentication came
			 * unprotected, so the UE does not have the old sets any
			 * more - delete them
			 */
			if (sock)
				ipsec_sa_rm_all(sock, old);
			ipsec_ctx_add_tmp(old, 0);
		} else if (!old->old) {
			/*
			 * 3GPP TS 24.229 5.2.2.2: the old set is kept, with its
			 * SIP level lifetime reduced to 64*T1.
			 * SPEC-DEVIATION: TS 24.229 5.2.2.2, TS 33.203 7.4.2a -- the
			 * new set is taken into use (and the lifetime of the old
			 * set reduced) with the 200 OK already, not with the first
			 * message the UE sends over the new set or when the old
			 * set is about to expire: only REGISTER requests are
			 * matched to a set on reception
			 */
			ipsec_ctx_add_tmp(old, IPSEC_OLD_SA_LIFETIME);
		}
		old->old = 1;
	}
	lock_release(&user->lock);
	if (sock)
		ipsec_sock_close(sock);
	return ret;
}

/* drops the registration reference, if it is still held */
void ipsec_ctx_unregister(struct ipsec_ctx *ctx)
{
	int drop;

	lock_get(&ctx->lock);
	drop = ctx->reg_ref;
	ctx->reg_ref = 0;
	lock_release(&ctx->lock);
	if (drop)
		ipsec_ctx_release(ctx);
}

/* unlinks the ctx from its user and drops the user reference of the link */
void ipsec_ctx_release_user(struct ipsec_ctx *ctx)
{
	struct ipsec_user *user = ctx->user;

	lock_get(&user->lock);
	LM_DBG("User %.*s has %d contexts, releasing %p\n",
			user->impi.len, user->impi.s, list_size(&user->sas), ctx);
	list_del(&ctx->list);
	INIT_LIST_HEAD(&ctx->list);
	ctx->user = NULL; /* avoid double release */
	lock_release(&user->lock);
	ipsec_release_user(user);
}

/*
 * XFRM reconciliation: kernel SAs tagged with IPSEC_USER_SELECTOR that no
 * live TMP/OK ctx claims are orphans (TMP expiry leak before the refcount
 * fix, leftovers after a hostNetwork restart, or a failed create that left
 * a selector behind). Delete them after reconcile_grace seconds.
 */
struct ipsec_xfrm_orphan {
	unsigned int spi;
	int family;
	xfrm_address_t daddr;
	xfrm_address_t saddr;
	struct xfrm_selector sel;
	struct ipsec_xfrm_orphan *next;
};

static void xfrm_addr_to_ip(int family, const xfrm_address_t *a, struct ip_addr *ip)
{
	memset(ip, 0, sizeof(*ip));
	if (family == AF_INET) {
		ip->af = AF_INET;
		ip->len = 4;
		memcpy(&ip->u.addr, &a->a4, 4);
	} else {
		ip->af = AF_INET6;
		ip->len = 16;
		memcpy(&ip->u.addr, &a->a6, 16);
	}
}

static int ipsec_xfrm_dump_cb(const struct nlmsghdr *nlh, void *data)
{
	struct xfrm_usersa_info *sa;
	struct ipsec_xfrm_orphan **head = data;
	struct ipsec_xfrm_orphan *o;
	struct ip_addr src, dst;
	unsigned short sport, dport;
	time_t now, age;

	if (nlh->nlmsg_type != XFRM_MSG_NEWSA)
		return MNL_CB_OK;
	sa = mnl_nlmsg_get_payload(nlh);
	if (sa->sel.user != IPSEC_USER_SELECTOR)
		return MNL_CB_OK;

	now = time(NULL);
	age = (sa->curlft.add_time && now > (time_t)sa->curlft.add_time) ?
		(now - (time_t)sa->curlft.add_time) : (time_t)ipsec_reconcile_grace + 1;
	if (age < (time_t)ipsec_reconcile_grace)
		return MNL_CB_OK;

	xfrm_addr_to_ip(sa->sel.family, &sa->sel.saddr, &src);
	xfrm_addr_to_ip(sa->sel.family, &sa->sel.daddr, &dst);
	sport = ntohs(sa->sel.sport);
	dport = ntohs(sa->sel.dport);
	if (ipsec_users_claim_port(&src, sport) || ipsec_users_claim_port(&src, dport) ||
			ipsec_users_claim_port(&dst, sport) || ipsec_users_claim_port(&dst, dport))
		return MNL_CB_OK;

	o = pkg_malloc(sizeof(*o));
	if (!o) {
		LM_ERR("oom for XFRM orphan\n");
		return MNL_CB_OK;
	}
	memset(o, 0, sizeof(*o));
	o->spi = ntohl(sa->id.spi);
	o->family = sa->sel.family;
	o->daddr = sa->id.daddr;
	o->saddr = sa->saddr;
	o->sel = sa->sel;
	o->next = *head;
	*head = o;
	return MNL_CB_OK;
}

static void ipsec_xfrm_del_orphan(struct ipsec_socket *sock, struct ipsec_xfrm_orphan *o)
{
	char buf[MNL_SOCKET_BUFFER_SIZE];
	struct nlmsghdr *nlh;
	struct xfrm_usersa_id *sa_id;
	struct xfrm_userpolicy_id *policy_id;
	int dir;

	memset(buf, 0, sizeof buf);
	nlh = mnl_nlmsg_put_header(buf);
	if (nlh) {
		nlh->nlmsg_flags = NLM_F_REQUEST;
		nlh->nlmsg_type = XFRM_MSG_DELSA;
		nlh->nlmsg_seq = ++ipsec_seq;
		sa_id = mnl_nlmsg_put_extra_header(nlh, sizeof(*sa_id));
		if (sa_id) {
			sa_id->spi = htonl(o->spi);
			sa_id->proto = IPPROTO_ESP;
			sa_id->family = o->family;
			sa_id->daddr = o->daddr;
			mnl_attr_put(nlh, XFRMA_SRCADDR, sizeof(o->saddr), &o->saddr);
			if (mnl_socket_sendto(sock, nlh, nlh->nlmsg_len) < 0)
				LM_ERR("reconcile DELSA spi=%u: %s\n", o->spi, strerror(errno));
		}
	}

	for (dir = XFRM_POLICY_IN; dir <= XFRM_POLICY_OUT; dir++) {
		memset(buf, 0, sizeof buf);
		nlh = mnl_nlmsg_put_header(buf);
		if (!nlh)
			continue;
		nlh->nlmsg_flags = NLM_F_REQUEST;
		nlh->nlmsg_type = XFRM_MSG_DELPOLICY;
		nlh->nlmsg_seq = ++ipsec_seq;
		policy_id = mnl_nlmsg_put_extra_header(nlh, sizeof(*policy_id));
		if (!policy_id)
			continue;
		policy_id->dir = dir;
		policy_id->sel = o->sel;
		mnl_socket_sendto(sock, nlh, nlh->nlmsg_len);
	}
	LM_INFO("reconciled orphan XFRM SA spi=%u\n", o->spi);
}

static void ipsec_xfrm_reconcile(void)
{
	char buf[MNL_SOCKET_BUFFER_SIZE];
	struct nlmsghdr *nlh;
	struct ipsec_socket *sock;
	struct ipsec_xfrm_orphan *head = NULL, *o, *next;
	int ret, deleted = 0;

	sock = ipsec_sock_new();
	if (!sock)
		return;

	memset(buf, 0, sizeof buf);
	nlh = mnl_nlmsg_put_header(buf);
	if (!nlh)
		goto out;
	nlh->nlmsg_type = XFRM_MSG_GETSA;
	nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
	nlh->nlmsg_seq = ++ipsec_seq;
	if (mnl_socket_sendto(sock, nlh, nlh->nlmsg_len) < 0) {
		LM_ERR("reconcile GETSA dump: %s\n", strerror(errno));
		goto out;
	}
	ret = mnl_socket_recvfrom(sock, buf, sizeof buf);
	while (ret > 0) {
		ret = mnl_cb_run(buf, ret, 0, 0, ipsec_xfrm_dump_cb, &head);
		if (ret <= MNL_CB_STOP)
			break;
		ret = mnl_socket_recvfrom(sock, buf, sizeof buf);
	}

	for (o = head; o; o = next) {
		next = o->next;
		ipsec_xfrm_del_orphan(sock, o);
		deleted++;
		pkg_free(o);
	}
	if (deleted)
		LM_INFO("XFRM reconcile removed %d orphan SA(s)\n", deleted);
out:
	ipsec_sock_close(sock);
}

#define IPSEC_TIMER_BATCH 256

void ipsec_ctx_timer(unsigned int ticks, void* param)
{
	struct list_head *it, *safe;
	struct ipsec_ctx *batch[IPSEC_TIMER_BATCH];
	struct ipsec_ctx *ctx;
	struct ipsec_socket *sock;
	int n, i;

	do {
		/*
		 * Unlink the expired sets, a batch at a time; their list
		 * references pass to the batch.  The lifetimes differ, so the
		 * list is not ordered.
		 */
		n = 0;
		lock_get(ipsec_tmp_contexts_lock);
		list_for_each_safe(it, safe, ipsec_tmp_contexts) {
			ctx = list_entry(it, struct ipsec_ctx, tmp);
			if (ticks < ctx->expire)
				continue;
			list_del(&ctx->tmp);
			INIT_LIST_HEAD(&ctx->tmp);
			batch[n++] = ctx;
			if (n == IPSEC_TIMER_BATCH)
				break;
		}
		lock_release(ipsec_tmp_contexts_lock);

		sock = n?ipsec_sock_new():NULL;
		for (i = 0; i < n; i++) {
			ctx = batch[i];
			if (ctx->state == IPSEC_STATE_TMP && !ctx->sa_removed)
				LM_ERR("IPSec ctx %p expired\n", ctx);
			/*
			 * The lifetime of the set is over (3GPP TS 24.229 5.2.2.2:
			 * "the P-CSCF shall delete any security association from
			 * the IPsec database when their SIP level lifetime
			 * expires"): remove the SAs now, even if a transaction
			 * still holds the ctx.
			 */
			if (sock)
				ipsec_sa_rm_all(sock, ctx);
			ipsec_ctx_unregister(ctx);
			ipsec_ctx_release(ctx); /* reference of the lifetime list */
		}
		if (sock)
			ipsec_sock_close(sock);
	} while (n == IPSEC_TIMER_BATCH);

	if (ipsec_reconcile_interval &&
			++ipsec_reconcile_tick >= ipsec_reconcile_interval) {
		ipsec_reconcile_tick = 0;
		ipsec_xfrm_reconcile();
	}
}

void ipsec_ctx_extend_tmp(struct ipsec_ctx *ctx)
{
	lock_get(ipsec_tmp_contexts_lock);
	lock_get(&ctx->lock);
	/* a set the timer is expiring right now is not listed any more */
	if (ctx->state == IPSEC_STATE_TMP && !ctx->sa_removed &&
			!list_empty(&ctx->tmp))
		ctx->expire = get_ticks() + ipsec_tmp_timeout;
	lock_release(&ctx->lock);
	lock_release(ipsec_tmp_contexts_lock);
}

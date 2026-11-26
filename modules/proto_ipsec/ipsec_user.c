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

#include "ipsec_user.h"
#include "../../lib/list.h"
#include "../../locking.h"
#include "../../hash_func.h"

struct ipsec_map_node {
	unsigned char n;
	unsigned int size;
	union {
		struct ipsec_map_node *nodes;
		struct ipsec_user_table *users;
	};
};

/*
 * The users behind one address, hashed by IMPI.  Most addresses have one
 * user, an address of a NAT or of a load generator has thousands: the table
 * starts with one bucket and grows with the number of IMPIs.
 */
struct ipsec_user_table {
	unsigned int size;  /* buckets, a power of two */
	unsigned int count; /* IMPIs */
	struct list_head buckets[0];
};
#define IPSEC_USER_TABLE_LOAD 4
#define IPSEC_USER_TABLE_GROW 4

struct ipsec_map {
	unsigned int size;
	struct ipsec_map_node *nodes;
	gen_lock_t lock;
};

struct ipsec_user_impi {
	str impi;
	unsigned int hash;
	struct list_head list;
	struct list_head users;
	char _buf[0];
};

struct ipsec_map *ipsec_map_ipv4;
struct ipsec_map *ipsec_map_ipv6;

static struct ipsec_map *ipsec_map_create(void)
{
	struct ipsec_map *map = shm_malloc(sizeof *map);
	if (!map)
		return NULL;
	memset(map, 0, sizeof *map);
	if (!lock_init(&map->lock)) {
		shm_free(map);
		return NULL;
	}
	return map;
}

static int ipsec_remove_node(struct ip_addr *ip, int level,
		struct ipsec_map_node **nodes_list, unsigned int *size);

static void _ipsec_map_destroy(struct ipsec_map *map)
{
	/* TODO: remove entries */
	lock_destroy(&map->lock);
	shm_free(map);
}

int ipsec_map_init(void)
{
	ipsec_map_ipv4 = ipsec_map_create();
	if (!ipsec_map_ipv4) {
		LM_ERR("could not initialize IPv4 map\n");
		return -1;
	}
	ipsec_map_ipv6 = ipsec_map_create();
	if (!ipsec_map_ipv6) {
		LM_ERR("could not initialize IPv6 map\n");
		return -1;
	}
	return 0;
}

void ipsec_map_destroy(void)
{
	if (ipsec_map_ipv4)
		_ipsec_map_destroy(ipsec_map_ipv4);
	if (ipsec_map_ipv6)
		_ipsec_map_destroy(ipsec_map_ipv6);
}

static void ipsec_dump_users_rec(struct ipsec_map_node *nodes, int size, int levels)
{
	int n;
	unsigned int b;
	struct list_head *it, *it2;
	struct ipsec_user_impi *impi;
	struct ipsec_user *user;

	for (n = 0; n < size; n++) {
		if (levels > 1) {
			ipsec_dump_users_rec(nodes[n].nodes, nodes[n].size, levels - 1);
			continue;
		}
		if (!nodes[n].users)
			continue;
		for (b = 0; b < nodes[n].users->size; b++) {
			list_for_each(it, &nodes[n].users->buckets[b]) {
				impi = list_entry(it, struct ipsec_user_impi, list);
				list_for_each(it2, &impi->users) {
					user = list_entry(it2, struct ipsec_user, list);
					LM_DBG("print %s - %.*s/%.*s\n", ip_addr2a(&user->ip),
						user->impi.len, user->impi.s, user->impu.len, user->impu.s);
				}
			}
		}
	}
}

static void ipsec_dump_users(struct ipsec_map *map)
{
	/* walks every user of the map - only worth it when it gets printed */
	if (!is_printable(L_DBG))
		return;
	lock_get(&map->lock);
	ipsec_dump_users_rec(map->nodes, map->size, (map == ipsec_map_ipv4?4:16));
	lock_release(&map->lock);
}

static struct ipsec_map_node *ipsec_get_node(struct ip_addr *ip, int level,
		struct ipsec_map_node **nodes_list, unsigned int *size)
{
	int i;
	unsigned char n;
	struct ipsec_map_node *nodes = *nodes_list;
	int leaf = (ip->len - 1 == level);
	n = ip->u.addr[level];

	/* first, check if there is an already existing node for this level */
	if (nodes && *size) {
		for (i = 0; i < *size; i++) {
			if (nodes[i].n == n) {
				if (leaf)
					return &nodes[i];
				else
					return ipsec_get_node(ip, level + 1,
							&nodes[i].nodes, &nodes[i].size);
			} else if (nodes[i].n > n) {
				break;
			}
		}
	} else {
		i = 0;
	}
	/* node does not exist - we need to add it */
	nodes = shm_realloc(nodes, ((*size) + 1) * sizeof(*nodes));
	if (!nodes) {
		LM_ERR("oom for nodes\n");
		return NULL;
	}
	/* make room for the new element */
	memmove(nodes + i + 1, nodes + i, ((*size) - i) * sizeof (*nodes));
	*nodes_list = nodes;
	(*size)++;
	memset(&nodes[i], 0, sizeof *nodes);
	nodes[i].n = n;
	if (leaf)
		return &nodes[i];
	else
		return ipsec_get_node(ip, level + 1, &nodes[i].nodes, &nodes[i].size);
}

static struct ipsec_user_table *ipsec_user_table_new(unsigned int size)
{
	unsigned int b;
	struct ipsec_user_table *table;

	table = shm_malloc(sizeof(*table) + size * sizeof(table->buckets[0]));
	if (!table)
		return NULL;
	table->size = size;
	table->count = 0;
	for (b = 0; b < size; b++)
		INIT_LIST_HEAD(&table->buckets[b]);
	return table;
}

/* returns the table to use from now on: the old one if there is no memory */
static struct ipsec_user_table *ipsec_user_table_grow(struct ipsec_user_table *table)
{
	unsigned int b;
	struct list_head *it, *safe;
	struct ipsec_user_impi *uimpi;
	struct ipsec_user_table *grown;

	grown = ipsec_user_table_new(table->size * IPSEC_USER_TABLE_GROW);
	if (!grown)
		return table;
	for (b = 0; b < table->size; b++) {
		list_for_each_safe(it, safe, &table->buckets[b]) {
			uimpi = list_entry(it, struct ipsec_user_impi, list);
			list_del(&uimpi->list);
			list_add(&uimpi->list,
					&grown->buckets[uimpi->hash & (grown->size - 1)]);
		}
	}
	grown->count = table->count;
	shm_free(table);
	return grown;
}

static struct ipsec_user_impi *ipsec_find_user_impi(struct ipsec_user_table *table,
		str *impi, unsigned int hash)
{
	struct ipsec_user_impi *uimpi;
	struct list_head *it;
	list_for_each(it, &table->buckets[hash & (table->size - 1)]) {
		uimpi = list_entry(it, struct ipsec_user_impi, list);
		if (uimpi->hash == hash && str_match(&uimpi->impi, impi))
			return uimpi;
	}
	return NULL;
}

struct ipsec_user *ipsec_find_user_in_impi(struct list_head *list, str *impu)
{
	struct ipsec_user *user;
	struct list_head *it;
	list_for_each(it, list) {
		user = list_entry(it, struct ipsec_user, list);
		if (str_match(&user->impu, impu))
			return user;
	}
	return NULL;
}

static struct ipsec_user *ipsec_get_create_user(struct ipsec_map_node *node,
		struct ip_addr *ip, str *impi, str *impu)
{
	struct ipsec_user_impi *uimpi = NULL;
	struct ipsec_user *user;
	unsigned int hash = core_hash(impi, NULL, 0);
	if (node->users) {
		uimpi = ipsec_find_user_impi(node->users, impi, hash);
		if (uimpi) {
			user = ipsec_find_user_in_impi(&uimpi->users, impu);
			if (user) {
				lock_get(&user->lock);
				user->ref++;
				lock_release(&user->lock);
				return user;
			}
		}
	} else {
		node->users = ipsec_user_table_new(1);
		if (!node->users)
			return NULL;
	}
	if (!uimpi) {
		uimpi = shm_malloc(sizeof(*uimpi) + impi->len);
		if (!uimpi)
			goto error;
		memset(uimpi, 0, sizeof *uimpi);
		uimpi->impi.s = uimpi->_buf;
		memcpy(uimpi->impi.s, impi->s, impi->len);
		uimpi->impi.len = impi->len;
		uimpi->hash = hash;
		INIT_LIST_HEAD(&uimpi->users);
		if (node->users->count >= node->users->size * IPSEC_USER_TABLE_LOAD)
			node->users = ipsec_user_table_grow(node->users);
		list_add(&uimpi->list,
				&node->users->buckets[hash & (node->users->size - 1)]);
		node->users->count++;
	}
	user = shm_malloc(sizeof(*user) + impu->len);
	if (!user) {
		LM_ERR("oom for creating a new user\n");
		goto error;
	}
	memset(user, 0, sizeof *user);
	user->impi = uimpi->impi;
	user->impu.s = user->_buf;
	user->impu.len = impu->len;
	memcpy(user->impu.s, impu->s, impu->len);
	memcpy(&user->ip, ip, sizeof *ip);
	lock_init(&user->lock);
	user->ref = 1;
	INIT_LIST_HEAD(&user->list);
	INIT_LIST_HEAD(&user->sas);
	list_add(&user->list, &uimpi->users);
	return user;
error:
	/* no uimpi if its allocation failed */
	if (uimpi && list_empty(&uimpi->users)) {
		list_del(&uimpi->list);
		node->users->count--;
		shm_free(uimpi);
	}
	if (node->users->count == 0) {
		shm_free(node->users);
		node->users = NULL;
	}
	return NULL;
}

struct ipsec_user *ipsec_get_user(struct ip_addr *ip, str *impi, str *impu)
{
	struct ipsec_map *map;
	struct ipsec_map_node *node;
	struct ipsec_user *user = NULL;

	if (ip->af == AF_INET)
		map = ipsec_map_ipv4;
	else
		map = ipsec_map_ipv6;
	lock_get(&map->lock);
	node = ipsec_get_node(ip, 0, &map->nodes, &map->size);
	if (node) {
		user = ipsec_get_create_user(node, ip, impi, impu);
		if (!user) {
			LM_ERR("could not create user!\n");
			ipsec_remove_node(ip, 0, &map->nodes, &map->size);
		}
	}
	lock_release(&map->lock);
	ipsec_dump_users(map);
	return user;
}

static struct ipsec_map_node *ipsec_find_node(struct ip_addr *ip, int level,
		struct ipsec_map_node *nodes, unsigned int size)
{
	int n;
	for (n = 0; n < size; n++) {
		if (nodes[n].n == ip->u.addr[level]) {
			if (ip->len - 1 == level)
				return &nodes[n];
			else
				return ipsec_find_node(ip, level + 1, nodes[n].nodes, nodes[n].size);
		}
	}
	return NULL;
}

struct ipsec_user *ipsec_find_user(struct ip_addr *ip, str *impi, str *impu)
{
	struct ipsec_map *map;
	struct ipsec_map_node *node;
	struct ipsec_user_impi *uimpi;
	struct ipsec_user *user = NULL;

	if (ip->af == AF_INET)
		map = ipsec_map_ipv4;
	else
		map = ipsec_map_ipv6;
	lock_get(&map->lock);
	node = ipsec_find_node(ip, 0, map->nodes, map->size);
	if (node && node->users) {
		uimpi = ipsec_find_user_impi(node->users, impi,
				core_hash(impi, NULL, 0));
		if (uimpi) {
			user = ipsec_find_user_in_impi(&uimpi->users, impu);
			if (user) {
				lock_get(&user->lock);
				user->ref++;
				lock_release(&user->lock);
			}
		}
	} else {
		user = NULL;
	}
	lock_release(&map->lock);
	ipsec_dump_users(map);
	return user;
}

/* removes the user from the map, which has to be locked */
static void ipsec_unlink_user(struct ipsec_map *map, struct ipsec_user *user)
{
	struct ipsec_map_node *node;
	struct ipsec_user_impi *uimpi;

	node = ipsec_find_node(&user->ip, 0, map->nodes, map->size);
	if (node && node->users) {
		uimpi = ipsec_find_user_impi(node->users, &user->impi,
				core_hash(&user->impi, NULL, 0));
		if (uimpi) {
			list_del(&user->list);
			if (list_empty(&uimpi->users)) {
				list_del(&uimpi->list);
				node->users->count--;
				shm_free(uimpi);
				if (node->users->count == 0) {
					shm_free(node->users);
					node->users = NULL;
				}
			}
		} else {
			LM_ERR("user impi %.*s not found!\n", user->impi.len, user->impi.s);
		}
	} else {
		LM_ERR("user not found!\n");
	}
	ipsec_remove_node(&user->ip, 0, &map->nodes, &map->size);
}

/*
 * A user is referenced by each ctx linked into user->sas and by whoever got
 * it from ipsec_get_user()/ipsec_find_user().  The last reference is dropped
 * with the map locked: the lookups take theirs under the same lock, so they
 * never return a user that is being destroyed.
 */
static void ipsec_release_user_count(struct ipsec_user *user, int count)
{
	struct ipsec_map *map;
	int free = 0;

	if (user->ip.af == AF_INET)
		map = ipsec_map_ipv4;
	else
		map = ipsec_map_ipv6;
	lock_get(&map->lock);
	lock_get(&user->lock);
	if (user->ref < count) {
		LM_BUG("invalid unref of %d with %d for user %p\n", user->ref, count, user);
	} else {
		user->ref -= count;
		free = (user->ref == 0);
	}
	lock_release(&user->lock);
	if (free)
		ipsec_unlink_user(map, user);
	lock_release(&map->lock);
	if (free) {
		lock_destroy(&user->lock);
		shm_free(user);
	}
}

void ipsec_release_user(struct ipsec_user *user)
{
	ipsec_release_user_count(user, 1);
}

static int ipsec_remove_node(struct ip_addr *ip, int level,
		struct ipsec_map_node **nodes_list, unsigned int *size)
{
	int n;
	struct ipsec_map_node *nodes;
	int remove = 0;
	int leaf = (ip->len - 1 == level);

	nodes = *nodes_list;
	for (n = 0; n < *size; n++) {
		if (nodes[n].n == ip->u.addr[level]) {
			if (leaf) {
				remove = (nodes[n].users == NULL);
			} else {
				/* an inner node goes only when its last child is gone */
				ipsec_remove_node(ip, level + 1, &nodes[n].nodes, &nodes[n].size);
				remove = (nodes[n].size == 0);
			}
			break;
		}
	}
	if (remove) {
		/* user found - remove the node */
		if (*size == 1) {
			shm_free(nodes);
			*nodes_list = NULL;
			*size = 0;
		} else {
			memmove(&nodes[n], &nodes[n + 1], ((*size) - n - 1) * sizeof (*nodes));
			(*size)--;
			*nodes_list = nodes;
		}
	}
	return remove;
}

/*
 * Returns the (referenced) set a protected message was received over.  Only
 * sets that have their SAs in the kernel are considered - a UE may reuse its
 * ports for a later set, and the kernel holds one policy per selector, so
 * at most one of them matches.
 */
struct ipsec_ctx *ipsec_get_ctx_user(struct ipsec_user *user, struct receive_info *ri)
{
	struct list_head *it;
	struct ipsec_ctx *ctx = NULL;
	lock_get(&user->lock);
	list_for_each_prev(it, &user->sas) {
		ctx = list_entry(it, struct ipsec_ctx, list);
		LM_DBG("checking ctx %p (state %d) for src_port %u, dst_port %u\n", ctx, ctx->state, ri->src_port, ri->dst_port);
		if (IPSEC_CTX_LIVE(ctx) && ctx->ue.port_c == ri->src_port &&
				ctx->me.port_s == ri->dst_port && ipsec_ctx_tryref(ctx))
			break;
		ctx = NULL;
	}
	lock_release(&user->lock);
	return ctx;
}

/*
 * Returns the (referenced) set to be used for sending to a port of the UE:
 * the established set that is in use, else an old set that still lives,
 * else a temporary one; among equals the most recent one.
 */
struct ipsec_ctx *ipsec_get_ctx_user_port(struct ipsec_user *user, unsigned short port)
{
	struct list_head *it;
	struct ipsec_ctx *ctx, *best = NULL;
	int rank, best_rank = 0;
	lock_get(&user->lock);
	list_for_each_prev(it, &user->sas) {
		ctx = list_entry(it, struct ipsec_ctx, list);
		LM_DBG("checking ctx %p for port %u (ue.port_s=%u ue.port_c=%u state=%d)\n",
				ctx, port, ctx->ue.port_s, ctx->ue.port_c, ctx->state);
		if (!IPSEC_CTX_LIVE(ctx) ||
				(ctx->ue.port_s != port && ctx->ue.port_c != port))
			continue;
		rank = (ctx->state == IPSEC_STATE_TMP?1:(ctx->old?2:3));
		if (rank > best_rank) {
			best = ctx;
			best_rank = rank;
		}
	}
	if (best && !ipsec_ctx_tryref(best))
		best = NULL;
	lock_release(&user->lock);
	return best;
}

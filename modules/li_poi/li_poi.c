/*
 * Lawful interception: point of interception (target match).
 *
 * The module holds the task table of the pod (digests of target
 * identifiers, see li_table.h) and tells the script whether a request
 * belongs to an intercepted communication. The script then copies the
 * messages of the transaction to the X2/X3 forwarder with tracer:
 *
 *   if (li_match($var(li)))
 *       trace("li_trace", "t", "sip", , , $var(li));
 *
 * Nothing here logs, counts per target or exports what it matched: who is
 * intercepted must not be visible to those who operate the platform.
 * There are no MI commands and no statistics on purpose.
 *
 * Target match as in 3GPP TS 33.128 clause 7.12.2.8.2: From and
 * P-Asserted-Identity (the target is the sender), Request-URI and To (the
 * target is the receiver). A task for an IMPI or an IMEI matches through
 * the registration: the user name of the Authorization header and the
 * +sip.instance of the Contact of a REGISTER, and for every other request
 * the IMPI and the instances stored with the usrloc record of the IMPU
 * ('usrloc_domain'). An INVITE that matched is remembered by its
 * Call-ID, so that later requests of the dialog are recognised when their
 * headers no longer name the target (e.g. an anonymous From). The memory
 * holds a salted digest of the Call-ID, not the Call-ID, and with
 * 'cluster_id' set it is shared with the other nodes of the cluster, because
 * a later request of the dialog can arrive at any of them.
 */

#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>

#include "../../sr_module.h"
#include "../../dprint.h"
#include "../../mem/mem.h"
#include "../../mem/shm_mem.h"
#include "../../locking.h"
#include "../../rw_locking.h"
#include "../../timer.h"
#include "../../pvar.h"
#include "../../sha256.h"
#include "../../hash_func.h"
#include "../../parser/msg_parser.h"
#include "../../parser/parse_from.h"
#include "../../parser/parse_to.h"
#include "../../parser/parse_pai.h"
#include "../../parser/digest/digest.h"
#include "../../parser/contact/parse_contact.h"
#include "../usrloc/usrloc.h"
#include "../../bin_interface.h"
#include "../clusterer/api.h"

#include "li_identity.h"
#include "li_table.h"

/* tasks one message can belong to */
#define LI_MAX_XIDS 8
#define LI_CALL_BUCKETS 1024
#define LI_MAX_IDENTITY 512
#define LI_RECONNECT 2
/* a longer Call-ID is cut to this length before it is hashed */
#define LI_MAX_CALLID 1024

/* seconds a call stays known after its BYE (retransmissions, and the passes
 * of the BYE through the application servers) */
#define LI_END_TTL 64

#define LI_BIN_VERSION 2
#define LI_REPL_CALL 1

struct li_shared {
	rw_lock_t *lock;
	unsigned int version;
	unsigned char salt[LI_MAX_SALT];
	int salt_len;
	/* read without the lock for the "nothing to do" test */
	unsigned int count;
	/* entries for an IMPI or an IMEI */
	unsigned int bound;
	struct li_entry *entries;
};

#define LI_SIDE_FROM 1
#define LI_SIDE_TO 2

struct li_xids {
	int n;
	unsigned char xid[LI_MAX_XIDS][LI_XID_LEN];
	/* per task: on which side of this request its target was found, and
	 * the direction of the session as its target sees it */
	unsigned char side[LI_MAX_XIDS];
	char dir[LI_MAX_XIDS];
};

struct li_call {
	struct li_call *next;
	unsigned int expires;
	struct li_xids xids;
	unsigned char key[LI_DIGEST_LEN];
};

static struct li_shared *tab;
static struct li_call **calls;
static gen_lock_set_t *calls_lock;
/* remembered calls; read without a lock for the "nothing to do" test */
static int *calls_active;

static str li_socket = {0, 0};
static int li_call_ttl = 7200;
static int li_cluster_id = 0;
static char *li_usrloc_domain = NULL;
static str li_impi_key = str_init("impi");

static usrloc_api_t ul;
static udomain_t *li_domain;

static str li_repl_cap = str_init("li-poi-call-repl");
static struct clusterer_binds c_api;

static int mod_init(void);
static void mod_destroy(void);
static void li_table_proc(int rank);
static int w_li_match(struct sip_msg *msg, pv_spec_t *out, str *caller,
	str *called);
static int li_init_cluster(void);

static const cmd_export_t cmds[] = {
	{"li_match", (cmd_function)w_li_match, {
		{CMD_PARAM_VAR, 0, 0},
		{CMD_PARAM_STR | CMD_PARAM_OPT, 0, 0},
		{CMD_PARAM_STR | CMD_PARAM_OPT, 0, 0}, {0, 0, 0}}, REQUEST_ROUTE},
	{0, 0, {{0, 0, 0}}, 0}
};

static const param_export_t params[] = {
	{"socket",   STR_PARAM, &li_socket.s},
	{"call_ttl", INT_PARAM, &li_call_ttl},
	{"cluster_id", INT_PARAM, &li_cluster_id},
	{"usrloc_domain", STR_PARAM, &li_usrloc_domain},
	{"impi_key", STR_PARAM, &li_impi_key.s},
	{0, 0, 0}
};

static module_dependency_t *get_deps_usrloc(const param_export_t *param)
{
	char *domain = *(char **)param->param_pointer;

	if (!domain || !*domain)
		return NULL;
	return alloc_module_dep(MOD_TYPE_DEFAULT, "usrloc", DEP_ABORT);
}

static const dep_export_t deps = {
	{ /* OpenSIPS module dependencies */
		{ MOD_TYPE_NULL, NULL, 0 },
	},
	{ /* modparam dependencies */
		{ "cluster_id", get_deps_clusterer },
		{ "usrloc_domain", get_deps_usrloc },
		{ NULL, NULL },
	},
};

static const proc_export_t procs[] = {
	{"LI table", 0, 0, li_table_proc, 1, 0},
	{0, 0, 0, 0, 0, 0}
};

struct module_exports exports = {
	"li_poi",        /* module name */
	MOD_TYPE_DEFAULT,/* class of this module */
	MODULE_VERSION,
	DEFAULT_DLFLAGS, /* dlopen flags */
	0,               /* load function */
	&deps,           /* OpenSIPS module dependencies */
	cmds,            /* exported functions */
	0,               /* exported async functions */
	params,          /* module parameters */
	0,               /* exported statistics */
	0,               /* exported MI functions */
	0,               /* exported pseudo-variables */
	0,               /* exported transformations */
	procs,           /* extra processes */
	0,               /* module pre-initialization function */
	mod_init,        /* module initialization function */
	0,               /* response function */
	mod_destroy,     /* destroy function */
	0,               /* per-child init function */
	0                /* reload confirm function */
};

static int mod_init(void)
{
	if (!li_socket.s || !*li_socket.s) {
		LM_ERR("the 'socket' parameter is required\n");
		return -1;
	}
	li_socket.len = strlen(li_socket.s);
	if (li_socket.len >= (int)sizeof(((struct sockaddr_un *)0)->sun_path)) {
		LM_ERR("the 'socket' path is too long\n");
		return -1;
	}

	tab = shm_malloc(sizeof *tab);
	calls = shm_malloc(LI_CALL_BUCKETS * sizeof *calls);
	calls_active = shm_malloc(sizeof *calls_active);
	if (!tab || !calls || !calls_active) {
		LM_ERR("no more shm memory\n");
		return -1;
	}
	memset(tab, 0, sizeof *tab);
	memset(calls, 0, LI_CALL_BUCKETS * sizeof *calls);
	*calls_active = 0;

	if (!(tab->lock = lock_init_rw())) {
		LM_ERR("failed to create the table lock\n");
		return -1;
	}
	if (!(calls_lock = lock_set_alloc(LI_CALL_BUCKETS)) ||
			!lock_set_init(calls_lock)) {
		LM_ERR("failed to create the call locks\n");
		return -1;
	}
	if (li_cluster_id > 0 && li_init_cluster() < 0)
		return -1;
	li_impi_key.len = strlen(li_impi_key.s);
	if (li_usrloc_domain && *li_usrloc_domain) {
		if (load_ul_api(&ul) < 0) {
			LM_ERR("failed to find the usrloc API\n");
			return -1;
		}
		if (ul.register_udomain(li_usrloc_domain, &li_domain) < 0) {
			LM_ERR("failed to register the usrloc domain %s\n",
				li_usrloc_domain);
			return -1;
		}
	}
	return 0;
}

static void mod_destroy(void)
{
	/* shm memory goes with the process group */
}

/* ------------------------------------------------------------------------
 * The table receiver process
 * ---------------------------------------------------------------------- */

static int read_all(int fd, unsigned char *buf, unsigned int len)
{
	ssize_t n;

	while (len > 0) {
		n = read(fd, buf, len);
		if (n == 0)
			return -1;
		if (n < 0) {
			if (errno == EINTR)
				continue;
			return -1;
		}
		buf += n;
		len -= n;
	}
	return 0;
}

static int apply_table(const struct li_parsed *parsed)
{
	struct li_entry *fresh = NULL, *old;
	unsigned int i, bound = 0;

	if (parsed->count) {
		fresh = shm_malloc(parsed->count * sizeof *fresh);
		if (!fresh) {
			LM_ERR("no more shm memory for the task table\n");
			return -1;
		}
		for (i = 0; i < parsed->count; i++) {
			li_parsed_entry(parsed, i, &fresh[i]);
			if (fresh[i].cls != LI_CLASS_IMPU)
				bound++;
		}
	}

	lock_start_write(tab->lock);
	old = tab->entries;
	tab->entries = fresh;
	tab->count = parsed->count;
	tab->bound = bound;
	tab->version = parsed->version;
	tab->salt_len = parsed->salt_len;
	memcpy(tab->salt, parsed->salt, parsed->salt_len);
	lock_stop_write(tab->lock);

	if (old)
		shm_free(old);
	return 0;
}

/* One connection to the forwarder; returns when it ends. */
static void receive_tables(int fd)
{
	unsigned char head[8], *body;
	unsigned int len;
	struct li_parsed parsed;

	for (;;) {
		if (read_all(fd, head, sizeof head) < 0)
			return;
		len = ((unsigned int)head[4] << 24) | ((unsigned int)head[5] << 16) |
			((unsigned int)head[6] << 8) | head[7];
		if (memcmp(head, "LIT1", 4) != 0 || len > LI_MAX_BODY) {
			LM_ERR("unexpected data from the forwarder\n");
			return;
		}
		body = pkg_malloc(len ? len : 1);
		if (!body) {
			LM_ERR("no more pkg memory\n");
			return;
		}
		if (read_all(fd, body, len) < 0) {
			pkg_free(body);
			return;
		}
		if (li_parse_table(body, len, &parsed) < 0) {
			LM_ERR("invalid task table from the forwarder\n");
			pkg_free(body);
			return;
		}
		if (apply_table(&parsed) == 0)
			LM_DBG("task table version %u applied\n", parsed.version);
		pkg_free(body);
	}
}

static void li_table_proc(int rank)
{
	struct sockaddr_un addr;
	int fd, connected = 0;

	memset(&addr, 0, sizeof addr);
	addr.sun_family = AF_UNIX;
	memcpy(addr.sun_path, li_socket.s, li_socket.len);

	/* While the forwarder is away the last table stays in use. */
	for (;;) {
		fd = socket(AF_UNIX, SOCK_STREAM, 0);
		if (fd < 0) {
			LM_ERR("socket: %s\n", strerror(errno));
		} else if (connect(fd, (struct sockaddr *)&addr, sizeof addr) < 0) {
			if (connected)
				LM_WARN("forwarder not reachable on %s: %s\n",
					li_socket.s, strerror(errno));
			connected = 0;
			close(fd);
		} else {
			LM_INFO("connected to the forwarder on %s\n", li_socket.s);
			connected = 1;
			receive_tables(fd);
			LM_WARN("connection to the forwarder lost\n");
			close(fd);
		}
		sleep(LI_RECONNECT);
	}
}

/* ------------------------------------------------------------------------
 * Target match
 * ---------------------------------------------------------------------- */

/* Adds a task, or a side to a task that is in the set. Returns its index,
 * -1 if the set is full. */
static int add_xid(struct li_xids *set, const unsigned char *xid, int side)
{
	int i;

	for (i = 0; i < set->n; i++)
		if (memcmp(set->xid[i], xid, LI_XID_LEN) == 0) {
			set->side[i] |= side;
			return i;
		}
	if (set->n >= LI_MAX_XIDS)
		return -1;
	memcpy(set->xid[set->n], xid, LI_XID_LEN);
	set->side[set->n] = side;
	set->dir[set->n] = 0;
	return set->n++;
}

/* Adds the tasks whose target is this identifier of class cls. Call with
 * the table lock held. */
static int match_id(int cls, const char *id, int id_len, struct li_xids *set,
	int side)
{
	unsigned char buf[LI_MAX_IDENTITY + LI_MAX_SALT];
	unsigned char digest[LI_DIGEST_LEN];
	unsigned int i;
	int len, found = 0;

	if (!id || id_len <= 0)
		return 0;
	len = li_canonical(cls, id, id_len, (char *)buf, LI_MAX_IDENTITY);
	if (len <= 0)
		return 0;
	memcpy(buf + len, tab->salt, tab->salt_len);
	sha256(buf, len + tab->salt_len, digest, 0);

	for (i = 0; i < tab->count; i++) {
		if (tab->entries[i].cls == cls &&
				memcmp(tab->entries[i].digest, digest, LI_DIGEST_LEN) == 0) {
			add_xid(set, tab->entries[i].xid, side);
			found = 1;
		}
	}
	return found;
}

/* An instance is an IMEI only as urn:gsma:imei (TS 24.229 clause 5.1.1.2.1);
 * a UUID has digits too. */
static int match_instance(const str *instance, struct li_xids *set, int side)
{
	static const str urn = str_init("urn:gsma:imei:");
	int i;

	if (!instance || !instance->s)
		return 0;
	for (i = 0; i + urn.len < instance->len; i++)
		if (strncasecmp(instance->s + i, urn.s, urn.len) == 0)
			return match_id(LI_CLASS_IMEI, instance->s + i + urn.len,
				instance->len - i - urn.len, set, side);
	return 0;
}

/*
 * Adds the tasks whose target is the IMPI or an IMEI registered for this
 * IMPU. The usrloc record is found by the user part alone, as the script
 * stores it. Call with the table lock held.
 */
static int match_bound(const str *uri, struct li_xids *set, int side)
{
	urecord_t *r = NULL;
	ucontact_t *c;
	int_str_t *impi;
	str aor;
	time_t now;
	int i, found = 0;

	if (!li_domain || !tab->bound || !uri || !uri->s || uri->len <= 0)
		return 0;
	for (i = 0; i < uri->len && uri->s[i] != ':'; i++);
	if (i >= uri->len - 1)
		return 0;
	aor.s = uri->s + i + 1;
	for (aor.len = 0; aor.s + aor.len < uri->s + uri->len &&
			aor.s[aor.len] != '@' && aor.s[aor.len] != ';'; aor.len++);
	if (aor.len == 0)
		return 0;

	now = time(NULL);
	ul.lock_udomain(li_domain, &aor);
	if (ul.get_urecord(li_domain, &aor, &r) == 0 && r) {
		impi = ul.get_urecord_key(r, &li_impi_key);
		if (impi && impi->is_str)
			found |= match_id(LI_CLASS_IMPI, impi->s.s, impi->s.len, set,
				side);
		for (c = r->contacts; c; c = c->next)
			if (VALID_CONTACT(c, now))
				found |= match_instance(&c->instance, set, side);
	}
	ul.unlock_udomain(li_domain, &aor);
	return found;
}

/* The identities a URI stands for: the IMPU itself and what is registered
 * for it. Call with the table lock held. */
static int match_impu(const str *uri, struct li_xids *set, int side)
{
	int found;

	if (!uri || !uri->s || uri->len <= 0)
		return 0;
	found = match_id(LI_CLASS_IMPU, uri->s, uri->len, set, side);
	found |= match_bound(uri, set, side);
	return found;
}

/* The IMPI and the IMEI a REGISTER itself names. Call with the table lock
 * held. */
static int match_register(struct sip_msg *msg, struct li_xids *set)
{
	struct hdr_field *h;
	contact_t *c;
	auth_body_t *auth;
	int found = 0;

	if (!tab->bound || parse_headers(msg, HDR_EOH_F, 0) < 0)
		return 0;
	if (msg->authorization && parse_credentials(msg->authorization) == 0 &&
			(auth = (auth_body_t *)msg->authorization->parsed) != NULL)
		found |= match_id(LI_CLASS_IMPI, auth->digest.username.whole.s,
			auth->digest.username.whole.len, set, LI_SIDE_FROM);
	for (h = msg->contact; h; h = h->sibling) {
		if (!h->parsed && parse_contact(h) < 0)
			continue;
		for (c = ((contact_body_t *)h->parsed)->contacts; c; c = c->next)
			if (c->instance)
				found |= match_instance(&c->instance->body, set,
					LI_SIDE_FROM);
	}
	return found;
}

/* The key of a Call-ID in the memory. Call with the table lock held. */
static void call_key(const str *callid, unsigned char *key)
{
	unsigned char buf[LI_MAX_CALLID + LI_MAX_SALT];
	int len = callid->len > LI_MAX_CALLID ? LI_MAX_CALLID : callid->len;

	memcpy(buf, callid->s, len);
	memcpy(buf + len, tab->salt, tab->salt_len);
	sha256(buf, len + tab->salt_len, key, 0);
}

static void push_call(bin_packet_t *packet, const struct li_call *c)
{
	str key = {(char *)c->key, LI_DIGEST_LEN};
	str xids = {(char *)c->xids.xid, c->xids.n * LI_XID_LEN};
	str dirs = {(char *)c->xids.dir, c->xids.n};

	bin_push_str(packet, &key);
	bin_push_str(packet, &xids);
	bin_push_str(packet, &dirs);
}

/* Tells the other nodes about a remembered call. */
static void replicate_call(const struct li_call *c, int ending)
{
	bin_packet_t packet;

	if (li_cluster_id <= 0)
		return;
	if (bin_init(&packet, &li_repl_cap, LI_REPL_CALL, LI_BIN_VERSION, 0) != 0)
		return;
	push_call(&packet, c);
	bin_push_int(&packet, ending);
	/* not acknowledged: a node that misses it matches by the headers */
	c_api.send_all(&packet, li_cluster_id);
	bin_free_packet(&packet);
}

/*
 * Looks a call up by its key and brings set and the memory in line: the
 * tasks of a remembered call are added to set with the session direction
 * they were stored with, and tasks that set has in addition stay with the
 * call from now on. A call that is not known is stored with remember != 0.
 * With ending != 0 (BYE) the call is forgotten LI_END_TTL seconds from now,
 * so that a Call-ID used again is a new call. Returns 1 if the call is
 * known. With replicate != 0 changes go to the other nodes.
 */
static int call_memory(const unsigned char *key, struct li_xids *set,
	int remember, int ending, int replicate)
{
	unsigned int bucket = (((unsigned int)key[0] << 8) | key[1]) %
		LI_CALL_BUCKETS;
	unsigned int now = get_ticks();
	struct li_call *c, **prev, copy;
	int found = 0, changed = 0, i, j;

	lock_set_get(calls_lock, bucket);
	prev = &calls[bucket];
	while ((c = *prev) != NULL) {
		if (c->expires < now) {
			*prev = c->next;
			shm_free(c);
			(*calls_active)--;
			continue;
		}
		if (memcmp(c->key, key, LI_DIGEST_LEN) == 0) {
			for (i = 0; i < c->xids.n; i++) {
				j = add_xid(set, c->xids.xid[i], 0);
				if (j >= 0)
					set->dir[j] = c->xids.dir[i];
			}
			if (set->n != c->xids.n) {
				c->xids = *set;
				changed = 1;
			}
			if (ending) {
				if (c->expires > now + LI_END_TTL) {
					c->expires = now + LI_END_TTL;
					changed = 1;
				}
			} else if (c->expires > now + LI_END_TTL) {
				/* not for a call that is ending */
				c->expires = now + li_call_ttl;
			}
			found = 1;
			copy = *c;
		}
		prev = &c->next;
	}
	if (!found && remember) {
		c = shm_malloc(sizeof *c);
		if (c) {
			c->expires = now + (ending ? LI_END_TTL : li_call_ttl);
			c->xids = *set;
			memcpy(c->key, key, LI_DIGEST_LEN);
			c->next = calls[bucket];
			calls[bucket] = c;
			(*calls_active)++;
			copy = *c;
			changed = 1;
		}
	}
	lock_set_release(calls_lock, bucket);
	if (changed && replicate)
		replicate_call(&copy, ending);
	return found;
}

/* ------------------------------------------------------------------------
 * Sharing the call memory in the cluster
 * ---------------------------------------------------------------------- */

static int pop_call(bin_packet_t *packet)
{
	struct li_xids set;
	str key, xids, dirs;
	int ending;

	if (bin_pop_str(packet, &key) < 0 || bin_pop_str(packet, &xids) < 0 ||
			bin_pop_str(packet, &dirs) < 0 || bin_pop_int(packet, &ending) < 0)
		return -1;
	if (key.len != LI_DIGEST_LEN || xids.len <= 0 ||
			xids.len % LI_XID_LEN || xids.len > LI_MAX_XIDS * LI_XID_LEN ||
			dirs.len != xids.len / LI_XID_LEN)
		return -1;
	memset(&set, 0, sizeof set);
	set.n = dirs.len;
	memcpy(set.xid, xids.s, xids.len);
	memcpy(set.dir, dirs.s, dirs.len);
	call_memory((unsigned char *)key.s, &set, 1, ending, 0);
	return 0;
}

static void li_receive_packet(bin_packet_t *packet)
{
	int rc = 0;

	switch (packet->type) {
	case LI_REPL_CALL:
		ensure_bin_version(packet, LI_BIN_VERSION);
		rc = pop_call(packet);
		break;
	default:
		rc = -1;
	}
	if (rc != 0)
		LM_ERR("invalid packet from node %d\n", packet->src_id);
}

static void li_cluster_event(enum clusterer_event ev, int node_id)
{
}

static int li_init_cluster(void)
{
	if (load_clusterer_api(&c_api) != 0) {
		LM_ERR("failed to find the clusterer API\n");
		return -1;
	}
	if (c_api.register_capability(&li_repl_cap, li_receive_packet,
			li_cluster_event, li_cluster_id, 0, NODE_CMP_ANY) < 0) {
		LM_ERR("failed to register with the clusterer\n");
		return -1;
	}
	/* No sync at startup: a node that waits for one is not "synced" for the
	 * clusterer, and nothing else may depend on this module. A node that
	 * restarts does not know the calls in progress. */
	return 0;
}

/*
 * li_match(result): 1 if the request belongs to an intercepted
 * communication, -1 otherwise. On a match the result variable is
 *
 *   v2;x=<xid>:<d><m>[,<xid>:<d><m>...]
 *
 * with one entry per task: the XID as 32 hex digits, d the direction of the
 * session as the target of that task sees it (f from the target, t to the
 * target, c combined, i indeterminate) and m the direction of this request
 * (f from, t to, u unknown). Two tasks can see one call from opposite sides.
 *
 * caller and called are identities the script worked out itself (a border
 * element that brings a carrier's number into its international form); they
 * count like From and Request-URI.
 */
static int w_li_match(struct sip_msg *msg, pv_spec_t *out, str *caller,
	str *called)
{
	static char buf[8 + LI_MAX_XIDS * (2 * LI_XID_LEN + 4)];
	static const char hex[] = "0123456789abcdef";
	struct li_xids set;
	struct to_body *from, *to;
	pv_value_t val;
	unsigned char key[LI_DIGEST_LEN];
	char mdir;
	int matched = 0, in_dialog, remember, i, j;
	char *p;

	/* the common case: no task and no remembered call */
	if (tab->count == 0 && *calls_active == 0)
		return -1;
	if (msg->first_line.type != SIP_REQUEST)
		return -1;
	if (parse_headers(msg, HDR_CALLID_F | HDR_TO_F | HDR_FROM_F, 0) < 0 ||
			!msg->callid || !msg->to || !msg->from ||
			parse_from_header(msg) < 0)
		return -1;
	from = get_from(msg);
	to = get_to(msg);
	if (!from || !to)
		return -1;

	memset(&set, 0, sizeof set);
	lock_start_read(tab->lock);
	if (tab->count) {
		matched = match_impu(&from->uri, &set, LI_SIDE_FROM);
		if (parse_pai_header(msg) == 0 && msg->pai && get_pai(msg))
			matched |= match_impu(&get_pai(msg)->uri, &set, LI_SIDE_FROM);
		matched |= match_impu(&REQ_LINE(msg).uri, &set, LI_SIDE_TO);
		matched |= match_impu(&to->uri, &set, LI_SIDE_TO);
		matched |= match_impu(caller, &set, LI_SIDE_FROM);
		matched |= match_impu(called, &set, LI_SIDE_TO);
		if (msg->REQ_METHOD == METHOD_REGISTER)
			matched |= match_register(msg, &set);
	}
	call_key(&msg->callid->body, key);
	lock_stop_read(tab->lock);

	in_dialog = to->tag_value.len > 0;
	for (i = 0; i < set.n; i++) {
		if (msg->REQ_METHOD == METHOD_REGISTER)
			set.dir[i] = 'f';
		else if (in_dialog)
			set.dir[i] = 'i';
		else if (set.side[i] == (LI_SIDE_FROM | LI_SIDE_TO))
			set.dir[i] = 'c';
		else
			set.dir[i] = set.side[i] == LI_SIDE_FROM ? 'f' : 't';
	}

	/* the memory overrides the direction with that of the INVITE */
	remember = matched && msg->REQ_METHOD == METHOD_INVITE && !in_dialog;
	if (*calls_active || remember)
		call_memory(key, &set, remember, msg->REQ_METHOD == METHOD_BYE, 1);
	if (set.n == 0)
		return -1;

	p = buf;
	memcpy(p, "v2;x=", 5); p += 5;
	for (i = 0; i < set.n; i++) {
		if (msg->REQ_METHOD == METHOD_REGISTER || (set.side[i] & LI_SIDE_FROM))
			mdir = 'f';
		else if (set.side[i] & LI_SIDE_TO)
			mdir = 't';
		else if (!in_dialog && (set.dir[i] == 'f' || set.dir[i] == 't'))
			/* The request that set the session up, on its way again (e.g.
			 * back from an application server that hid the caller): it
			 * still travels in the direction of the session. */
			mdir = set.dir[i];
		else
			mdir = 'u';
		if (i)
			*p++ = ',';
		for (j = 0; j < LI_XID_LEN; j++) {
			*p++ = hex[set.xid[i][j] >> 4];
			*p++ = hex[set.xid[i][j] & 0x0f];
		}
		*p++ = ':';
		*p++ = set.dir[i];
		*p++ = mdir;
	}

	val.rs.s = buf;
	val.rs.len = (int)(p - buf);
	val.ri = 0;
	val.flags = PV_VAL_STR;
	if (pv_set_value(msg, out, 0, &val) < 0) {
		LM_ERR("failed to set the result variable\n");
		return -1;
	}
	return 1;
}

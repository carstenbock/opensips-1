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
 * target is the receiver). An INVITE that matched is remembered by its
 * Call-ID, so that later requests of the dialog are recognised when their
 * headers no longer name the target (e.g. an anonymous From).
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

#include "li_identity.h"
#include "li_table.h"

/* tasks one message can belong to */
#define LI_MAX_XIDS 8
#define LI_CALL_BUCKETS 1024
#define LI_MAX_IDENTITY 512
#define LI_RECONNECT 2

struct li_shared {
	rw_lock_t *lock;
	unsigned int version;
	unsigned char salt[LI_MAX_SALT];
	int salt_len;
	/* read without the lock for the "nothing to do" test */
	unsigned int count;
	struct li_entry *entries;
};

struct li_xids {
	int n;
	unsigned char xid[LI_MAX_XIDS][LI_XID_LEN];
};

struct li_call {
	struct li_call *next;
	unsigned int expires;
	char dir;
	struct li_xids xids;
	int callid_len;
	char callid[1];
};

static struct li_shared *tab;
static struct li_call **calls;
static gen_lock_set_t *calls_lock;
/* remembered calls; read without a lock for the "nothing to do" test */
static int *calls_active;

static str li_socket = {0, 0};
static int li_call_ttl = 7200;

static int mod_init(void);
static void mod_destroy(void);
static void li_table_proc(int rank);
static int w_li_match(struct sip_msg *msg, pv_spec_t *out);

static const cmd_export_t cmds[] = {
	{"li_match", (cmd_function)w_li_match, {
		{CMD_PARAM_VAR, 0, 0}, {0, 0, 0}}, REQUEST_ROUTE},
	{0, 0, {{0, 0, 0}}, 0}
};

static const param_export_t params[] = {
	{"socket",   STR_PARAM, &li_socket.s},
	{"call_ttl", INT_PARAM, &li_call_ttl},
	{0, 0, 0}
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
	0,               /* OpenSIPS module dependencies */
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
	unsigned int i;

	if (parsed->count) {
		fresh = shm_malloc(parsed->count * sizeof *fresh);
		if (!fresh) {
			LM_ERR("no more shm memory for the task table\n");
			return -1;
		}
		for (i = 0; i < parsed->count; i++)
			li_parsed_entry(parsed, i, &fresh[i]);
	}

	lock_start_write(tab->lock);
	old = tab->entries;
	tab->entries = fresh;
	tab->count = parsed->count;
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

static void add_xid(struct li_xids *set, const unsigned char *xid)
{
	int i;

	for (i = 0; i < set->n; i++)
		if (memcmp(set->xid[i], xid, LI_XID_LEN) == 0)
			return;
	if (set->n < LI_MAX_XIDS)
		memcpy(set->xid[set->n++], xid, LI_XID_LEN);
}

/* Adds the tasks whose target is this IMPU. Call with the table lock held. */
static int match_impu(const str *uri, struct li_xids *set)
{
	unsigned char buf[LI_MAX_IDENTITY + LI_MAX_SALT];
	unsigned char digest[LI_DIGEST_LEN];
	unsigned int i;
	int len, found = 0;

	if (!uri || !uri->s || uri->len <= 0)
		return 0;
	len = li_canonical(LI_CLASS_IMPU, uri->s, uri->len, (char *)buf,
		LI_MAX_IDENTITY);
	if (len <= 0)
		return 0;
	memcpy(buf + len, tab->salt, tab->salt_len);
	sha256(buf, len + tab->salt_len, digest, 0);

	for (i = 0; i < tab->count; i++) {
		if (tab->entries[i].cls == LI_CLASS_IMPU &&
				memcmp(tab->entries[i].digest, digest, LI_DIGEST_LEN) == 0) {
			add_xid(set, tab->entries[i].xid);
			found = 1;
		}
	}
	return found;
}

/*
 * Looks the Call-ID up. If it is remembered, its tasks are added to set and
 * its session direction is returned. Otherwise, with remember != 0, it is
 * stored with set and dir. Returns 0 if the Call-ID is not known.
 */
static char call_memory(const str *callid, struct li_xids *set, char dir,
	int remember)
{
	unsigned int bucket = core_hash(callid, NULL, LI_CALL_BUCKETS);
	unsigned int now = get_ticks();
	struct li_call *c, **prev;
	char found = 0;
	int i;

	lock_set_get(calls_lock, bucket);
	prev = &calls[bucket];
	while ((c = *prev) != NULL) {
		if (c->expires < now) {
			*prev = c->next;
			shm_free(c);
			(*calls_active)--;
			continue;
		}
		if (c->callid_len == callid->len &&
				memcmp(c->callid, callid->s, callid->len) == 0) {
			for (i = 0; i < c->xids.n; i++)
				add_xid(set, c->xids.xid[i]);
			/* tasks that started to match during the call stay with it */
			c->xids = *set;
			c->expires = now + li_call_ttl;
			found = c->dir;
		}
		prev = &c->next;
	}
	if (!found && remember) {
		c = shm_malloc(sizeof *c + callid->len);
		if (c) {
			c->expires = now + li_call_ttl;
			c->dir = dir;
			c->xids = *set;
			c->callid_len = callid->len;
			memcpy(c->callid, callid->s, callid->len);
			c->next = calls[bucket];
			calls[bucket] = c;
			(*calls_active)++;
		}
	}
	lock_set_release(calls_lock, bucket);
	return found;
}

/*
 * li_match(result): 1 if the request belongs to an intercepted
 * communication, -1 otherwise. On a match the result variable is
 *
 *   v1;d=<f|t|c|i>;m=<f|t|u>;x=<xid>[,<xid>...]
 *
 * d: direction of the session (from the target, to the target, combined,
 *    indeterminate); m: direction of this request (from, to, unknown);
 * x: the tasks, each XID as 32 hex digits.
 */
static int w_li_match(struct sip_msg *msg, pv_spec_t *out)
{
	static char buf[32 + LI_MAX_XIDS * (2 * LI_XID_LEN + 1)];
	static const char hex[] = "0123456789abcdef";
	struct li_xids set;
	struct to_body *from, *to;
	pv_value_t val;
	char dir, mdir, known;
	int from_match = 0, to_match = 0, in_dialog, i, j;
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

	set.n = 0;
	lock_start_read(tab->lock);
	if (tab->count) {
		from_match = match_impu(&from->uri, &set);
		if (parse_pai_header(msg) == 0 && msg->pai && get_pai(msg))
			from_match |= match_impu(&get_pai(msg)->uri, &set);
		to_match = match_impu(&REQ_LINE(msg).uri, &set);
		to_match |= match_impu(&to->uri, &set);
	}
	lock_stop_read(tab->lock);

	in_dialog = to->tag_value.len > 0;
	if (msg->REQ_METHOD == METHOD_REGISTER)
		dir = 'f';
	else if (in_dialog)
		dir = 'i';
	else if (from_match && to_match)
		dir = 'c';
	else
		dir = from_match ? 'f' : 't';

	known = 0;
	if (*calls_active || ((from_match || to_match) &&
			msg->REQ_METHOD == METHOD_INVITE && !in_dialog))
		known = call_memory(&msg->callid->body, &set, dir,
			(from_match || to_match) && msg->REQ_METHOD == METHOD_INVITE &&
			!in_dialog);
	if (known)
		dir = known;
	if (set.n == 0)
		return -1;

	if (msg->REQ_METHOD == METHOD_REGISTER || from_match)
		mdir = 'f';
	else if (to_match)
		mdir = 't';
	else if (!in_dialog && (dir == 'f' || dir == 't'))
		/* The request that set the session up, on its way again (e.g. back
		 * from an application server that hid the caller): it still travels
		 * in the direction of the session. */
		mdir = dir;
	else
		mdir = 'u';

	p = buf;
	memcpy(p, "v1;d=", 5); p += 5;
	*p++ = dir;
	memcpy(p, ";m=", 3); p += 3;
	*p++ = mdir;
	memcpy(p, ";x=", 3); p += 3;
	for (i = 0; i < set.n; i++) {
		if (i)
			*p++ = ',';
		for (j = 0; j < LI_XID_LEN; j++) {
			*p++ = hex[set.xid[i][j] >> 4];
			*p++ = hex[set.xid[i][j] & 0x0f];
		}
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

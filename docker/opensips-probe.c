/*
 * opensips-probe: Kubernetes probes and hooks for the distroless OpenSIPS
 * images, which have no shell (helm ADR-0051). Built statically.
 *
 *   opensips-probe sip <host> <port> <timeout-s>
 *       Liveness. Sends one SIP OPTIONS over UDP from <host> to <host>:<port>
 *       and waits for a final response (>= 200) with the same Call-ID. A TCP
 *       connect succeeds even when every SIP worker is stuck; a SIP reply
 *       needs a free worker. Same behaviour as the former sip-ping script.
 *
 *   opensips-probe cluster-ready <host> <tcp-port> <mi-port> <wait-s> <file>
 *       Readiness of a clusterer node: SIP is served on <host>:<tcp-port>,
 *       and either the pod started at least <wait-s> seconds ago (mtime of
 *       <file>, written at start), or every clusterer capability is synced
 *       and no link to another node is Down or Probe (MI over HTTP on
 *       127.0.0.1:<mi-port>/mi).
 *
 *   opensips-probe mi-until <flag-file> <mi-port> <method> <expect> <tries> <interval-s>
 *       postStart hook. Only when <flag-file> exists: calls the MI <method>
 *       every <interval-s> seconds until the answer contains <expect>, at
 *       most <tries> times. Always exits 0, so the hook never kills the
 *       container. Works in the background: returns at once.
 *
 *   opensips-probe tcp <host> <port> <timeout-s>
 *       Liveness without SIP: a TCP connect to <host>:<port>.
 *
 *   opensips-probe route-del-local <host>
 *       preStop hook of the IPsec gateway: deletes the local route
 *       <host>/32 dev lo from table local (what `ip route del local
 *       <host>/32 dev lo table local` did). Always exits 0.
 *
 * <host> is an IPv4 address, "env:NAME" (the value of an environment
 * variable) or "file:PATH" (the first line of a file).
 *
 * Exit status: 0 = success, 1 = probe failed, 2 = usage error.
 */
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <net/if.h>
#include <netinet/in.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

static int resolve_host(const char *spec, char *out, size_t outlen)
{
    if (strncmp(spec, "env:", 4) == 0) {
        const char *v = getenv(spec + 4);
        if (!v || !*v) {
            fprintf(stderr, "opensips-probe: %s is not set\n", spec + 4);
            return -1;
        }
        snprintf(out, outlen, "%s", v);
    } else if (strncmp(spec, "file:", 5) == 0) {
        FILE *f = fopen(spec + 5, "r");
        if (!f || !fgets(out, (int)outlen, f)) {
            fprintf(stderr, "opensips-probe: cannot read %s\n", spec + 5);
            if (f)
                fclose(f);
            return -1;
        }
        fclose(f);
        out[strcspn(out, " \t\r\n")] = '\0';
    } else {
        snprintf(out, outlen, "%s", spec);
    }
    return 0;
}

static double now_mono(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec + ts.tv_nsec / 1e9;
}

static void random_hex(char *out, size_t nbytes)
{
    unsigned char buf[32];
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd < 0 || read(fd, buf, nbytes) != (ssize_t)nbytes) {
        unsigned long seed = (unsigned long)time(NULL) ^ (unsigned long)getpid();
        for (size_t i = 0; i < nbytes; i++)
            buf[i] = (unsigned char)((seed = seed * 1103515245 + 12345) >> 16);
    }
    if (fd >= 0)
        close(fd);
    for (size_t i = 0; i < nbytes; i++)
        sprintf(out + 2 * i, "%02x", buf[i]);
}

/* Status code of a final response that carries our Call-ID, else 0. */
static int final_status(char *msg, const char *callid)
{
    int code;
    if (strncmp(msg, "SIP/2.0 ", 8) != 0 || sscanf(msg + 8, "%d", &code) != 1 || code < 200)
        return 0;
    for (char *line = strstr(msg, "\r\n"); line; line = strstr(line, "\r\n")) {
        line += 2;
        char *colon = strchr(line, ':');
        char *eol = strstr(line, "\r\n");
        if (!colon || (eol && colon > eol))
            continue;
        size_t nlen = (size_t)(colon - line);
        while (nlen && (line[nlen - 1] == ' ' || line[nlen - 1] == '\t'))
            nlen--;
        if (!((nlen == 7 && strncasecmp(line, "Call-ID", 7) == 0) ||
              (nlen == 1 && (line[0] == 'i' || line[0] == 'I'))))
            continue;
        char *v = colon + 1;
        while (*v == ' ' || *v == '\t')
            v++;
        size_t vlen = eol ? (size_t)(eol - v) : strlen(v);
        while (vlen && (v[vlen - 1] == ' ' || v[vlen - 1] == '\t'))
            vlen--;
        if (vlen == strlen(callid) && strncmp(v, callid, vlen) == 0)
            return code;
    }
    return 0;
}

static int cmd_sip(const char *hostspec, int port, double timeout)
{
    char host[64];
    if (resolve_host(hostspec, host, sizeof host) < 0)
        return 1;
    struct sockaddr_in addr = {.sin_family = AF_INET};
    if (inet_pton(AF_INET, host, &addr.sin_addr) != 1) {
        fprintf(stderr, "opensips-probe: not an IPv4 address: %s\n", host);
        return 2;
    }
    int s = socket(AF_INET, SOCK_DGRAM, 0);
    /* Bind to the target address so the request's source IP is the pod's
     * own address; the OpenSIPS scripts answer OPTIONS only from there. */
    struct sockaddr_in local = addr;
    local.sin_port = 0;
    socklen_t llen = sizeof local;
    if (s < 0 || bind(s, (struct sockaddr *)&local, sizeof local) < 0 ||
        getsockname(s, (struct sockaddr *)&local, &llen) < 0) {
        fprintf(stderr, "opensips-probe: socket: %s\n", strerror(errno));
        return 1;
    }
    char branch[17], tag[9], callid[40], msg[1024];
    random_hex(branch, 8);
    random_hex(tag, 4);
    random_hex(callid, 8);
    strcat(callid, "@sip-ping");
    int n = snprintf(msg, sizeof msg,
                     "OPTIONS sip:%s:%d SIP/2.0\r\n"
                     "Via: SIP/2.0/UDP %s:%d;branch=z9hG4bK%s;rport\r\n"
                     "Max-Forwards: 1\r\n"
                     "To: <sip:%s:%d>\r\n"
                     "From: <sip:sip-ping@%s>;tag=%s\r\n"
                     "Call-ID: %s\r\n"
                     "CSeq: 1 OPTIONS\r\n"
                     "User-Agent: sip-ping\r\n"
                     "Content-Length: 0\r\n\r\n",
                     host, port, host, ntohs(local.sin_port), branch, host, port,
                     host, tag, callid);
    addr.sin_port = htons((unsigned short)port);
    if (sendto(s, msg, (size_t)n, 0, (struct sockaddr *)&addr, sizeof addr) < 0) {
        fprintf(stderr, "opensips-probe: sendto: %s\n", strerror(errno));
        return 1;
    }
    double deadline = now_mono() + timeout;
    for (;;) {
        double remaining = deadline - now_mono();
        if (remaining <= 0)
            break;
        struct pollfd p = {.fd = s, .events = POLLIN};
        if (poll(&p, 1, (int)(remaining * 1000) + 1) <= 0)
            continue;
        char buf[65536];
        ssize_t r = recv(s, buf, sizeof buf - 1, 0);
        if (r <= 0)
            continue;
        buf[r] = '\0';
        int code = final_status(buf, callid);
        if (code) {
            printf("sip-ping: %s:%d answered %d\n", host, port, code);
            return 0;
        }
    }
    fprintf(stderr, "sip-ping: no SIP response from %s:%d within %gs\n", host, port, timeout);
    return 1;
}

static int tcp_connect(const char *host, int port, int timeout_ms)
{
    struct sockaddr_in addr = {.sin_family = AF_INET, .sin_port = htons((unsigned short)port)};
    if (inet_pton(AF_INET, host, &addr.sin_addr) != 1)
        return -1;
    int s = socket(AF_INET, SOCK_STREAM, 0);
    if (s < 0)
        return -1;
    fcntl(s, F_SETFL, O_NONBLOCK);
    if (connect(s, (struct sockaddr *)&addr, sizeof addr) < 0 && errno != EINPROGRESS) {
        close(s);
        return -1;
    }
    struct pollfd p = {.fd = s, .events = POLLOUT};
    int err = 0;
    socklen_t elen = sizeof err;
    if (poll(&p, 1, timeout_ms) != 1 || getsockopt(s, SOL_SOCKET, SO_ERROR, &err, &elen) < 0 || err) {
        close(s);
        return -1;
    }
    fcntl(s, F_SETFL, 0);
    return s;
}

/* POST a JSON-RPC call to 127.0.0.1:<port>/mi; the body of the answer in
 * out. Returns 0 on an HTTP 200, -1 otherwise. */
static int mi_call(int port, const char *method, char *out, size_t outlen)
{
    int s = tcp_connect("127.0.0.1", port, 2000);
    if (s < 0)
        return -1;
    char body[256], req[512];
    int blen = snprintf(body, sizeof body, "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"%s\"}", method);
    int rlen = snprintf(req, sizeof req,
                        "POST /mi HTTP/1.0\r\nHost: 127.0.0.1:%d\r\n"
                        "Content-Type: application/json\r\nContent-Length: %d\r\n"
                        "Connection: close\r\n\r\n%s",
                        port, blen, body);
    if (write(s, req, (size_t)rlen) != rlen) {
        close(s);
        return -1;
    }
    size_t got = 0;
    double deadline = now_mono() + 2.0;
    while (got < outlen - 1) {
        double remaining = deadline - now_mono();
        struct pollfd p = {.fd = s, .events = POLLIN};
        if (remaining <= 0 || poll(&p, 1, (int)(remaining * 1000) + 1) <= 0)
            break;
        ssize_t r = read(s, out + got, outlen - 1 - got);
        if (r <= 0)
            break;
        got += (size_t)r;
    }
    close(s);
    out[got] = '\0';
    if (strncmp(out, "HTTP/1.", 7) != 0 || strncmp(out + 8, " 200", 4) != 0)
        return -1;
    char *b = strstr(out, "\r\n\r\n");
    if (b)
        memmove(out, b + 4, strlen(b + 4) + 1);
    return 0;
}

static int cmd_cluster_ready(const char *hostspec, int tcp_port, int mi_port, long wait_s,
                             const char *file)
{
    char host[64];
    if (resolve_host(hostspec, host, sizeof host) < 0)
        return 1;
    int s = tcp_connect(host, tcp_port, 2000);
    if (s < 0) {
        fprintf(stderr, "cluster-ready: SIP not served on %s:%d\n", host, tcp_port);
        return 1;
    }
    close(s);
    struct stat st;
    if (stat(file, &st) == 0 && time(NULL) - st.st_mtime >= wait_s)
        return 0;
    static char rsp[1 << 20];
    if (mi_call(mi_port, "clusterer_list_cap", rsp, sizeof rsp) < 0 ||
        strstr(rsp, "not synced") || !strstr(rsp, "\"Capabilities\"")) {
        fprintf(stderr, "cluster-ready: capabilities not synced\n");
        return 1;
    }
    if (mi_call(mi_port, "clusterer_list", rsp, sizeof rsp) < 0 ||
        strstr(rsp, "\"link_state\":\"Down\"") || strstr(rsp, "\"link_state\":\"Probe\"") ||
        !strstr(rsp, "\"Nodes\"")) {
        fprintf(stderr, "cluster-ready: a cluster link is not Up\n");
        return 1;
    }
    return 0;
}

static int cmd_mi_until(const char *flag, int mi_port, const char *method, const char *expect,
                        int tries, int interval)
{
    if (access(flag, F_OK) != 0)
        return 0;
    /* Return at once and work in the background, as the shell subshell this
     * replaces did: a postStart hook holds the container's start until it
     * returns. The messages go to the container's log (stdout of PID 1). */
    pid_t pid = fork();
    if (pid != 0)
        return 0;
    setsid();
    signal(SIGPIPE, SIG_IGN);
    int fd = open("/proc/1/fd/1", O_WRONLY);
    if (fd < 0)
        fd = open("/dev/null", O_WRONLY);
    if (fd >= 0) {
        dup2(fd, STDOUT_FILENO);
        dup2(fd, STDERR_FILENO);
        if (fd > STDERR_FILENO)
            close(fd);
    }
    static char rsp[1 << 16];
    for (int i = 0; i < tries; i++) {
        sleep((unsigned)interval);
        if (mi_call(mi_port, method, rsp, sizeof rsp) < 0)
            continue;
        if (strstr(rsp, expect)) {
            printf("mi-until: %s answered %s\n", method, expect);
            return 0;
        }
        printf("mi-until: %s answered: %.200s\n", method, rsp);
    }
    fprintf(stderr, "mi-until: ERROR - %s did not answer %s after %d tries\n", method, expect, tries);
    return 0;
}

static int cmd_tcp(const char *hostspec, int port, double timeout)
{
    char host[64];
    if (resolve_host(hostspec, host, sizeof host) < 0)
        return 1;
    int s = tcp_connect(host, port, (int)(timeout * 1000));
    if (s < 0) {
        fprintf(stderr, "tcp: no connection to %s:%d\n", host, port);
        return 1;
    }
    close(s);
    return 0;
}

static int cmd_route_del_local(const char *hostspec)
{
    char host[64];
    struct in_addr dst;
    if (resolve_host(hostspec, host, sizeof host) < 0 || inet_pton(AF_INET, host, &dst) != 1) {
        fprintf(stderr, "route-del-local: no address\n");
        return 0;
    }
    struct {
        struct nlmsghdr nh;
        struct rtmsg rt;
        char attrs[64];
    } req;
    memset(&req, 0, sizeof req);
    req.nh.nlmsg_type = RTM_DELROUTE;
    req.nh.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
    req.rt.rtm_family = AF_INET;
    req.rt.rtm_dst_len = 32;
    req.rt.rtm_table = RT_TABLE_LOCAL;
    req.rt.rtm_type = RTN_LOCAL;
    req.rt.rtm_scope = RT_SCOPE_NOWHERE;
    req.rt.rtm_protocol = RTPROT_UNSPEC;
    struct rtattr *a = (struct rtattr *)req.attrs;
    a->rta_type = RTA_DST;
    a->rta_len = RTA_LENGTH(sizeof dst);
    memcpy(RTA_DATA(a), &dst, sizeof dst);
    int len = RTA_ALIGN(a->rta_len);
    a = (struct rtattr *)(req.attrs + len);
    int lo = (int)if_nametoindex("lo");
    a->rta_type = RTA_OIF;
    a->rta_len = RTA_LENGTH(sizeof lo);
    memcpy(RTA_DATA(a), &lo, sizeof lo);
    len += RTA_ALIGN(a->rta_len);
    req.nh.nlmsg_len = NLMSG_LENGTH(sizeof req.rt) + (unsigned)len;

    int s = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
    struct sockaddr_nl kernel = {.nl_family = AF_NETLINK};
    if (s < 0 || sendto(s, &req, req.nh.nlmsg_len, 0, (struct sockaddr *)&kernel, sizeof kernel) < 0) {
        fprintf(stderr, "route-del-local: netlink: %s\n", strerror(errno));
        return 0;
    }
    char buf[4096];
    struct pollfd p = {.fd = s, .events = POLLIN};
    if (poll(&p, 1, 2000) == 1) {
        ssize_t r = recv(s, buf, sizeof buf, 0);
        struct nlmsghdr *nh = (struct nlmsghdr *)buf;
        if (r >= (ssize_t)NLMSG_LENGTH(sizeof(struct nlmsgerr)) && nh->nlmsg_type == NLMSG_ERROR) {
            int err = ((struct nlmsgerr *)NLMSG_DATA(nh))->error;
            if (err)
                fprintf(stderr, "route-del-local %s: %s\n", host, strerror(-err));
            else
                printf("route-del-local: removed %s/32 from table local\n", host);
        }
    }
    close(s);
    return 0;
}

int main(int argc, char **argv)
{
    if (argc == 5 && strcmp(argv[1], "sip") == 0)
        return cmd_sip(argv[2], atoi(argv[3]), atof(argv[4]));
    if (argc == 7 && strcmp(argv[1], "cluster-ready") == 0)
        return cmd_cluster_ready(argv[2], atoi(argv[3]), atoi(argv[4]), atol(argv[5]), argv[6]);
    if (argc == 5 && strcmp(argv[1], "tcp") == 0)
        return cmd_tcp(argv[2], atoi(argv[3]), atof(argv[4]));
    if (argc == 3 && strcmp(argv[1], "route-del-local") == 0)
        return cmd_route_del_local(argv[2]);
    if (argc == 8 && strcmp(argv[1], "mi-until") == 0)
        return cmd_mi_until(argv[2], atoi(argv[3]), argv[4], argv[5], atoi(argv[6]), atoi(argv[7]));
    fprintf(stderr,
            "usage: opensips-probe sip <host> <port> <timeout-s>\n"
            "       opensips-probe cluster-ready <host> <tcp-port> <mi-port> <wait-s> <file>\n"
            "       opensips-probe mi-until <flag-file> <mi-port> <method> <expect> <tries> <interval-s>\n"
            "       opensips-probe tcp <host> <port> <timeout-s>\n"
            "       opensips-probe route-del-local <host>\n"
            "  <host>: IPv4 address, env:NAME or file:PATH\n");
    return 2;
}

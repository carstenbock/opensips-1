# Stages (helm ADR-0051, ADR-0019):
#
#   builder   compiles OpenSIPS into .deb packages.
#   debug     Debian with every module, opensips-cli and the debug tools.
#             Tagged <version>-debug (and <version>, for charts older than
#             the distroless rollout). For troubleshooting only.
#   init      Debian slim with the tools the charts' entrypoint scripts use
#             (bash, envsubst, mariadb client, wget, ip). Tagged
#             <version>-init; the charts run it as the init container that
#             renders the configuration.
#   tiny      (last stage) FROM scratch: the opensips binary, the modules of
#             one chart (tiny/modules/modules.lst.<VARIANT>), their shared
#             libraries and opensips-probe. Tagged <version>-<variant>; the
#             default image of the charts.
#
# Build with ./build (all variants) or e.g.
#   docker build --target tiny --build-arg VARIANT=pcscf .
ARG FD_IMAGE=freediameter-builder:package-bookworm
FROM ${FD_IMAGE} AS fd-packages

FROM debian:bookworm AS builder
RUN export DEBIAN_FRONTEND=noninteractive
COPY --from=fd-packages /debs/ /tmp/fd-debs/
RUN apt-get update && \
    dpkg -i /tmp/fd-debs/freediameter-common_*.deb \
            /tmp/fd-debs/freediameter-dev_*.deb || true && \
    apt-get -f -y install
#RUN echo 'deb http://deb.debian.org/debian bullseye-backports main' > /etc/apt/sources.list.d/backports.list
RUN apt-get install -y dpkg-dev dnsutils wget software-properties-common net-tools curl lsb-release debhelper sofia-sip-bin flex bison devscripts default-libmysqlclient-dev docbook-xml erlang-dev libconfuse-dev libdb-dev libev-dev libevent-dev libexpat1-dev libgeoip-dev libhiredis-dev libjansson-dev libjson-c-dev libldap2-dev liblua5.1-0-dev libmemcached-dev libmono-2.0-dev libncurses5-dev libpcre3-dev libperl-dev libpq-dev librabbitmq-dev libradcli-dev libreadline-dev libsasl2-dev libsctp-dev libsnmp-dev libsqlite3-dev libsystemd-dev libunistring-dev libxml2-dev pkg-config python3 python3-dev unixodbc-dev uuid-dev xsltproc zlib1g-dev libbson-dev libmaxminddb-dev libmnl-dev libmongoc-dev libphonenumber-dev python-is-python3 python3-dev python-dev-is-python3 ruby-dev libwolfssl-dev libssl-dev musl-dev musl-tools libmicrohttpd-dev librdkafka-dev git-core libjwt-dev libcurl4-openssl-dev libpcre2-dev
COPY . /tmp/build/opensips/
COPY build-deb.sh /usr/sbin/build-deb.sh
RUN /usr/sbin/build-deb.sh

# Probe and hook helper for the shell-less images, statically linked.
FROM builder AS probe
COPY docker/opensips-probe.c /tmp/opensips-probe.c
RUN gcc -O2 -Wall -Wextra -static -o /usr/local/bin/opensips-probe /tmp/opensips-probe.c

FROM debian:bookworm AS debug
COPY --from=fd-packages /debs/ /tmp/fd-debs/
COPY --from=builder /tmp/deb/ /tmp/debs/
RUN export DEBIAN_FRONTEND=noninteractive && \
apt-get update && apt-get install -y wget gnupg2 ca-certificates && \
dpkg -i /tmp/fd-debs/freediameter-common_*.deb \
        /tmp/fd-debs/freediameter-dictionary-rfc4006_*.deb || true && \
apt-get -f -y install && \
dpkg -i /tmp/debs/*.deb || true && \
apt-get update && apt-get -f -y install && \
apt-get -y install gnupg2 ca-certificates iproute2 mariadb-client gettext-base gdb python3 python3-pip sngrep sofia-sip-bin ngrep tcpdump && \
pip3 install --break-system-packages --no-cache-dir opensipscli==0.4.0 opensips==0.1.9 && \
apt-get autoremove --purge -y && \
apt-get clean && \
rm -rf /var/lib/apt/lists/*
COPY docker/sip-ping /usr/local/bin/sip-ping
COPY --from=probe /usr/local/bin/opensips-probe /usr/local/bin/opensips-probe
ENTRYPOINT ["/usr/sbin/opensips", "-F"]

# Init container of the charts: renders the configuration, waits for the
# database and sets up addresses, then exits. OpenSIPS never runs here.
FROM debian:bookworm-slim AS init
RUN export DEBIAN_FRONTEND=noninteractive && \
apt-get update && \
apt-get install -y --no-install-recommends gettext-base mariadb-client-core iproute2 wget ca-certificates && \
apt-get clean && \
rm -rf /var/lib/apt/lists/*
ENTRYPOINT ["/bin/bash"]

# File list of one tiny variant, from the installed packages of the debug
# stage (tiny/make_min_archive.sh).
FROM debug AS minimize
ARG VARIANT=pcscf
COPY tiny/make_min_archive.sh /tmp/opensips/make_min_archive.sh
COPY tiny/modules/modules.lst.${VARIANT} /tmp/modules.lst
# The script leaves opensips_img.tar.gz in the working directory, which
# must not be /tmp (it cleans /tmp up at the end).
RUN cd / && /bin/bash /tmp/opensips/make_min_archive.sh && \
    mkdir /tmp/build_image && tar xzf /opensips_img.tar.gz -C /tmp/build_image

FROM scratch AS tiny
COPY --from=minimize /tmp/build_image /
ENTRYPOINT ["/usr/sbin/opensips", "-F"]

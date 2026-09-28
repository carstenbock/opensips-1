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

FROM debian:bookworm
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
ENTRYPOINT ["/usr/sbin/opensips", "-F"]

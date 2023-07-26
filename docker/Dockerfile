# A docker file for scripts/make/build-docker.sh.

FROM alpine:3.18

ARG BUILD_DATE
ARG VERSION
ARG VCS_REF

LABEL\
	maintainer="AdGuard Team <devteam@adguard.com>" \
	org.opencontainers.image.authors="AdGuard Team <devteam@adguard.com>" \
	org.opencontainers.image.created=$BUILD_DATE \
	org.opencontainers.image.description="Simple DNS proxy with DoH, DoT, DoQ and DNSCrypt support" \
	org.opencontainers.image.documentation="https://github.com/AdguardTeam/dnsproxy" \
	org.opencontainers.image.licenses="Apache-2.0" \
	org.opencontainers.image.revision=$VCS_REF \
	org.opencontainers.image.source="https://github.com/AdguardTeam/dnsproxy" \
	org.opencontainers.image.title="dnsproxy" \
	org.opencontainers.image.url="https://github.com/AdguardTeam/dnsproxy" \
	org.opencontainers.image.vendor="AdGuard" \
	org.opencontainers.image.version=$VERSION

# Update certificates.
RUN apk --no-cache add ca-certificates libcap tzdata && \
	mkdir -p /opt/dnsproxy && chown -R nobody: /opt/dnsproxy

ARG DIST_DIR
ARG TARGETARCH
ARG TARGETOS
ARG TARGETVARIANT

COPY --chown=nobody:nogroup\
	./${DIST_DIR}/docker/dnsproxy_${TARGETOS}_${TARGETARCH}_${TARGETVARIANT}\
	/opt/dnsproxy/dnsproxy
COPY --chown=nobody:nogroup\
    ./${DIST_DIR}/docker/config.yaml\
    /opt/dnsproxy/config.yaml

RUN setcap 'cap_net_bind_service=+eip' /opt/dnsproxy/dnsproxy

# 53     : TCP, UDP : DNS
# 80     : TCP      : HTTP
# 443    : TCP, UDP : HTTPS, DNS-over-HTTPS (incl. HTTP/3), DNSCrypt (main)
# 853    : TCP, UDP : DNS-over-TLS, DNS-over-QUIC
# 5443   : TCP, UDP : DNSCrypt (alt)
# 6060   : TCP      : HTTP (pprof)
EXPOSE 53/tcp 53/udp \
       80/tcp \
       443/tcp 443/udp \
       853/tcp 853/udp \
       5443/tcp 5443/udp \
       6060/tcp

WORKDIR /opt/dnsproxy

ENTRYPOINT ["/opt/dnsproxy/dnsproxy"]
CMD ["--config-path=/opt/dnsproxy/config.yaml"]

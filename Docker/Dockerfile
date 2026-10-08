FROM golang:1.14-alpine as builder

RUN apk --update --no-cache add \
    build-base \
    git \
  && rm -rf /tmp/* /var/cache/apk/*

WORKDIR ~
RUN git clone https://github.com/AdguardTeam/dnsproxy

WORKDIR dnsproxy/

RUN go build -mod=vendor -v

FROM alpine:3.12
LABEL maintainer="coolquasar@gmail.com"

RUN apk update && \
    apk add bash supervisor certbot procps net-tools && \
    rm -rf /tmp/* /var/cache/apk/*

COPY --from=builder /go/~/dnsproxy/dnsproxy /usr/bin

COPY supervisord.conf /etc/supervisor/conf.d/supervisord.conf

COPY letsencrypt-wrapper.sh /srv/
COPY dnsproxy.sh /srv/
COPY start.sh /srv/

VOLUME ["/var/log", "/etc/letsencrypt"]

EXPOSE "80"
EXPOSE "443"
EXPOSE "784"/udp
EXPOSE "853"

ENTRYPOINT ["/srv/start.sh"]

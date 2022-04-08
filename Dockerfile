# syntax=docker/dockerfile:1
FROM --platform=$BUILDPLATFORM golang:1.17 as build
ARG TARGETPLATFORM
ARG BUILDPLATFORM

WORKDIR /go/src/dnsproxy/

COPY . .

RUN set -e \
    && echo "Running on $BUILDPLATFORM, building for $TARGETPLATFORM" \
    && apt-get update \
    && apt-get install --no-install-recommends -y ruby \
    && ruby docker-env.rb

FROM --platform=$TARGETPLATFORM busybox:1.35
COPY --from=build /go/src/dnsproxy/dnsproxy /usr/local/bin/dnsproxy

WORKDIR /root

EXPOSE 53/udp
EXPOSE 443
EXPOSE 853

CMD ["dnsproxy", "-u", "1.1.1.1:53", "-u", "1.0.0.1:53", "-s", "443", "-p", "53", "-t", "853" ]

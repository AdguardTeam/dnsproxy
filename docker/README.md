# DNS Proxy

A simple DNS proxy server that supports all existing DNS protocols including
`DNS-over-TLS`, `DNS-over-HTTPS`, `DNSCrypt`, and `DNS-over-QUIC`. Moreover,
it can work as a `DNS-over-HTTPS`, `DNS-over-TLS` or `DNS-over-QUIC` server.

Learn more about dnsproxy and its full capabilities in
its [Github repo][dnsproxy].

[dnsproxy]: https://github.com/AdguardTeam/dnsproxy

## Quick start

### Pull the Docker image

This command will pull the latest stable version:

```shell
docker pull adguard/dnsproxy
```

### Run the container

Run the container with the default configuration (see `config.yaml.dist` in the
repository) and expose DNS ports.

```shell
docker run --name dnsproxy \
  -p 53:53/tcp -p 53:53/udp \
  adguard/dnsproxy
```

Run the container with command-line args configuration and expose DNS ports.

```shell
docker run --name dnsproxy_google_dns \
  -p 53:53/tcp -p 53:53/udp \
  adguard/dnsproxy \
  -u 8.8.8.8:53
```

Run the container with a configuration file and expose DNS ports.

```shell
docker run --name dnsproxy_google_dns \
  -p 53:53/tcp -p 53:53/udp \
  -v $PWD/config.yaml:/opt/dnsproxy/config.yaml \
  adguard/dnsproxy
```

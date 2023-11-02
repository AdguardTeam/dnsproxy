[![Code Coverage](https://img.shields.io/codecov/c/github/AdguardTeam/dnsproxy/master.svg)](https://codecov.io/github/AdguardTeam/dnsproxy?branch=master)
[![Go Report Card](https://goreportcard.com/badge/github.com/AdguardTeam/dnsproxy)](https://goreportcard.com/report/AdguardTeam/dnsproxy)
[![GolangCI](https://golangci.com/badges/github.com/AdguardTeam/dnsproxy.svg)](https://golangci.com/r/github.com/AdguardTeam/dnsproxy)
[![Go Doc](https://godoc.org/github.com/AdguardTeam/dnsproxy?status.svg)](https://godoc.org/github.com/AdguardTeam/dnsproxy)

# DNS Proxy <!-- omit in toc -->

A simple DNS proxy server that supports all existing DNS protocols including
`DNS-over-TLS`, `DNS-over-HTTPS`, `DNSCrypt`, and `DNS-over-QUIC`. Moreover,
it can work as a `DNS-over-HTTPS`, `DNS-over-TLS` or `DNS-over-QUIC` server.

- [How to install](#how-to-install)
- [How to build](#how-to-build)
- [Usage](#usage)
- [Examples](#examples)
  - [Simple options](#simple-options)
  - [Encrypted upstreams](#encrypted-upstreams)
  - [Encrypted DNS server](#encrypted-dns-server)
  - [Additional features](#additional-features)
  - [DNS64 server](#dns64-server)
  - [Fastest addr + cache-min-ttl](#fastest-addr--cache-min-ttl)
  - [Specifying upstreams for domains](#specifying-upstreams-for-domains)
  - [EDNS Client Subnet](#edns-client-subnet)
  - [Bogus NXDomain](#bogus-nxdomain)

## How to install

There are several options how to install `dnsproxy`.

1. Grab the binary for your device/OS from the [Releases][releases] page.
2. Use the [official Docker image][docker].
3. Build it yourself (see the instruction below).

[releases]: https://github.com/AdguardTeam/dnsproxy/releases
[docker]: https://hub.docker.com/r/adguard/dnsproxy

## How to build

You will need Go v1.20 or later.

```shell
$ make build
```

## Usage

```
Usage:
  dnsproxy [OPTIONS]

Application Options:
      --config-path=               yaml configuration file. Minimal working configuration in config.yaml.dist. Options passed through command line will override the ones from this file.
  -v, --verbose                    Verbose output (optional)
  -o, --output=                    Path to the log file. If not set, write to stdout.
  -l, --listen=                    Listening addresses
  -p, --port=                      Listening ports. Zero value disables TCP and UDP listeners
  -s, --https-port=                Listening ports for DNS-over-HTTPS
  -t, --tls-port=                  Listening ports for DNS-over-TLS
  -q, --quic-port=                 Listening ports for DNS-over-QUIC
  -y, --dnscrypt-port=             Listening ports for DNSCrypt
  -c, --tls-crt=                   Path to a file with the certificate chain
  -k, --tls-key=                   Path to a file with the private key
      --tls-min-version=           Minimum TLS version, for example 1.0
      --tls-max-version=           Maximum TLS version, for example 1.3
      --insecure                   Disable secure TLS certificate validation
  -g, --dnscrypt-config=           Path to a file with DNSCrypt configuration. You can generate one using https://github.com/ameshkov/dnscrypt
      --http3                      Enable HTTP/3 support
  -u, --upstream=                  An upstream to be used (can be specified multiple times). You can also specify path to a file with the list of servers
  -b, --bootstrap=                 Bootstrap DNS for DoH and DoT, can be specified multiple times (default: use system-provided)
  -f, --fallback=                  Fallback resolvers to use when regular ones are unavailable, can be specified multiple times. You can also specify path to a file with the list of servers
      --private-rdns-upstream=     Private DNS upstreams to use for reverse DNS lookups of private addresses, can be specified multiple times
      --all-servers                If specified, parallel queries to all configured upstream servers are enabled
      --fastest-addr               Respond to A or AAAA requests only with the fastest IP address
      --timeout=                   Timeout for outbound DNS queries to remote upstream servers in a human-readable form (default: 10s)
      --cache                      If specified, DNS cache is enabled
      --cache-size=                Cache size (in bytes). Default: 64k
      --cache-min-ttl=             Minimum TTL value for DNS entries, in seconds. Capped at 3600. Artificially extending TTLs should only be done with careful consideration.
      --cache-max-ttl=             Maximum TTL value for DNS entries, in seconds.
      --cache-optimistic           If specified, optimistic DNS cache is enabled
  -r, --ratelimit=                 Ratelimit (requests per second)
      --ratelimit-subnet-len-ipv4= Ratelimit subnet length for IPv4. (default: 24)
      --ratelimit-subnet-len-ipv6= Ratelimit subnet length for IPv6. (default: 64)
      --refuse-any                 If specified, refuse ANY requests
      --edns                       Use EDNS Client Subnet extension
      --edns-addr=                 Send EDNS Client Address
      --dns64                      If specified, dnsproxy will act as a DNS64 server
      --dns64-prefix=              Prefix used to handle DNS64. If not specified, dnsproxy uses the 'Well-Known Prefix' 64:ff9b::.  Can be specified multiple times
      --https-server-name=         Set the Server header for the responses from the HTTPS server. (default: dnsproxy)
      --https-userinfo=            If set, all DoH queries are required to have this basic authentication information.
      --ipv6-disabled              If specified, all AAAA requests will be replied with NoError RCode and empty answer
      --bogus-nxdomain=            Transform the responses containing at least a single IP that matches specified addresses and CIDRs into NXDOMAIN.  Can be specified multiple times.
      --udp-buf-size=              Set the size of the UDP buffer in bytes. A value <= 0 will use the system default.
      --max-go-routines=           Set the maximum number of go routines. A value <= 0 will not not set a maximum.
      --pprof                      If present, exposes pprof information on localhost:6060.
      --version                    Prints the program version

Help Options:
  -h, --help                       Show this help message
```

## Examples

### Simple options

Runs a DNS proxy on `0.0.0.0:53` with a single upstream - Google DNS.
```shell
./dnsproxy -u 8.8.8.8:53
```

The same proxy with verbose logging enabled writing it to the file `log.txt`.
```shell
./dnsproxy -u 8.8.8.8:53 -v -o log.txt
```

Runs a DNS proxy on `127.0.0.1:5353` with multiple upstreams.
```shell
./dnsproxy -l 127.0.0.1 -p 5353 -u 8.8.8.8:53 -u 1.1.1.1:53
```

Listen on multiple interfaces and ports:
```shell
./dnsproxy -l 127.0.0.1 -l 192.168.1.10 -p 5353 -p 5354 -u 1.1.1.1
```

The plain DNS upstream server may be specified in several ways:

 -  With a plain IP address:
    ```shell
    ./dnsproxy -l 127.0.0.1 -u 8.8.8.8:53
    ```

 -  With a hostname or plain IP address and the `udp://` scheme:
    ```shell
    ./dnsproxy -l 127.0.0.1 -u udp://dns.google -u udp://1.1.1.1
    ```

 -  With a hostname or plain IP address and the `tcp://` scheme to force using
    TCP:
    ```shell
    ./dnsproxy -l 127.0.0.1 -u tcp://dns.google -u tcp://1.1.1.1
    ```

### Encrypted upstreams

DNS-over-TLS upstream:
```shell
./dnsproxy -u tls://dns.adguard.com
```

DNS-over-HTTPS upstream with specified bootstrap DNS:
```shell
./dnsproxy -u https://dns.adguard.com/dns-query -b 1.1.1.1:53
```

DNS-over-QUIC upstream:
```shell
./dnsproxy -u quic://dns.adguard.com
```

DNS-over-HTTPS upstream with enabled HTTP/3 support (chooses it if it's faster):
```shell
./dnsproxy -u https://dns.google/dns-query --http3
```

DNS-over-HTTPS upstream with forced HTTP/3 (no fallback to other protocol):
```shell
./dnsproxy -u h3://dns.google/dns-query
```

DNSCrypt upstream ([DNS Stamp](https://dnscrypt.info/stamps) of AdGuard DNS):
```shell
./dnsproxy -u sdns://AQIAAAAAAAAAFDE3Ni4xMDMuMTMwLjEzMDo1NDQzINErR_JS3PLCu_iZEIbq95zkSV2LFsigxDIuUso_OQhzIjIuZG5zY3J5cHQuZGVmYXVsdC5uczEuYWRndWFyZC5jb20
```

DNS-over-HTTPS upstream ([DNS Stamp](https://dnscrypt.info/stamps) of Cloudflare DNS):
```shell
./dnsproxy -u sdns://AgcAAAAAAAAABzEuMC4wLjGgENk8mGSlIfMGXMOlIlCcKvq7AVgcrZxtjon911-ep0cg63Ul-I8NlFj4GplQGb_TTLiczclX57DvMV8Q-JdjgRgSZG5zLmNsb3VkZmxhcmUuY29tCi9kbnMtcXVlcnk
```

DNS-over-TLS upstream with two fallback servers (to be used when the main upstream is not available):
```shell
./dnsproxy -u tls://dns.adguard.com -f 8.8.8.8:53 -f 1.1.1.1:53
```

### Encrypted DNS server

Runs a DNS-over-TLS proxy on `127.0.0.1:853`.
```shell
./dnsproxy -l 127.0.0.1 --tls-port=853 --tls-crt=example.crt --tls-key=example.key -u 8.8.8.8:53 -p 0
```

Runs a DNS-over-HTTPS proxy on `127.0.0.1:443`.
```shell
./dnsproxy -l 127.0.0.1 --https-port=443 --tls-crt=example.crt --tls-key=example.key -u 8.8.8.8:53 -p 0
```

Runs a DNS-over-HTTPS proxy on `127.0.0.1:443` with HTTP/3 support.
```shell
./dnsproxy -l 127.0.0.1 --https-port=443 --http3 --tls-crt=example.crt --tls-key=example.key -u 8.8.8.8:53 -p 0
```

Runs a DNS-over-QUIC proxy on `127.0.0.1:853`.
```shell
./dnsproxy -l 127.0.0.1 --quic-port=853 --tls-crt=example.crt --tls-key=example.key -u 8.8.8.8:53 -p 0
```

Runs a DNSCrypt proxy on `127.0.0.1:443`.

```shell
./dnsproxy -l 127.0.0.1 --dnscrypt-config=./dnscrypt-config.yaml --dnscrypt-port=443 --upstream=8.8.8.8:53 -p 0
```

> Please note that in order to run a DNSCrypt proxy, you need to obtain DNSCrypt configuration first. You can use https://github.com/ameshkov/dnscrypt command-line tool to do that with a command like this `./dnscrypt generate --provider-name=2.dnscrypt-cert.example.org --out=dnscrypt-config.yaml`

### Additional features

Runs a DNS proxy on `0.0.0.0:53` with rate limit set to `10 rps`, enabled DNS cache, and that refuses type=ANY requests.
```shell
./dnsproxy -u 8.8.8.8:53 -r 10 --cache --refuse-any
```

Runs a DNS proxy on 127.0.0.1:5353 with multiple upstreams and enable parallel queries to all configured upstream servers.
```shell
./dnsproxy -l 127.0.0.1 -p 5353 -u 8.8.8.8:53 -u 1.1.1.1:53 -u tls://dns.adguard.com --all-servers
```

Loads upstreams list from a file.
```shell
./dnsproxy -l 127.0.0.1 -p 5353 -u ./upstreams.txt
```

### DNS64 server

`dnsproxy` is capable of working as a DNS64 server.

> **What is DNS64/NAT64**
> This is a mechanism of providing IPv6 access to IPv4. Using a NAT64 gateway
> with IPv4-IPv6 translation capability lets IPv6-only clients connect to
> IPv4-only services via synthetic IPv6 addresses starting with a prefix that
> routes them to the NAT64 gateway. DNS64 is a DNS service that returns AAAA
> records with these synthetic IPv6 addresses for IPv4-only destinations
> (with A but not AAAA records in the DNS). This lets IPv6-only clients use
> NAT64 gateways without any other configuration.

See also [RFC 6147](https://datatracker.ietf.org/doc/html/rfc6147).

Enables DNS64 with the default [Well-Known Prefix][wkp]:
```shell
./dnsproxy -l 127.0.0.1 -p 5353 -u 8.8.8.8 --private-rdns-upstream=127.0.0.1  --dns64
```

You can also specify any number of custom DNS64 prefixes:
```shell
./dnsproxy -l 127.0.0.1 -p 5353 -u 8.8.8.8 --private-rdns-upstream=127.0.0.1 --dns64 --dns64-prefix=64:ffff:: --dns64-prefix=32:ffff::
```

Note that only the first specified prefix will be used for synthesis.

PTR queries for addresses within the specified ranges or the
[Well-Known one][wkp] could only be answered with locally appropriate data, so
dnsproxy will route those to the local upstream servers.  Those should be
specified if DNS64 is enabled.

[wkp]: https://datatracker.ietf.org/doc/html/rfc6052#section-2.1

### Fastest addr + cache-min-ttl

This option would be useful to the users with problematic network connection.
In this mode, `dnsproxy` would detect the fastest IP address among all that were returned,
and it will return only it.

Additionally, for those with problematic network connection, it makes sense to override `cache-min-ttl`.
In this case, `dnsproxy` will make sure that DNS responses are cached for at least the specified amount of time.

It makes sense to run it with multiple upstream servers only.

Run a DNS proxy with two upstreams, min-TTL set to 10 minutes, fastest address detection is enabled:
```
./dnsproxy -u 8.8.8.8 -u 1.1.1.1 --cache --cache-min-ttl=600 --fastest-addr
```

 who run `dnsproxy` with multiple upstreams

### Specifying upstreams for domains

You can specify upstreams that will be used for a specific domain(s). We use the dnsmasq-like syntax (see `--server` description [here](http://www.thekelleys.org.uk/dnsmasq/docs/dnsmasq-man.html)).

**Syntax:** `[/[domain1][/../domainN]/]upstreamString`

Where `upstreamString` is one or many upstreams separated by space (e.g. `1.1.1.1` or `1.1.1.1 2.2.2.2`).

If one or more domains are specified, that upstream (`upstreamString`) is used only for those domains. Usually, it is used for private nameservers. For instance, if you have a nameserver on your network which deals with `xxx.internal.local` at `192.168.0.1` then you can specify `[/internal.local/]192.168.0.1`, and dnsproxy will send all queries to that nameserver. Everything else will be sent to the default upstreams (which are mandatory!).

1. An empty domain specification, // has the special meaning of "unqualified names only" ie names without any dots in them.
2. More specific domains take precedence over less specific domains, so: `--upstream=[/host.com/]1.2.3.4 --upstream=[/www.host.com/]2.3.4.5` will send queries for *.host.com to 1.2.3.4, except *.www.host.com, which will go to 2.3.4.5
3. The special server address `#` means, "use the standard servers", so: `--upstream=[/host.com/]1.2.3.4 --upstream=[/www.host.com/]#` will send queries for \*.host.com to 1.2.3.4, except \*.www.host.com which will be forwarded as usual.
4. The wildcard `*` has special meaning of "any sub-domain", so: `--upstream=[/*.host.com/]1.2.3.4` will send queries for \*.host.com to 1.2.3.4, but host.com will be forwarded to default upstreams.

**Examples**

Sends queries for `*.local` domains to `192.168.0.1:53`. Other queries are sent to `8.8.8.8:53`.
```
./dnsproxy -u 8.8.8.8:53 -u [/local/]192.168.0.1:53
```

Sends queries for `*.host.com` to `1.1.1.1:53` except for `*.maps.host.com` which are sent to `8.8.8.8:53` (along with other queries).
```
./dnsproxy -u 8.8.8.8:53 -u [/host.com/]1.1.1.1:53 -u [/maps.host.com/]#
```

Sends queries for `*.host.com` to `1.1.1.1:53` except for `host.com` which is sent to `8.8.8.8:53` (along with other queries).
```
./dnsproxy -u 8.8.8.8:53 -u [/*.host.com/]1.1.1.1:53
```

### EDNS Client Subnet

To enable support for EDNS Client Subnet extension you should run dnsproxy with `--edns` flag:

```
./dnsproxy -u 8.8.8.8:53 --edns
```

Now if you connect to the proxy from the Internet - it will pass through your original IP address's prefix to the upstream server.  This way the upstream server may respond with IP addresses of the servers that are located near you to minimize latency.

If you want to use EDNS CS feature when you're connecting to the proxy from a local network, you need to set `--edns-addr=PUBLIC_IP` argument:

```
./dnsproxy -u 8.8.8.8:53 --edns --edns-addr=72.72.72.72
```

Now even if your IP address is 192.168.0.1 and it's not a public IP, the proxy will pass through 72.72.72.72 to the upstream server.

### Bogus NXDomain

This option is similar to dnsmasq `bogus-nxdomain`.  `dnsproxy` will transform
responses that contain at least a single IP address which is also specified by
the option into `NXDOMAIN`. Can be specified multiple times.

In the example below, we use AdGuard DNS server that returns `0.0.0.0` for
blocked domains, and transform them to `NXDOMAIN`.

```
./dnsproxy -u 94.140.14.14:53 --bogus-nxdomain=0.0.0.0
```

CIDR ranges are supported as well.  The following will respond with `NXDOMAIN`
instead of responses containing any IP from `192.168.0.0`-`192.168.255.255`:

```
./dnsproxy -u 192.168.0.15:53 --bogus-nxdomain=192.168.0.0/16
```

### Basic Auth for DoH

By setting the `--https-userinfo` option you can use `dnsproxy` as a DoH proxy
with basic authentication requirements.

For example:

```sh
./dnsproxy\
    --https-port='443'\
    --https-userinfo='user:p4ssw0rd'\
    --tls-crt='…/my.crt'\
    --tls-key='…/my.key'\
    -u '94.140.14.14:53'
```

This configuration will only allow DoH queries that contain an `Authorization`
header containing the BasicAuth credentials for user `user` with password
`p4ssw0rd`.

Add `-p 0` if you also want to disable plain-DNS handling and make `dnsproxy`
only serve DoH with Basic Auth checking.

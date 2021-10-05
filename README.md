[![Code Coverage](https://img.shields.io/codecov/c/github/AdguardTeam/dnsproxy/master.svg)](https://codecov.io/github/AdguardTeam/dnsproxy?branch=master)
[![Go Report Card](https://goreportcard.com/badge/github.com/AdguardTeam/dnsproxy)](https://goreportcard.com/report/AdguardTeam/dnsproxy)
[![GolangCI](https://golangci.com/badges/github.com/AdguardTeam/dnsproxy.svg)](https://golangci.com/r/github.com/AdguardTeam/dnsproxy)
[![Go Doc](https://godoc.org/github.com/AdguardTeam/dnsproxy?status.svg)](https://godoc.org/github.com/AdguardTeam/dnsproxy)

# DNS Proxy <!-- omit in toc -->

A simple DNS proxy server that supports all existing DNS protocols including `DNS-over-TLS`, `DNS-over-HTTPS`, `DNSCrypt`, and `DNS-over-QUIC`. Moreover, it can work as a `DNS-over-HTTPS`, `DNS-over-TLS` or `DNS-over-QUIC` server.

> Note that `DNS-over-QUIC` support is experimental, don't use it in production.
> Note that `DoH/DoT/DoQ` client authentication support is experimental, only DoH authentication has been tested

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

## How to build

You will need go v1.15 or later.

```shell
$ go build -mod=vendor
```

## Usage

```
Usage:
  dnsproxy [OPTIONS]

Application Options:
  -v, --verbose          Verbose output (optional)
  -o, --output=          Path to the log file. If not set, write to stdout.
  -l, --listen=          Listening addresses (default: 0.0.0.0)
  -p, --port=            Listening ports. Zero value disables TCP and UDP listeners (default: 53)
  -s, --https-port=      Listening ports for DNS-over-HTTPS
  -t, --tls-port=        Listening ports for DNS-over-TLS
  -q, --quic-port=       Listening ports for DNS-over-QUIC
  -y, --dnscrypt-port=   Listening ports for DNSCrypt
  -c, --tls-crt=         Path to a file with the certificate chain
  -k, --tls-key=         Path to a file with the private key
      --tls-min-version= Minimum TLS version, for example 1.0
      --tls-max-version= Maximum TLS version, for example 1.3
      --insecure         Disable secure TLS certificate validation
  -g, --dnscrypt-config= Path to a file with DNSCrypt configuration. You can generate one using
                         https://github.com/ameshkov/dnscrypt
  -u, --upstream=        An upstream to be used (can be specified multiple times). You can also specify path to a file with
                         the list of servers
  -b, --bootstrap=       Bootstrap DNS for DoH and DoT, can be specified multiple times (default: 8.8.8.8:53)
  -f, --fallback=        Fallback resolvers to use when regular ones are unavailable, can be specified multiple times. You can
                         also specify path to a file with the list of servers
      --all-servers      If specified, parallel queries to all configured upstream servers are enabled
      --fastest-addr     Respond to A or AAAA requests only with the fastest IP address
      --cache            If specified, DNS cache is enabled
      --cache-size=      Cache size (in bytes). Default: 64k
      --cache-min-ttl=   Minimum TTL value for DNS entries, in seconds. Capped at 3600. Artificially extending TTLs should
                         only be done with careful consideration.
      --cache-max-ttl=   Maximum TTL value for DNS entries, in seconds.
  -r, --ratelimit=       Ratelimit (requests per second) (default: 0)
      --refuse-any       If specified, refuse ANY requests
      --edns             Use EDNS Client Subnet extension
      --edns-addr=       Send EDNS Client Address
      --dns64            If specified, dnsproxy will act as a DNS64 server
      --dns64-prefix=    If specified, this is the DNS64 prefix dnsproxy will be using when it works as a DNS64 server. If not
                         specified, dnsproxy uses the 'Well-Known Prefix' 64:ff9b::
      --ipv6-disabled    If specified, all AAAA requests will be replied with NoError RCode and empty answer
      --bogus-nxdomain=  Transform responses that contain at least one of the given IP addresses into NXDOMAIN. Can be
                         specified multiple times.
      --udp-buf-size=    Set the size of the UDP buffer in bytes. A value <= 0 will use the system default. (default: 0)
      --max-go-routines= Set the maximum number of go routines. A value <= 0 will not not set a maximum. (default: 0)
      --version          Prints the program version
      --a-tls-crt=       Path to the file to the tls certificate used to DoH/DoT/DoQ Client when client-authentication is enabled
      --a-tls-key=       Path to the file to the tls key used to DoH/DoT/DoQ Client when client-authentication is enabled

Help Options:
  -h, --help             Show this help message
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

### Encrypted upstreams

DNS-over-TLS upstream:
```shell
./dnsproxy -u tls://dns.adguard.com
```

DNS-over-HTTPS upstream with specified bootstrap DNS:
```shell
./dnsproxy -u https://dns.adguard.com/dns-query -b 1.1.1.1:53
```

DNS-over-HTTPS upstream with specified bootstrap DNS and Client authentication:
```shell
./dnsproxy -l 127.0.0.1 -u https://dns.plido.net/dns-query --a-tls-crt=/home/.../dohclient.cert.pem --a-tls-key=/home/.../dohclient.key.pem -b 1.1.1.1:53
```

DNS-over-QUIC upstream:
```shell
./dnsproxy -u quic://dns.adguard.com
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

Runs a DNS-over-QUIC proxy on `127.0.0.1:8853`.
```shell
./dnsproxy -l 127.0.0.1 --quic-port=8853 --tls-crt=example.crt --tls-key=example.key -u 8.8.8.8:53 -p 0
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

Enables DNS64 with the default "Well-Known Prefix" `64:ff9b::/96`:
```shell
./dnsproxy -l 127.0.0.1 -p 5353 -u 8.8.8.8 --dns64
```

You can also specify a custom DNS64 prefix:
```shell
./dnsproxy -l 127.0.0.1 -p 5353 -u 8.8.8.8 --dns64 --dns64-prefix=64:ffff::
```

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

If one or more domains are specified, that upstream (`upstreamString`) is used only for those domains. Usually, it is used for private nameservers. For instance, if you have a nameserver on your network which deals with `xxx.internal.local` at `192.168.0.1` then you can specify `[/internal.local/]192.168.0.1`, and dnsproxy will send all queries to that nameserver. Everything else will be sent to the default upstreams (which are mandatory!).

1. An empty domain specification, // has the special meaning of "unqualified names only" ie names without any dots in them.
2. More specific domains take precedence over less specific domains, so: `--upstream=[/host.com/]1.2.3.4 --upstream=[/www.host.com/]2.3.4.5` will send queries for *.host.com to 1.2.3.4, except *.www.host.com, which will go to 2.3.4.5
3. The special server address '#' means, "use the standard servers", so: `--upstream=[/host.com/]1.2.3.4 --upstream=[/www.host.com/]#` will send queries for *.host.com to 1.2.3.4, except *.www.host.com which will be forwarded as usual.

**Examples**

Sends queries for `*.local` domains to `192.168.0.1:53`. Other queries are sent to `8.8.8.8:53`.
```
./dnsproxy -u 8.8.8.8:53 -u [/local/]192.168.0.1:53
```

Sends queries for `*.host.com` to `1.1.1.1:53` except for `*.maps.host.com` which are sent to `8.8.8.8:53` (as long as other queries).
```
./dnsproxy -u 8.8.8.8:53 -u [/host.com/]1.1.1.1:53 -u [/maps.host.com/]#`
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

This option is similar to dnsmasq `bogus-nxdomain`. If specified, `dnsproxy` transforms responses that contain at least one of the given IP addresses into `NXDOMAIN`. Can be specified multiple times.

In the example below, we use AdGuard DNS server that returns `0.0.0.0` for blocked domains, and transform them to `NXDOMAIN`.

```
./dnsproxy -u 94.140.14.14:53 --bogus-nxdomain=0.0.0.0
```

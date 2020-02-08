[![Build Status](https://travis-ci.com/AdguardTeam/dnsproxy.svg?branch=master)](https://travis-ci.com/AdguardTeam/dnsproxy)
[![Code Coverage](https://img.shields.io/codecov/c/github/AdguardTeam/dnsproxy/master.svg)](https://codecov.io/github/AdguardTeam/dnsproxy?branch=master)
[![Go Report Card](https://goreportcard.com/badge/github.com/AdguardTeam/dnsproxy)](https://goreportcard.com/report/AdguardTeam/dnsproxy)
[![GolangCI](https://golangci.com/badges/github.com/AdguardTeam/dnsproxy.svg)](https://golangci.com/r/github.com/AdguardTeam/dnsproxy)
[![Go Doc](https://godoc.org/github.com/AdguardTeam/dnsproxy?status.svg)](https://godoc.org/github.com/AdguardTeam/dnsproxy)

# DNS Proxy

A simple DNS proxy server that supports all existing DNS protocols including `DNS-over-TLS`, `DNS-over-HTTPS`, and `DNSCrypt`.

Moreover, it can work as a `DNS-over-HTTPS` and/or `DNS-over-TLS` server.

## How to build

You will need go v1.13 or later.

```
$ go build
```

## Usage

```
Usage:
  dnsproxy [OPTIONS]

Application Options:
  -v, --verbose        Verbose output (optional)
  -o, --output=        Path to the log file. If not set, write to stdout.
  -l, --listen=        Listen address (default: 0.0.0.0)
  -p, --port=          Listen port. Zero value disables TCP and UDP listeners (default: 53)
  -h, --https-port=    Listen port for DNS-over-HTTPS (default: 0)
  -t, --tls-port=      Listen port for DNS-over-TLS (default: 0)
  -c, --tls-crt=       Path to a file with the certificate chain
  -k, --tls-key=       Path to a file with the private key
  -b, --bootstrap=     Bootstrap DNS for DoH and DoT, can be specified multiple times (default: 8.8.8.8:53)
  -r, --ratelimit=     Ratelimit (requests per second) (default: 0)
  -z, --cache          If specified, DNS cache is enabled
  -e  --cache-size=    Cache size (in bytes). Default: 65536
  -a, --refuse-any     If specified, refuse ANY requests
  -u, --upstream=      An upstream to be used (can be specified multiple times)
  -f, --fallback=      Fallback resolvers to use when regular ones are unavailable, can be specified multiple times
  -s, --all-servers    Use parallel queries to speed up resolving by querying all upstream servers simultaneously
  -d, --ipv6-disabled  Disable IPv6. All AAAA requests will be replied with No Error response code and empty answer 
      --edns           Use EDNS Client Subnet extension
      --edns-addr=     Send EDNS Client Address
      --cache-min-ttl= Minimum TTL value for DNS entries, in seconds.
      --cache-max-ttl= Maximum TTL value for DNS entries, in seconds.

Help Options:
  -h, --help        Show this help message
  --version         Print DNS proxy version
```

## Examples

### Simple options

Runs a DNS proxy on `0.0.0.0:53` with a single upstream - Google DNS.
```
./dnsproxy -u 8.8.8.8:53
```

The same proxy with verbose logging enabled writing it to the file `log.txt`. 
```
./dnsproxy -u 8.8.8.8:53 -v -o log.txt
```

Runs a DNS proxy on `127.0.0.1:5353` with multiple upstreams.
```
./dnsproxy -l 127.0.0.1 -p 5353 -u 8.8.8.8:53 -u 1.1.1.1:53
```

### Encrypted upstreams

DNS-over-TLS upstream:
```
./dnsproxy -u tls://dns.adguard.com
```

DNS-over-HTTPS upstream with specified bootstrap DNS:
```
./dnsproxy -u https://dns.adguard.com/dns-query -b 1.1.1.1:53
```

DNSCrypt upstream ([DNS Stamp](https://dnscrypt.info/stamps) of AdGuard DNS):
```
./dnsproxy -u sdns://AQIAAAAAAAAAFDE3Ni4xMDMuMTMwLjEzMDo1NDQzINErR_JS3PLCu_iZEIbq95zkSV2LFsigxDIuUso_OQhzIjIuZG5zY3J5cHQuZGVmYXVsdC5uczEuYWRndWFyZC5jb20
```

DNS-over-HTTPS upstream ([DNS Stamp](https://dnscrypt.info/stamps) of Cloudflare DNS):
```
./dnsproxy -u sdns://AgcAAAAAAAAABzEuMC4wLjGgENk8mGSlIfMGXMOlIlCcKvq7AVgcrZxtjon911-ep0cg63Ul-I8NlFj4GplQGb_TTLiczclX57DvMV8Q-JdjgRgSZG5zLmNsb3VkZmxhcmUuY29tCi9kbnMtcXVlcnk
```

DNS-over-TLS upstream with two fallback servers (to be used when the main upstream is not available):
```
./dnsproxy -u tls://dns.adguard.com -f 8.8.8.8:53 -f 1.1.1.1:53
```

### Encrypted DNS server

Runs a DNS-over-TLS proxy on `127.0.0.1:853`.
```
./dnsproxy -l 127.0.0.1 --tls-port=853 --tls-crt=example.crt --tls-key=example.key -u 8.8.8.8:53 -p 0 
```

Runs a DNS-over-HTTPS proxy on `127.0.0.1:443`.
```
./dnsproxy -l 127.0.0.1 --https-port=443 --tls-crt=example.crt --tls-key=example.key -u 8.8.8.8:53 -p 0 
```

### Additional features

Runs a DNS proxy on `0.0.0.0:53` with rate limit set to `10 rps`, enabled DNS cache, and that refuses type=ANY requests.
```
./dnsproxy -u 8.8.8.8:53 -r 10 --cache --refuse-any
```

Runs a DNS proxy on 127.0.0.1:5353 with multiple upstreams and enable parallel queries to all configured upstream servers  
```
./dnsproxy -l 127.0.0.1 -p 5353 -u 8.8.8.8:53 -u 1.1.1.1:53 -u tls://dns.adguard.com --all-servers
```

### Specifying upstreams for domains

You can specify upstreams that will be used for a specific domain(s). We use the dnsmasq-like syntax (see `--server` description [here](http://www.thekelleys.org.uk/dnsmasq/docs/dnsmasq-man.html)).

**Syntax:** `[/[domain1][/../domainN]/]upstreamString`

If one or more domains are specified, that upstream (`upstreamString`) is used only for those domains. Usually, it is used for private nameservers. For instance, if you have a nameserver on your network which deals with `xxx.internal.local` at `192.168.0.1` then you can specify `[/internal.local/]192.168.0.1`, and dnsproxy will send all queries to that nameserver. Everything else will be sent to the default upstreams (which are mandatory!).

1. An empty domain specification, // has the special meaning of "unqualified names only" ie names without any dots in them.
2. More specific domains take precedence over less specific domains, so: `--upstream=[/host.com/]1.2.3.4 --upstream=[/www.host.com/]2.3.4.5` will send queries for *.host.com to 1.2.3.4, except *.www.host.com, which will go to 2.3.4.5
3. The special server address '#' means, "use the standard servers", so: `--upstream=[/host.com/]1.2.3.4 --upstream=[/www.host.com/]#` will send queries for *.host.com to 1.2.3.4, except *.www.host.com which will be forwarded as usual.

#### Examples

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


### TODO

* [x] Configure fallback resolver
* [x] Listen on TCP/TLS as well
* [X] gomobile/gobind builds
* [X] Listen on HTTPS
* [ ] DNSSEC validation
* [ ] 1.0.0 release

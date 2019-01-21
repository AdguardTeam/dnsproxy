[![Build Status](https://travis-ci.org/AdguardTeam/dnsproxy.svg?branch=master)](https://travis-ci.org/AdguardTeam/dnsproxy)
[![Code Coverage](https://img.shields.io/codecov/c/github/AdguardTeam/dnsproxy/master.svg)](https://codecov.io/github/AdguardTeam/dnsproxy?branch=master)
[![Go Report Card](https://goreportcard.com/badge/github.com/AdguardTeam/dnsproxy)](https://goreportcard.com/report/AdguardTeam/dnsproxy)
[![Go Doc](https://godoc.org/github.com/AdguardTeam/dnsproxy?status.svg)](https://godoc.org/github.com/AdguardTeam/dnsproxy)

# DNS Proxy

A simple DNS proxy server that supports all existing DNS protocols including `DNS-over-TLS`, `DNS-over-HTTPS`, and `DNSCrypt`.

Moreover, it can work as a `DNS-over-HTTPS` and/or `DNS-over-TLS` server.

## How to build

You will need go v1.11 or later.

```
$ go build
```

## Usage

```
Usage:
  dnsproxy [OPTIONS]

Application Options:
  -v, --verbose     Verbose output (optional)
  -o, --output=     Path to the log file. If not set, write to stdout.
  -l, --listen=     Listen address (default: 0.0.0.0)
  -p, --port=       Listen port (default: 53)
  -h, --https-port= Listen port for DNS-over-HTTPS (default: 0)
  -t, --tls-port=   Listen port for DNS-over-TLS (default: 0)
  -c, --tls-crt=    Path to a file with the certificate chain
  -k, --tls-key=    Path to a file with the private key
  -n, --tls-name=   HTTPS/TLS server name
  -b, --bootstrap=  Bootstrap DNS for DoH and DoT (default: 8.8.8.8:53)
  -r, --ratelimit=  Ratelimit (requests per second) (default: 0)
  -z, --cache       If specified, DNS cache is enabled
  -a, --refuse-any  If specified, refuse ANY requests
  -u, --upstream=   An upstream to be used (can be specified multiple times)
  -f, --fallback=   A fallback resolver to use when regular ones aren't available

Help Options:
  -h, --help        Show this help message
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

DNS-over-HTTPS upstream:
```
./dnsproxy -u https://dns.adguard.com/dns-query
```

DNSCrypt upstream ([DNS Stamp](https://dnscrypt.info/stamps) of AdGuard DNS):
```
./dnsproxy -u sdns://AQIAAAAAAAAAFDE3Ni4xMDMuMTMwLjEzMDo1NDQzINErR_JS3PLCu_iZEIbq95zkSV2LFsigxDIuUso_OQhzIjIuZG5zY3J5cHQuZGVmYXVsdC5uczEuYWRndWFyZC5jb20
```

DNS-over-HTTPS upstream ([DNS Stamp](https://dnscrypt.info/stamps) of Cloudflare DNS):
```
./dnsproxy -u sdns://AgcAAAAAAAAABzEuMC4wLjGgENk8mGSlIfMGXMOlIlCcKvq7AVgcrZxtjon911-ep0cg63Ul-I8NlFj4GplQGb_TTLiczclX57DvMV8Q-JdjgRgSZG5zLmNsb3VkZmxhcmUuY29tCi9kbnMtcXVlcnk
```

DNS-over-TLS upstream with fallback (to be used when the main upstream is not available):
```
./dnsproxy -u tls://dns.adguard.com -f 8.8.8.8:53
```

### Encrypted DNS server

Runs a DNS-over-TLS proxy on `127.0.0.1:853`.
```
./dnsproxy -l 127.0.0.1 --tls-port=853 --tls-crt=example.crt --tls-key=example.key -u 8.8.8.8:53 
```

Runs a DNS-over-HTTPS proxy on `127.0.0.1:443`.
```
./dnsproxy -l 127.0.0.1 --https-port=443 --tls-crt=example.crt --tls-key=example.key --tls-name=example.org -u 8.8.8.8:53 
```

### Additional features

Runs a DNS proxy on `0.0.0.0:53` with rate limit set to `10 rps`, enabled DNS cache, and that refuses type=ANY requests.
```
./dnsproxy -u 8.8.8.8:53 -r 10 --cache --refuse-any
```

### TODO

* [x] Configure fallback resolver
* [x] Listen on TCP/TLS as well
* [X] gomobile/gobind builds
* [X] Listen on HTTPS
* [ ] DNSSEC validation
* [ ] 1.0.0 release
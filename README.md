[![Build Status](https://travis-ci.org/AdguardTeam/dnsproxy.svg?branch=master)](https://travis-ci.org/AdguardTeam/dnsproxy)
[![Code Coverage](https://img.shields.io/codecov/c/github/AdguardTeam/dnsproxy/master.svg)](https://codecov.io/github/AdguardTeam/dnsproxy?branch=master)
[![Go Report Card](https://goreportcard.com/badge/github.com/AdguardTeam/dnsproxy)](https://goreportcard.com/report/AdguardTeam/dnsproxy)
[![Go Doc](https://godoc.org/github.com/AdguardTeam/dnsproxy?status.svg)](https://godoc.org/github.com/AdguardTeam/dnsproxy)

# DNS Proxy

A simple DNS proxy server that supports all existing DNS protocols including `DNS-over-TLS`, `DNS-over-HTTPS`, and `DNSCrypt`.

## Usage

```
$ ./dnsproxy -h
Usage:
  dnsproxy [OPTIONS]

Application Options:
  -v, --verbose    Verbose output (optional)
  -o, --output=    Path to the log file. If not set, write to stdout.
  -l, --listen=    Listen address (default: 0.0.0.0)
  -p, --port=      Listen port (default: 53)
  -b, --bootstrap= Bootstrap DNS for DoH and DoT (default: 8.8.8.8:53)
  -u, --upstream=  An upstream to be used (can be specified multiple times)

Help Options:
  -h, --help       Show this help message
```

## Examples

Runs a DNS proxy on `0.0.0.0:53` with a single upstream - Google DNS.
```
./dnsproxy -u 8.8.8.8:53
```

Runs a DNS proxy on `127.0.0.1:5353` with multiple upstreams.
```
./dnsproxy -l 127.0.0.1 -p 5353 -u 8.8.8.8:53 -u 1.1.1.1:53
```

The same proxy with verbose logging enabled writing it to the file `log.txt`. 
```
./dnsproxy -u 8.8.8.8:53 -v -out log.txt
```

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

### TODO:

* [ ] Listen on TCP as well
* [ ] Mobile builds
* [ ] Gobind interfaces
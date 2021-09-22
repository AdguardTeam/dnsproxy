[![Code Coverage](https://img.shields.io/codecov/c/github/AdguardTeam/dnsproxy/master.svg)](https://codecov.io/github/AdguardTeam/dnsproxy?branch=master)
[![Go Report Card](https://goreportcard.com/badge/github.com/AdguardTeam/dnsproxy)](https://goreportcard.com/report/AdguardTeam/dnsproxy)
[![GolangCI](https://golangci.com/badges/github.com/AdguardTeam/dnsproxy.svg)](https://golangci.com/r/github.com/AdguardTeam/dnsproxy)
[![Go Doc](https://godoc.org/github.com/AdguardTeam/dnsproxy?status.svg)](https://godoc.org/github.com/AdguardTeam/dnsproxy)

# DNS Proxy <!-- omit in toc -->

A simple DNS proxy server that supports all existing DNS protocols including `DNS-over-TLS`, `DNS-over-HTTPS`, `DNSCrypt`, and `DNS-over-QUIC`. Moreover, it can work as a `DNS-over-HTTPS`, `DNS-over-TLS` or `DNS-over-QUIC` server.

> Note that `DNS-over-QUIC` support is experimental, don't use it in production.

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
  dnsproxy -c [Path to the .toml config file]
```

## Example configuration file:

```
# Configuration file for dnsproxy
# Log settings
# // --

Verbose = false # Verbose output (optional)
LogOutput = "" # Path to a log file, if not set, write to stdout

# Listen addrs
# --

ListenAddrs = ["127.0.0.1"] # Server listen address

# Server listen ports 
ListenPorts = [53] # Listening ports. Zero value disables TCP and UDP listeners
#HTTPSListenPorts = [] # Listening ports for DNS-over-HTTPS
#TLSListenPorts = [] # Listening ports for DNS-over-TLS
#QUICListenPorts = [] # Listening ports for DNS-over-QUIC
#DNSCryptListenPorts = [] # Listening ports for DNSCrypt

# Encryption config
# --

#TLSCertPath = "" # Path to the .crt/.pem with the certificate chain, when the proxy is used as a DNS server
#TLSKeyPath = "" # Path to a file with the private key, when the proxy is used as a DNS server
#TLSMinVersion = # Minimum TLS version, for example 1.0
#TLSMaxVersion = # Maximum TLS version, for example 1.3
Insecure = false # Disable secure TLS certificate validation, for DNS server
#DNSCryptConfigPath = "" # Path to a file with DNSCrypt configuration. You can generate one using https://github.com/ameshkov/dnscrypt

#DoH Upstream Authentication
TLSAuthCertPath = "/home/marino/certificates/root/ca/intermediate/certs/dohclient.cert.pem" # Path to a file with the client certificate, coment if you don't want to use client auth
TLSAuthKeyPath = "/home/marino/certificates/root/ca/intermediate/private/dohclient.key.pem" # Path to a file with the client private key, coment if you don't want to use client auth

#Upstream DNS servers settings
#--
Upstreams = ["https://dns.plido.net/dns-query"] # An upstream to be used (can be specified multiple times). You can also specify path to a file with the list of servers, it must be set
BootstrapDNS = ["1.1.1.1:53"] # Bootstrap DNS for DoH and DoT, can be specified multiple times 
#Fallbacks = [""] # Fallback DNS resolver to use when regular ones are unavailable, can be specified multiple times. You can also specify path to a file with the list of servers"`
#AllServers = false # If true, parallel queries to all configured upstream servers
#FastestAddress = # Respond to A or AAAA requests only with the fastest IP address, detected by ICMP response time or TCP connection time

# Cache settings
# --

#Cache = true # If true, DNS cache is enabled
#CacheSizeBytes = 64000 # Cache size value, default: 64k
#CacheMinTTL = # Minimum TTL value for DNS entries, in seconds. Capped at 3600. Artificially extending TTLs should only be done with careful consideration."`
#CacheMaxTTL = # Maximum TTL value for DNS entries, in seconds
#CacheOptimistic = # CacheOptimistic, if set to true, enables the optimistic DNS cache. That means that cached results will be served even if their cache TTL has already expired

# Anti-DNS amplification measures
# --

Ratelimit = 0 # Ratelimit (requests per second)
#RefuseAny = false # If true, refuse ANY requests

# ECS settings
# --

#EnableEDNSSubnet = true # Use EDNS Client Subnet extension
#EDNSAddr = "" # Send EDNS custom client address

#DNS64 settings
#

#DNS64 = true # If specified, dnsproxy will act as a DNS64 server
#DNS64Prefix = "" # If specified, this is the DNS64 prefix dnsproxy will be using when it works as a DNS64 server. If not specified, dnsproxy uses the 'Well-Known Prefix' 64:ff9b::

#Other settings and options
#--

IPv6Disabled = false # If true, all AAAA requests will be replied with NoError RCode and empty answer
# BogusNXDomain = [""] # Transform responses that contain at least one of the given IP addresses into NXDOMAIN. Can be specified multiple times
UDPBufferSize = 0 # Set the size of the UDP buffer in bytes. A value <= 0 will use the system default.
MaxGoRoutines = 0 # Set the maximum number of go routines. A value <= 0 will not not set a maximum default to 0
Version = false # Prints the program version"`
```

#### Linux (`systemd`)

To run the `dnsproxy` as a daemon and without `root` under Linux with `systemd` as init system follow the instructions.
This example will connect to the Cloudflare DNS service.
1. Build the binary (see [Build](#Build)).
2. Copy the binary to `/usr/bin` as `root`:
   ```
   # cp dnsproxy /usr/bin/
   ```
3. Copy the config files to `/etc/systemd/system/` as `root`:
   ```
   # cp dnsproxy.service /etc/systemd/system
   ```
   If the location of the binary is different from above then change the path in `dnsproxy.service` under `ExecStart`. 
4. Reload `systemd` manager configuration:
   ```
   # systemctl daemon-reload
   ```
5. Enable the `dnsproxy` as a daemon:
   ```
   # systemctl enable dnsproxy
   ```
6. Reboot the system or start the daemon manually:
   ```
   # systemctl start dnsproxy
   ```
7. Adjust the `/etc/resolv.conf` by adding the following line. The address should be the same as in the config file (ListenAddrs):
   ```
   nameserver 127.0.0.1
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

[![Code Coverage](https://img.shields.io/codecov/c/github/ameshkov/dnscrypt/master.svg)](https://codecov.io/github/ameshkov/dnscrypt?branch=master)
[![Go Report Card](https://goreportcard.com/badge/github.com/ameshkov/dnscrypt)](https://goreportcard.com/report/ameshkov/dnscrypt)
[![Go Doc](https://godoc.org/github.com/ameshkov/dnscrypt?status.svg)](https://godoc.org/github.com/ameshkov/dnscrypt)

# DNSCrypt Go

Golang-implementation of the [DNSCrypt v2 protocol](https://dnscrypt.info/protocol).

This repo includes everything you need to work with DNSCrypt. You can run your own resolver, make DNS lookups to other DNSCrypt resolvers, and you can use it as a library in your own projects.

* [Command-line tool](#commandline)
    * [How to install](#install)
    * [How to configure](#configure)
      * [Converting dnscrypt-wrapper configuration](#convertfromwrapper)
    * [Running a server](#runningserver)
    * [Making lookups](#lookup)
* [Programming interface](#api)
    * [Client](#client)
    * [Server](#server)

## <a id="commandline"></a> Command-line tool

`dnscrypt` is a helper tool that can work as a DNSCrypt client or server.

Please note, that even though this tool can work as a server, it's purpose is merely testing. Use [dnsproxy](https://github.com/AdguardTeam/dnsproxy) or [AdGuard Home](https://github.com/AdguardTeam/AdGuardHome) for real-life purposes.


### <a id="install"></a> How to install

Download and unpack an archive for your platform from the [latest release](https://github.com/ameshkov/dnscrypt/releases).

Homebrew:
```
brew install ameshkov/tap/dnscrypt
```

### <a id="configure"></a> How to configure

Generate a configuration file for running a DNSCrypt server:

```
./dnscrypt generate

[generate command options]
      -p, --provider-name= DNSCrypt provider name. Param is required.
      -o, --out=           Path to the resulting config file. Param is required.
      -k, --private-key=   Private key (hex-encoded)
      -t, --ttl=           Certificate time-to-live (seconds)
```

It will generate a configuration file that looks like this:

```yaml
provider_name: 2.dnscrypt-cert.example.org
public_key: F11DDBCC4817E543845FDDD4CB881849B64226F3DE397625669D87B919BC4FB0
private_key: 5752095FFA56D963569951AFE70FE1690F378D13D8AD6F8054DFAA100907F8B6F11DDBCC4817E543845FDDD4CB881849B64226F3DE397625669D87B919BC4FB0
resolver_secret: 9E46E79FEB3AB3D45F4EB3EA957DEAF5D9639A0179F1850AFABA7E58F87C74C4
resolver_public: 9327C5E64783E19C339BD6B680A56DB85521CC6E4E0CA5DF5274E2D3CE026C6B
es_version: 1
certificate_ttl: 0s
```

* `provider_name` - DNSCrypt resolver name.
* `public_key`, `private_key` - keypair that is used by the DNSCrypt resolver to sign the certificate.
* `resolver_secret`, `resolver_public` - keypair that is used by the DNSCrypt resolver to encrypt and decrypt messages.
* `es_version` - crypto to use. Can be `1` (XSalsa20Poly1305) or `2` (XChacha20Poly1305).
* `certificate_ttl` - certificate time-to-live. By default it's set to `0` and in this case 1-year cert is generated. The certificate is generated on `dnscrypt` start-up and it will only be valid for the specified amount of time. You should periodically restart `dnscrypt` to rotate the cert. 

#### <a id="convertfromwrapper"></a> Converting [dnscrypt-wrapper](https://github.com/cofyc/dnscrypt-wrapper) configuration

Also, to create a configuration, you can use the keys generated using [dnscrypt-wrapper](https://github.com/cofyc/dnscrypt-wrapper) by running the command:

```
./dnscrypt convert-dnscrypt-wrapper

[convert-dnscrypt-wrapper command options]
      -p, --private-key=     Path to the DNSCrypt resolver private key file that is used for signing certificates. Param is required.
      -r, --resolver-secret= Path to the Short-term privacy key file for encrypting/decrypting DNS queries. If not specified, resolver_secret and resolver_public will be randomly generated.
      -n, --provider-name=   DNSCrypt provider name. Param is required.
      -o, --out=             Path to the resulting config file. Param is required.
      -t, --ttl=             Certificate time-to-live (seconds)
```


### <a id="runningserver"></a> Running a server

This configuration file can be used to run a DNSCrypt forwarding server:

```
./dnscrypt server 

[server command options]
      -c, --config=  Path to the DNSCrypt configuration file. Param is required.
      -f, --forward= Forwards DNS queries to the specified address (default: 94.140.14.140:53)
      -l, --listen=  Listening addresses (default: 0.0.0.0)
      -p, --port=    Listening ports (default: 443)
```

Now you can go to https://dnscrypt.info/stamps and use `provider_name` and `public_key` from this configuration to generate a DNS stamp. Here's how it looks like for a server running on `127.0.0.1:443`:

```
sdns://AQcAAAAAAAAADTEyNy4wLjAuMTo0NDMg8R3bzEgX5UOEX93Uy4gYSbZCJvPeOXYlZp2HuRm8T7AbMi5kbnNjcnlwdC1jZXJ0LmV4YW1wbGUub3Jn
```

### <a id="lookup"></a> Making lookups

You can use that stamp to send a DNSCrypt request to your server:

```
./dnscrypt lookup-stamp

[lookup-stamp command options]
      -n, --network= network type (tcp/udp) (default: udp)
      -s, --stamp=   DNSCrypt resolver stamp. Param is required.
      -d, --domain=  Domain to resolve. Param is required.
      -t, --type=    DNS query type (default: A)
```

You can also send a DNSCrypt request using a command that does not require stamps:

```
./dnscrypt lookup \

[lookup command options]
      -n, --network=       network type (tcp/udp) (default: udp)
      -p, --provider-name= DNSCrypt resolver provider name. Param is required.
      -k, --public-key=    DNSCrypt resolver public key. Param is required.
      -a, --addr=          Resolver address (IP[:port]). By default, the port is 443. Param is required.
      -d, --domain=        Domain to resolve. Param is required.
      -t, --type=          DNS query type (default: A)
```

## <a id="api"></a> Programming interface

### <a id="client"></a> Client

```go
import (
    "github.com/ameshkov/dnscrypt/v2"
)

// AdGuard DNS stamp
stampStr := "sdns://AQMAAAAAAAAAETk0LjE0MC4xNC4xNDo1NDQzINErR_JS3PLCu_iZEIbq95zkSV2LFsigxDIuUso_OQhzIjIuZG5zY3J5cHQuZGVmYXVsdC5uczEuYWRndWFyZC5jb20"

// Initializing the DNSCrypt client
c := dnscrypt.Client{Net: "udp", Timeout: 10 * time.Second}

// Fetching and validating the server certificate
resolverInfo, err := c.Dial(stampStr)
if err != nil {
    return err
}

// Create a DNS request
req := dns.Msg{}
req.Id = dns.Id()
req.RecursionDesired = true
req.Question = []dns.Question{
    {
        Name: "google-public-dns-a.google.com.",
        Qtype: dns.TypeA,
        Qclass: dns.ClassINET,
    },
}

// Get the DNS response
reply, err := c.Exchange(&req, resolverInfo)
```

## <a id="server"></a> Server

```go
import (
    "github.com/ameshkov/dnscrypt/v2"
)

// Prepare the test DNSCrypt server config
rc, err := dnscrypt.GenerateResolverConfig("example.org", nil)
if err != nil {
    return err
}

cert, err := rc.CreateCert()
if err != nil {
    return err
}

s := &dnscrypt.Server{
    ProviderName: rc.ProviderName,
    ResolverCert: cert,
    Handler:      dnscrypt.DefaultHandler,
}

// Prepare TCP listener
tcpConn, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.IPv4zero, Port: 443})
if err != nil {
    return err
}

// Prepare UDP listener
udpConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4zero, Port: 443})
if err != nil {
    return err
}

// Start the server
go s.ServeUDP(udpConn)
go s.ServeTCP(tcpConn)
```

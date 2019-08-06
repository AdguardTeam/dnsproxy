/*
Package dnscrypt implements a very simple DNSCrypt client library.

The idea is to let others use DNSCrypt resolvers in the same manner as we can use regular and DoT resolvers with miekg's DNS library.

Here is a simple usage example:

    // AdGuard DNS stamp
    stampStr := "sdns://AQIAAAAAAAAAFDE3Ni4xMDMuMTMwLjEzMDo1NDQzINErR_JS3PLCu_iZEIbq95zkSV2LFsigxDIuUso_OQhzIjIuZG5zY3J5cHQuZGVmYXVsdC5uczEuYWRndWFyZC5jb20"

    // Initializing the DNSCrypt client
    c := dnscrypt.Client{Proto: "udp", Timeout: 10 * time.Second}

    // Fetching and validating the server certificate
    serverInfo, rtt, err := client.Dial(stampStr)

    // Create a DNS request
    req := dns.Msg{}
    req.Id = dns.Id()
    req.RecursionDesired = true
    req.Question = []dns.Question{
        {Name: "google-public-dns-a.google.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET},
    }

    // Get the DNS response
    reply, rtt, err := c.Exchange(&req, serverInfo)

Unfortunately, I have not found an easy way to use dnscrypt-proxy as a dependency so here's why this library was created.
*/
package dnscrypt

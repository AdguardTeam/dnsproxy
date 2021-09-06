/*
Package dnscrypt includes everything you need to work with DNSCrypt. You can run your own resolver, make DNS lookups to other DNSCrypt resolvers, and you can use it as a library in your own projects.

Here's how to create a simple DNSCrypt client:

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
		{Name: "google-public-dns-a.google.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET},
	}

	// Get the DNS response
	reply, err := c.Exchange(&req, resolverInfo)

Here's how to run a DNSCrypt resolver:

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
*/
package dnscrypt

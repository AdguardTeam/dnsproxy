package upstream

import (
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/AdguardTeam/golibs/log"
	"github.com/miekg/dns"
)

//
// recursive DNS
//
type recursiveDNS struct {
	timeout time.Duration
}

func (p *recursiveDNS) Address() string { return "recursive" }

/*
a.root-servers.net 	198.41.0.4, 2001:503:ba3e::2:30 	VeriSign, Inc.
b.root-servers.net 	199.9.14.201, 2001:500:200::b 	University of Southern California (ISI)
c.root-servers.net 	192.33.4.12, 2001:500:2::c 	Cogent Communications
d.root-servers.net 	199.7.91.13, 2001:500:2d::d 	University of Maryland
e.root-servers.net 	192.203.230.10, 2001:500:a8::e 	NASA (Ames Research Center)
f.root-servers.net 	192.5.5.241, 2001:500:2f::f 	Internet Systems Consortium, Inc.
g.root-servers.net 	192.112.36.4, 2001:500:12::d0d 	US Department of Defense (NIC)
h.root-servers.net 	198.97.190.53, 2001:500:1::53 	US Army (Research Lab)
i.root-servers.net 	192.36.148.17, 2001:7fe::53 	Netnod
j.root-servers.net 	192.58.128.30, 2001:503:c27::2:30 	VeriSign, Inc.
k.root-servers.net 	193.0.14.129, 2001:7fd::1 	RIPE NCC
l.root-servers.net 	199.7.83.42, 2001:500:9f::42 	ICANN
m.root-servers.net 	202.12.27.33, 2001:dc3::35 	WIDE Project
*/

var roots = []net.IP{
	[]byte{198, 41, 0, 4},
	[]byte{199, 9, 14, 201},
	[]byte{192, 33, 4, 12},
	[]byte{199, 7, 91, 13},
	[]byte{192, 203, 230, 10},
	[]byte{192, 5, 5, 241},
	[]byte{192, 112, 36, 4},
	[]byte{198, 97, 190, 53},
	[]byte{192, 36, 148, 17},
	[]byte{192, 58, 128, 30},
	[]byte{193, 0, 14, 129},
	[]byte{199, 7, 83, 42},
	[]byte{202, 12, 27, 33},
}
var iroot int

// Get next root server's IP (round-robin)
func getRoot() net.IP {
	if iroot == len(roots) {
		iroot = 0
	}
	iroot++
	return roots[iroot-1]
}

type server struct {
	name string
	ip   []net.IP
	down bool // true if this server didn't answer in time
}

type entry struct {
	host string
	ns   []server // authority servers
}

type ctx struct {
	target string     // host name to resolve
	client dns.Client // object to use for DNS lookup
	qtype  uint16     // question type
	stack  []entry    // list of jobs to complete
	resp   *dns.Msg   // final response message
	err    error
}

const maxRecurseLevel = 8 // max number of pending recursive jobs
const maxIterations = 16  // max total lookups per one request

func (p *recursiveDNS) Exchange(m *dns.Msg) (*dns.Msg, error) {
	c := ctx{}
	c.client = dns.Client{Timeout: p.timeout, UDPSize: dns.MaxMsgSize}
	c.target = m.Question[0].Name
	c.qtype = m.Question[0].Qtype

	if !(c.qtype == dns.TypeA || c.qtype == dns.TypeAAAA) {
		return nil, fmt.Errorf("unsupported query type")
	}

	return c.resolve()
}

// Result of a single resolve operation
const (
	rContinue = iota
	rError    = iota
	rFatal    = iota
	rDone     = iota
)

/*
Algorithm:
. Send request to a root server, or NS server from the previous iteration
. If response isn't received (due to a network error),
   blacklist this server, try next one.
  If all servers are down, we won't be able to resolve this hostname.
   If this is a target hostname, it's a fatal error.
   Otherwise, we move up the stack and try to resolve next NS server.
. If response has authoritative Answer records:
 . Pop from lookup stack.  If stack is empty - finish.
. Get the list of NS records
  Additional Records may contain IP addresses of NS servers.
. Update the list of NS servers for the current hostname
. (Get IP of NS server) Push to lookup stack.
. Repeat from the beginning.

Example:

#1. Initial request to root server

Stack:
 0: "example.org", NS:[]

Request root server
Response:
 "server1", NS:[.org -> server1, .org -> server2]

#2. Update stack: set the list of NS servers

Stack:
 0: "example.org", NS:[server1, server2]

#3. Request NS server information from root server

Stack:
 0: "example.org", NS:[server1, server2]
 1: "server1", NS:[]

Request root server
Response:
 "server1", NS:[server1 -> server3], ADD:[server3 -> IP]

#4. Update stack: set the list of NS servers.
As we already have an IP address of "server3",
 request NS server "server1" information from NS server "server3".

Stack:
 0: "example.org", NS:[server1, server2]
 1: "server1", NS:[server3=IP]

Request NS server (server3)
Response:
 "server1", A:[server1 -> IP]

#5. Update stack: set the IP address of NS server

Stack:
 0: "example.org", NS:[server1=IP, server2]

Request NS server (server1)
Response:
 "example.org", A:[example.org -> IP]
*/
func (c *ctx) resolve() (*dns.Msg, error) {

	log.SetLevel(log.DEBUG)
	_ = c.stackPush(c.target)

	for i := 0; ; i++ {

		cur := &c.stack[len(c.stack)-1]

		if i == maxIterations {
			log.Info("reached max iterations limit (while trying to resolve %s)  target:%s  type:%d",
				cur.host, c.target, c.qtype)
			c.err = fmt.Errorf("reached max iterations limit")
			return nil, c.err
		}

		log.Debug("[%d] stack: %v", len(c.stack), c.stack)

		r := c.resolve1(cur)
		switch r {
		case rContinue:
			//continue

		case rDone:
			return c.resp, nil

		case rFatal:
			return nil, c.err

		case rError:
			log.Info("%s", c.err)
			if len(c.stack) != 1 {
				c.stackPop()
				continue // try to resolve next NS server
			}
			return nil, c.err
		}

		time.Sleep(200 * time.Millisecond)
	}
}

func (c *ctx) stackPush(host string) bool {
	if len(c.stack) > maxRecurseLevel {
		log.Info("reached max recursion level")
		c.err = fmt.Errorf("reached max recursion level")
		return false
	}

	ent := entry{}
	ent.host = host
	c.stack = append(c.stack, ent)
	return true
}

func (c *ctx) stackPop() {
	if len(c.stack) == 0 {
		log.Fatal("len(c.stack) == 0")
	}
	c.stack = c.stack[:len(c.stack)-1]
}

// Perform one DNS lookup and process the response
func (c *ctx) resolve1(cur *entry) int {
	srv := net.IP{} // DNS server to request
	if len(cur.ns) == 0 {
		srv = getRoot()
	}

	nsSelected := -1 // selected NS server
	nsAlive := -1    // first possibly alive NS server (isn't selected)

	for i, ns := range cur.ns {

		if ns.down {
			continue
		}

		if len(ns.ip) != 0 && nsSelected == -1 {
			srv = ns.ip[0] // TODO
			nsSelected = i

			if ns.name == cur.host {
				c.setIP(cur.host, ns.ip)
				return rContinue
			}

		} else if nsAlive == -1 {
			nsAlive = i
		}
	}

	if len(srv) == 0 {
		if nsAlive == -1 {
			c.err = fmt.Errorf("All NS servers are down: %v (host: %s)", cur.ns, cur.host)
			return rError
		}

		if !c.stackPush(cur.ns[nsAlive].name) {
			return rFatal
		}

		log.Debug("Resolving NS %s for %s", cur.ns[nsAlive].name, cur.host)
		return rContinue
	}

	qtype := c.qtype
	if len(c.stack) != 1 {
		qtype = dns.TypeA
	}

	resp, err := c.exchange(srv, cur.host, qtype)
	if resp == nil {
		log.Info("No response from server %s (host: %s): %s", srv, cur.host, err)

		if len(cur.ns) == 0 {
			return rContinue // try next root server
		}

		cur.ns[nsSelected].down = true
		return rContinue // try next NS server
	}

	if len(c.stack) == 1 && cur.host == c.target && resp.Authoritative {
		c.resp = resp
		return rDone
	}

	if len(resp.Answer) != 0 {
		ipList := c.processAnswer(resp)
		if len(ipList) == 0 {
			c.err = fmt.Errorf("empty answer (host: %s  server: %s)", cur.host, srv)
			return rError
		}

		c.setIP(cur.host, ipList)

	} else if len(resp.Ns) != 0 {
		nsList := c.processNS(resp)
		if len(nsList) == 0 {
			c.err = fmt.Errorf("empty NS list for %s", cur.host)
			return rError
		}

		log.Debug("Replacing NS list for %s: %v", cur.host, nsList)
		cur.ns = nsList

	} else {
		c.err = fmt.Errorf("empty answer (host: %s  server: %s)", cur.host, srv)
		return rError
	}

	return rContinue
}

// Get the list of IP addresses from DNS response
func (c *ctx) processAnswer(resp *dns.Msg) []net.IP {
	ipList := []net.IP{}
	target := resp.Question[0].Name

	for _, _a := range resp.Answer {

		if _a.Header().Rrtype == dns.TypeA {
			a, ok := _a.(*dns.A)
			if !ok {
				continue
			}

			if a.Header().Name != target {
				log.Debug("Skipping A for %s (target:%s)",
					a.Header().Name, target)
				continue
			}

			ipList = append(ipList, a.A)

		} else if _a.Header().Rrtype == dns.TypeAAAA {
			a6, ok := _a.(*dns.AAAA)
			if !ok {
				continue
			}

			if a6.Header().Name != target {
				log.Debug("Skipping AAAA for %s (target:%s)",
					a6.Header().Name, target)
				continue
			}

			ipList = append(ipList, a6.AAAA)
		}
	}

	return ipList
}

// Get the list of NS servers from DNS response
func (c *ctx) processNS(resp *dns.Msg) []server {
	nsList := []server{}
	target := resp.Question[0].Name

	for _, _ns := range resp.Ns {

		ns, ok := _ns.(*dns.NS)
		if !ok {
			continue
		}

		if !strings.HasSuffix(target, ns.Header().Name) {
			log.Debug("Skipping NS for %s (target:%s)",
				ns.Header().Name, target)
			continue
		}

		srv := server{}
		srv.name = ns.Ns

		for _, ex := range resp.Extra {
			var a *dns.A
			var a6 *dns.AAAA
			var ok bool

			a, ok = ex.(*dns.A)
			if ok {
				if a.Hdr.Name == ns.Ns {
					srv.ip = append(srv.ip, a.A)
				}
				continue
			}

			a6, ok = ex.(*dns.AAAA)
			if ok {
				if a6.Hdr.Name == ns.Ns {
					srv.ip = append(srv.ip, a6.AAAA)
				}
			}
		}

		nsList = append(nsList, srv)
	}

	return nsList
}

// Set IP address of the previous element in stack; pop from the stack
func (c *ctx) setIP(name string, ipList []net.IP) {
	if len(c.stack) <= 1 {
		log.Fatal("len(c.stack) <= 1")
	}
	prev := &c.stack[len(c.stack)-2]
	for i, ns := range prev.ns {
		if ns.name == name {
			prev.ns[i].ip = ipList
			log.Debug("Set IP %s for NS %s for %s", ipList, ns.name, prev.host)
			break
		}
	}

	c.stackPop()
}

// Send request to DNS server and receive response
func (c *ctx) exchange(server net.IP, host string, qtype uint16) (*dns.Msg, error) {
	req := dns.Msg{}
	req.SetQuestion(host, qtype)

	resp, _, err := c.client.Exchange(&req, server.String()+":53")

	if err != nil {
		return nil, err
	}

	if resp == nil {
		return nil, nil
	}

	log.Debug("client.Exchange(): host:%s  server:%s  type:%d  ans:[%d] %s  ns:[%d] %s  add:[%d] %s",
		host, server.String(), qtype, len(resp.Answer), resp.Answer,
		len(resp.Ns), resp.Ns,
		len(resp.Extra), resp.Extra)

	return resp, nil
}

package upstream

import (
	"net/url"
	"time"

	"github.com/AdguardTeam/golibs/log"
	"github.com/miekg/dns"
)

// plainDNS is a struct that implements the Upstream interface for the regular
// DNS protocol.
type plainDNS struct {
	address   string
	timeout   time.Duration
	preferTCP bool
}

// type check
var _ Upstream = &plainDNS{}

// newPlain returns the plain DNS Upstream.
func newPlain(uu *url.URL, timeout time.Duration, preferTCP bool) (u *plainDNS) {
	addPort(uu, defaultPortPlain)

	return &plainDNS{
		address:   uu.Host,
		timeout:   timeout,
		preferTCP: preferTCP,
	}
}

// Address implements the Upstream interface for *plainDNS.
func (p *plainDNS) Address() string {
	if p.preferTCP {
		return "tcp://" + p.address
	}

	return p.address
}

// Exchange implements the Upstream interface for *plainDNS.
func (p *plainDNS) Exchange(m *dns.Msg) (*dns.Msg, error) {
	if p.preferTCP {
		tcpClient := dns.Client{Net: "tcp", Timeout: p.timeout}

		logBegin(p.Address(), m)
		reply, _, tcpErr := tcpClient.Exchange(m, p.address)
		logFinish(p.Address(), tcpErr)

		return reply, tcpErr
	}

	client := dns.Client{Timeout: p.timeout, UDPSize: dns.MaxMsgSize}

	logBegin(p.Address(), m)
	reply, _, err := client.Exchange(m, p.address)
	logFinish(p.Address(), err)

	if reply != nil && reply.Truncated {
		log.Tracef("Truncated message was received, retrying over TCP, question: %s", m.Question[0].String())
		tcpClient := dns.Client{Net: "tcp", Timeout: p.timeout}

		logBegin(p.Address(), m)
		reply, _, err = tcpClient.Exchange(m, p.address)
		logFinish(p.Address(), err)
	}

	return reply, err
}

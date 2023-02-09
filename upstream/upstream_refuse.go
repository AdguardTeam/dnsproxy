package upstream

import (
	"github.com/miekg/dns"
)

// refuseDNS is a struct that implements the Upstream interface and refuses all
// queries
type refuseDNS struct{}

// type check
var _ Upstream = &refuseDNS{}

// Address implements the Upstream interface for *refuseDNS.
func (r *refuseDNS) Address() string {
	return "!"
}

// Exchange implements the Upstream interface for *refuseDNS.
func (r *refuseDNS) Exchange(m *dns.Msg) (*dns.Msg, error) {
	return new(dns.Msg).SetRcode(m, dns.RcodeRefused), nil
}

// Close implements the Upstream interface for *refuseDNS.
func (r *refuseDNS) Close() (err error) {
	// Nothing to close here.
	return nil
}

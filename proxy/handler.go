package proxy

import (
	"time"

	log "github.com/sirupsen/logrus"
)

// Handler is an optional middleware interface
type Handler interface {
	// ServeDNS can modify the DNSContext instance in any way
	// and should call next.ServeDNS to continue the execution
	ServeDNS(d *DNSContext, next Handler) error
}

// ServeDNS is a Handler implementation. If there is a custom middleware supplied, *p will be passed to it
func (p *Proxy) ServeDNS(d *DNSContext, next Handler) error {

	if p.cache != nil {
		val, ok := p.cache.Get(d.Req)
		if ok && val != nil {
			d.Res = val
			log.Debugf("Serving cached response")
			return nil
		}
	}

	dnsUpstream := d.Upstream

	// execute the DNS request
	startTime := time.Now()
	reply, err := dnsUpstream.Exchange(d.Req)
	rtt := int(time.Since(startTime) / time.Millisecond)
	log.Debugf("RTT: %d ms", rtt)

	// Update the upstreams weight
	p.calculateUpstreamWeights(d.UpstreamIdx, rtt)

	// Saving cached response
	if p.cache != nil && reply != nil {
		p.cache.Set(reply)
	}

	if reply == nil {
		d.Res = p.genServerFailure(d.Req)
	} else {
		d.Res = reply
	}

	return err
}

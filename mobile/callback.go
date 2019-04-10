package mobile

import (
	"sync"
	"time"

	"github.com/miekg/dns"

	"github.com/AdguardTeam/dnsproxy/proxy"
)

//noinspection GoUnusedGlobalVariable
var dnsRequestProcessedListener DNSRequestProcessedListener // nolint
var dnsRequestProcessedListenerGuard sync.Mutex             // nolint

// DNSRequestProcessedEvent
type DNSRequestProcessedEvent struct {
	Domain string // Queried domain name
	Type   string // Query type

	StartTime    int64  // Time when dnsproxy started processing request (epoch in milliseconds)
	Elapsed      int    // Time elapsed on processing
	Answer       string // DNS Answers string representation
	UpstreamAddr string // Address of the upstream used to resolve

	BytesSent     int // Number of bytes sent
	BytesReceived int // Number of bytes received

	Error string // If not empty, contains the error text (occurred while processing the DNS query)
}

// DNSRequestProcessedListener is a callback interface that can be configured from by the client library
type DNSRequestProcessedListener interface {
	DNSRequestProcessed(e *DNSRequestProcessedEvent)
}

// Configures a global listener for the DNSRequestProcessedEvent events
func ConfigureDNSRequestProcessedListener(l DNSRequestProcessedListener) {
	dnsRequestProcessedListenerGuard.Lock()
	dnsRequestProcessedListener = l
	dnsRequestProcessedListenerGuard.Unlock()
}

// handleDNSResponse handles DNS response calls by the DNS proxy,
// transforms them to a DNSRequestProcessedEvent instance and notifies the client code about processed messages.
func handleDNSResponse(d *proxy.DNSContext, err error) {
	dnsRequestProcessedListenerGuard.Lock()
	defer dnsRequestProcessedListenerGuard.Unlock()
	if dnsRequestProcessedListener == nil {
		return
	}

	e := DNSRequestProcessedEvent{}

	// Query properties
	e.Domain = d.Req.Question[0].Name
	e.Type = dns.Type(d.Req.Question[0].Qtype).String()

	// Set time/elapsed
	e.StartTime = d.StartTime.UnixNano() / int64(time.Millisecond)
	e.Elapsed = int(time.Since(d.StartTime) / time.Millisecond)

	// Send/received
	e.BytesSent = d.Req.Len()
	if d.Res != nil {
		e.BytesReceived = d.Res.Len()
	}

	// Set answer
	if d.Res != nil && len(d.Res.Answer) > 0 {
		s := ""
		for i := 0; i < len(d.Res.Answer); i++ {
			if d.Res.Answer[i] != nil {
				s += d.Res.Answer[i].String() + "\n"
			}
		}
		e.Answer = s
	}

	// Upstream
	if d.Upstream != nil {
		e.UpstreamAddr = d.Upstream.Address()
	}

	// Error
	if err != nil {
		e.Error = err.Error()
	}

	dnsRequestProcessedListener.DNSRequestProcessed(&e)
}

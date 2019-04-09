package mobile

import (
	"sync"
	"time"

	"github.com/AdguardTeam/dnsproxy/proxy"
)

//noinspection GoUnusedGlobalVariable
var dnsRequestProcessedListener DNSRequestProcessedListener // nolint
var dnsRequestProcessedListenerGuard sync.Mutex             // nolint

// DNSRequestProcessedEvent
type DNSRequestProcessedEvent struct {
	RawDNSMessage string // raw DNS message (it contains both Question and Answer sections)
	Elapsed       int    // elapsed time in milliseconds
	UpstreamAddr  string // Address of the upstream used to resolve
	Error         string // If not empty, contains the error text (occurred while processing the DNS query)
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
	if d.Res != nil {
		e.RawDNSMessage = d.Res.String()
	} else {
		e.RawDNSMessage = d.Req.String()
	}
	e.Elapsed = int(time.Since(d.StartTime) / time.Millisecond)
	if d.Upstream != nil {
		e.UpstreamAddr = d.Upstream.Address()
	}
	if err != nil {
		e.Error = err.Error()
	}

	dnsRequestProcessedListener.DNSRequestProcessed(&e)
}

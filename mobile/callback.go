package mobile

import (
	"strings"
	"sync"
	"time"

	"github.com/AdguardTeam/urlfilter/rules"

	"github.com/AdguardTeam/dnsproxy/proxy"
	"github.com/miekg/dns"
)

//noinspection GoUnusedGlobalVariable
var dnsRequestProcessedListener DNSRequestProcessedListener // nolint
var dnsRequestProcessedListenerGuard sync.Mutex             // nolint

// DNSRequestProcessedEvent represents DNS processed event
type DNSRequestProcessedEvent struct {
	Domain string // Queried domain name
	Type   string // Query type

	StartTime      int64  // Time when dnsproxy started processing request (epoch in milliseconds)
	Elapsed        int    // Time elapsed on processing
	Answer         string // DNS Answers string representation
	OriginalAnswer string // Original DNS Answers before filtering. This field will be filled if response was blocked by CNAME or IP.
	UpstreamAddr   string // Address of the upstream used to resolve

	BytesSent     int // Number of bytes sent
	BytesReceived int // Number of bytes received

	FilteringRule string // Filtering rule text
	FilterListID  int    // Filter list ID
	Whitelist     bool   // True if filtering rule is whitelist

	Error string // If not empty, contains the error text (occurred while processing the DNS query)
}

// DNSRequestProcessedListener is a callback interface that can be configured from by the client library
type DNSRequestProcessedListener interface {
	DNSRequestProcessed(e *DNSRequestProcessedEvent)
}

// ConfigureDNSRequestProcessedListener configures a global listener for the DNSRequestProcessedEvent events
func ConfigureDNSRequestProcessedListener(l DNSRequestProcessedListener) {
	dnsRequestProcessedListenerGuard.Lock()
	dnsRequestProcessedListener = l
	dnsRequestProcessedListenerGuard.Unlock()
}

// handleDNSResponse handles DNS response from the DNS proxy with filtering rule
// transforms them to a DNSRequestProcessedEvent instance and notifies the client code about processed messages.
func handleDNSResponse(d *proxy.DNSContext, originalAnswer *dns.Msg, filteringRule rules.Rule, err error, bytesReceived int) {
	dnsRequestProcessedListenerGuard.Lock()
	defer dnsRequestProcessedListenerGuard.Unlock()
	if dnsRequestProcessedListener == nil {
		return
	}

	e := DNSRequestProcessedEvent{}

	// Query properties
	e.Domain = strings.TrimSuffix(d.Req.Question[0].Name, ".")
	e.Type = dns.Type(d.Req.Question[0].Qtype).String()

	// Set time/elapsed
	e.StartTime = d.StartTime.UnixNano() / int64(time.Millisecond)
	e.Elapsed = int(time.Since(d.StartTime) / time.Millisecond)

	// Send/received
	e.BytesSent = d.Req.Len()
	if bytesReceived > 0 {
		e.BytesReceived = bytesReceived
	} else if d.Res != nil {
		e.BytesReceived = d.Res.Len()
	}

	if d.Res != nil {
		// Set answer
		if len(d.Res.Answer) > 0 {
			e.Answer = dnsAnswerListToString(d.Res.Answer)
		} else {
			e.Answer = dns.Type(d.Req.Question[0].Qtype).String() + ", " + dns.RcodeToString[d.Res.Rcode]
		}
	}

	// Filtering rule
	if filteringRule != nil {
		e.FilterListID = filteringRule.GetFilterListID()
		e.FilteringRule = filteringRule.Text()
		if networkRule, ok := filteringRule.(*rules.NetworkRule); ok {
			e.Whitelist = networkRule.Whitelist
		}

		if originalAnswer != nil && len(originalAnswer.Answer) > 0 {
			e.OriginalAnswer = dnsAnswerListToString(originalAnswer.Answer)
		}
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

func dnsAnswerListToString(list []dns.RR) string {
	// Separate cname and A/AAAA string builders to be sure of the display order
	sb := strings.Builder{}
	cnameSB := strings.Builder{}
	for _, rr := range list {
		// Let's check what kind of response we have
		rrCNAME, okCNAME := rr.(*dns.CNAME)
		rrAAAA, okAAAA := rr.(*dns.AAAA)
		rrA, okA := rr.(*dns.A)

		if !okA && !okAAAA && !okCNAME {
			continue
		}

		rType := dns.Type(rr.Header().Rrtype).String() + ", "

		if okCNAME {
			cnameSB.WriteString(rType)
			cnameSB.WriteString(rrCNAME.Target)
			cnameSB.WriteRune('\n')
			continue
		}

		sb.WriteString(rType)
		if okA {
			sb.WriteString(rrA.A.String())
		} else {
			sb.WriteRune('[')
			sb.WriteString(rrAAAA.AAAA.String())
			sb.WriteRune(']')
		}

		sb.WriteRune('\n')
	}
	return sb.String() + cnameSB.String()
}

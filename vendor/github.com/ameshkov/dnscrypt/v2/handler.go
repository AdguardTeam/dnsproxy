package dnscrypt

import (
	"net"
	"time"

	"github.com/miekg/dns"
)

const defaultTimeout = 10 * time.Second

// Handler is implemented by any value that implements ServeDNS.
type Handler interface {
	ServeDNS(rw ResponseWriter, r *dns.Msg) error
}

// ResponseWriter is the interface that needs to be implemented for different protocols
type ResponseWriter interface {
	LocalAddr() net.Addr       // LocalAddr - local socket address
	RemoteAddr() net.Addr      // RemoteAddr - remote client socket address
	WriteMsg(m *dns.Msg) error // WriteMsg - writes response message to the client
}

// DefaultHandler is the default Handler implementation
// that is used by Server if custom handler is not configured
var DefaultHandler Handler = &defaultHandler{
	udpClient: &dns.Client{
		Net:     "udp",
		Timeout: defaultTimeout,
	},
	tcpClient: &dns.Client{
		Net:     "tcp",
		Timeout: defaultTimeout,
	},
	addr: "94.140.14.140:53",
}

type defaultHandler struct {
	udpClient *dns.Client
	tcpClient *dns.Client
	addr      string
}

// ServeDNS implements Handler interface
func (h *defaultHandler) ServeDNS(rw ResponseWriter, r *dns.Msg) error {
	// Google DNS
	res, _, err := h.udpClient.Exchange(r, h.addr)
	if err != nil {
		return err
	}

	if res.Truncated {
		res, _, err = h.tcpClient.Exchange(r, h.addr)
		if err != nil {
			return err
		}
	}

	return rw.WriteMsg(res)
}

package upstream

import (
	"os"
	"sync"
	"time"

	"github.com/AdguardTeam/golibs/log"
	"github.com/ameshkov/dnscrypt"
	"github.com/joomcode/errorx"
	"github.com/miekg/dns"
)

//
// DNSCrypt
//
type dnsCrypt struct {
	boot       *bootstrapper
	client     *dnscrypt.Client     // DNSCrypt client properties
	serverInfo *dnscrypt.ServerInfo // DNSCrypt server info

	sync.RWMutex // protects DNSCrypt client
}

func (p *dnsCrypt) Address() string { return p.boot.address }

func (p *dnsCrypt) Exchange(m *dns.Msg) (*dns.Msg, error) {
	var client *dnscrypt.Client
	var serverInfo *dnscrypt.ServerInfo

	p.RLock()
	client = p.client
	serverInfo = p.serverInfo
	p.RUnlock()

	now := uint32(time.Now().Unix())
	if client == nil || serverInfo == nil || (serverInfo != nil && serverInfo.ServerCert.NotAfter < now) {
		p.Lock()

		// Using "udp" for DNSCrypt upstreams by default
		client = &dnscrypt.Client{Timeout: p.boot.timeout, AdjustPayloadSize: false}
		si, _, err := client.Dial(p.boot.address)

		if err != nil {
			p.Unlock()
			return nil, errorx.Decorate(err, "failed to fetch certificate info from %s", p.Address())
		}

		p.client = client
		p.serverInfo = si
		serverInfo = si
		p.Unlock()
	}

	reply, _, err := client.Exchange(m, serverInfo)

	if reply != nil && reply.Truncated {
		log.Tracef("Truncated message was received, retrying over TCP, question: %s", m.Question[0].String())
		tcpClient := dnscrypt.Client{Timeout: p.boot.timeout, Proto: "tcp"}
		reply, _, err = tcpClient.Exchange(m, serverInfo)
	}

	if err == nil && reply != nil && reply.Id != m.Id {
		err = dns.ErrId
	}

	if os.IsTimeout(err) {
		// If request times out, it is possible that the server configuration has been changed.
		// It is safe to assume that the key was rotated (for instance, as it is described here: https://dnscrypt.pl/2017/02/26/how-key-rotation-is-automated/).
		// We should re-fetch the server certificate info so that the new requests were not failing.
		p.Lock()
		p.client = nil
		p.serverInfo = nil
		p.Unlock()
	}

	return reply, err
}

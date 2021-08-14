package upstream

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/joomcode/errorx"
	"github.com/lucas-clemente/quic-go"
	"github.com/miekg/dns"
)

const handshakeTimeout = time.Second

//
// DNS-over-QUIC
//
type dnsOverQUIC struct {
	boot    *bootstrapper
	session quic.Session

	bytesPool    *sync.Pool // byte packets pool
	sync.RWMutex            // protects session and bytesPool
}

// type check
var _ Upstream = &dnsOverQUIC{}

func (p *dnsOverQUIC) Address() string { return p.boot.URL.String() }

func (p *dnsOverQUIC) Exchange(m *dns.Msg) (*dns.Msg, error) {
	session, err := p.getSession(true)
	if err != nil {
		return nil, err
	}

	// If any message sent on a DoQ connection contains an edns-tcp-keepalive EDNS(0) Option,
	// this is a fatal error and the recipient of the defective message MUST forcibly abort
	// the connection immediately.
	// https://datatracker.ietf.org/doc/html/draft-ietf-dprive-dnsoquic-02#section-6.6.2
	if opt := m.IsEdns0(); opt != nil {
		for _, option := range opt.Option {
			// Check for EDNS TCP keepalive option
			if option.Option() == dns.EDNS0TCPKEEPALIVE {
				_ = session.CloseWithError(0, "") // Already closing the connection so we don't care about the error
				return nil, errors.New("EDNS0 TCP keepalive option is set")
			}
		}
	}

	// https://datatracker.ietf.org/doc/html/draft-ietf-dprive-dnsoquic-02#section-6.4
	// When sending queries over a QUIC connection, the DNS Message ID MUST be set to zero.
	id := m.Id
	var reply *dns.Msg
	m.Id = 0
	defer func() {
		// Restore the original ID to not break compatibility with proxies
		m.Id = id
		if reply != nil {
			reply.Id = id
		}
	}()

	stream, err := p.openStream(session)
	if err != nil {
		return nil, errorx.Decorate(err, "failed to open new stream to %s", p.Address())
	}

	buf, err := m.Pack()
	if err != nil {
		return nil, err
	}

	_, err = stream.Write(buf)
	if err != nil {
		return nil, err
	}

	// The client MUST send the DNS query over the selected stream, and MUST
	// indicate through the STREAM FIN mechanism that no further data will
	// be sent on that stream.
	// stream.Close() -- closes the write-direction of the stream.
	_ = stream.Close()

	pool := p.getBytesPool()
	bufPtr := pool.Get().(*[]byte)

	defer pool.Put(bufPtr)

	respBuf := *bufPtr
	n, err := stream.Read(respBuf)
	if err != nil && n == 0 {
		return nil, errorx.Decorate(err, "failed to read response from %s due to %v", p.Address(), err)
	}

	reply = new(dns.Msg)
	err = reply.Unpack(respBuf)
	if err != nil {
		return nil, errorx.Decorate(err, "failed to unpack response from %s", p.Address())
	}

	return reply, nil
}

func (p *dnsOverQUIC) getBytesPool() *sync.Pool {
	p.Lock()
	if p.bytesPool == nil {
		p.bytesPool = &sync.Pool{
			New: func() interface{} {
				b := make([]byte, dns.MaxMsgSize)

				return &b
			},
		}
	}
	p.Unlock()
	return p.bytesPool
}

// getSession - opens or returns an existing quic.Session
// useCached - if true and cached session exists, return it right away
// otherwise - forcibly creates a new session
func (p *dnsOverQUIC) getSession(useCached bool) (quic.Session, error) {
	var session quic.Session
	p.RLock()
	session = p.session
	if session != nil && useCached {
		p.RUnlock()
		return session, nil
	}
	if session != nil {
		// we're recreating the session, let's create a new one
		_ = session.CloseWithError(0, "")
	}
	p.RUnlock()

	p.Lock()
	defer p.Unlock()

	var err error
	session, err = p.openSession()
	if err != nil {
		// This does not look too nice, but QUIC (or maybe quic-go)
		// doesn't seem stable enough.
		// Maybe retransmissions aren't fully implemented in quic-go?
		// Anyways, the simple solution is to make a second try when
		// it fails to open the QUIC session.
		session, err = p.openSession()
		if err != nil {
			return nil, err
		}
	}
	p.session = session
	return session, nil
}

func (p *dnsOverQUIC) openStream(session quic.Session) (quic.Stream, error) {
	ctx := context.Background()

	if p.boot.options.Timeout > 0 {
		deadline := time.Now().Add(p.boot.options.Timeout)
		var cancel context.CancelFunc
		ctx, cancel = context.WithDeadline(context.Background(), deadline)
		defer cancel() // avoid resource leak
	}

	stream, err := session.OpenStreamSync(ctx)
	if err == nil {
		return stream, nil
	}

	// try to recreate the session
	newSession, err := p.getSession(false)
	if err != nil {
		return nil, err
	}
	// open a new stream
	return newSession.OpenStreamSync(ctx)
}

func (p *dnsOverQUIC) openSession() (quic.Session, error) {
	tlsConfig, dialContext, err := p.boot.get()
	if err != nil {
		return nil, err
	}

	// we're using bootstrapped address instead of what's passed to the function
	// it does not create an actual connection, but it helps us determine
	// what IP is actually reachable (when there're v4/v6 addresses)
	rawConn, err := dialContext(context.TODO(), "udp", "")
	if err != nil {
		return nil, err
	}
	// It's never actually used
	_ = rawConn.Close()

	udpConn, ok := rawConn.(*net.UDPConn)
	if !ok {
		return nil, fmt.Errorf("failed to open connection to %s", p.Address())
	}

	addr := udpConn.RemoteAddr().String()
	quicConfig := &quic.Config{
		HandshakeIdleTimeout: handshakeTimeout,
	}
	session, err := quic.DialAddrContext(context.Background(), addr, tlsConfig, quicConfig)
	if err != nil {
		return nil, errorx.Decorate(err, "failed to open QUIC session to %s", p.Address())
	}

	return session, nil
}

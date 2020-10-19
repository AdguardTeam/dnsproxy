package dnscrypt

import (
	"bytes"
	"net"

	"github.com/AdguardTeam/golibs/log"
	"github.com/miekg/dns"
)

type encryptionFunc func(m *dns.Msg, q EncryptedQuery) ([]byte, error)

// UDPResponseWriter - ResponseWriter implementation for UDP
type UDPResponseWriter struct {
	udpConn    *net.UDPConn   // UDP connection
	remoteAddr *net.UDPAddr   // Remote peer address
	localIP    net.IP         // Local IP (that was used to accept the remote connection)
	encrypt    encryptionFunc // DNSCRypt encryption function
	req        *dns.Msg       // DNS query that was processed
	query      EncryptedQuery // DNSCrypt query properties
}

// type check
var _ ResponseWriter = &UDPResponseWriter{}

// LocalAddr - server socket local address
func (w *UDPResponseWriter) LocalAddr() net.Addr {
	return w.udpConn.LocalAddr()
}

// RemoteAddr - client's address
func (w *UDPResponseWriter) RemoteAddr() net.Addr {
	return w.remoteAddr
}

// WriteMsg - writes DNS message to the client
func (w *UDPResponseWriter) WriteMsg(m *dns.Msg) error {
	m.Truncate(dnsSize("udp", w.req))

	res, err := w.encrypt(m, w.query)
	if err != nil {
		log.Tracef("Failed to encrypt the DNS query: %v", err)
		return err
	}

	_, _ = udpWrite(res, w.udpConn, w.remoteAddr, w.localIP)
	return nil
}

// ServeUDP - listens to UDP connections, queries are then processed by Server.Handler.
// It blocks the calling goroutine and to stop it you need to close the listener.
func (s *Server) ServeUDP(l *net.UDPConn) error {
	// Check that server is properly configured
	if !s.validate() {
		return ErrServerConfig
	}

	// set UDP options to allow receiving OOB data
	err := udpSetOptions(l)
	if err != nil {
		return err
	}

	// Buffer to read incoming messages
	b := make([]byte, dns.MaxMsgSize)

	// Serialize the cert right away and prepare it to be sent to the client
	certBuf, err := s.ResolverCert.Serialize()
	if err != nil {
		return err
	}
	certTxt := packTxtString(certBuf)

	// Init oobSize - it will be used later when reading and writing UDP messages
	oobSize := udpGetOOBSize()

	log.Info("Entering DNSCrypt UDP listening loop on udp://%s", l.LocalAddr().String())

	for {
		n, localIP, addr, err := udpRead(l, b, oobSize)
		if n < minDNSPacketSize {
			// Ignore the packets that are too short
			continue
		}

		if bytes.Equal(b[:clientMagicSize], s.ResolverCert.ClientMagic[:]) {
			// This is an encrypted message, we should decrypt it
			m, q, err := s.decrypt(b[:n])
			if err == nil {
				rw := &UDPResponseWriter{
					udpConn:    l,
					remoteAddr: addr,
					localIP:    localIP,
					encrypt:    s.encrypt,
					req:        m,
					query:      q,
				}
				go s.serveDNS(rw, m)
			} else {
				log.Tracef("Failed to decrypt incoming message len=%d: %v", n, err)
			}
		} else {
			// Most likely this a DNS message requesting the certificate
			reply, err := s.handleHandshake(b, certTxt)
			if err != nil {
				log.Tracef("Failed to process a plain DNS query: %v", err)
			}
			if err == nil {
				_, _ = l.WriteTo(reply, addr)
			}
		}

		if err != nil {
			if isConnClosed(err) {
				log.Info("udpListen.ReadFrom() returned because we're reading from a closed connection, exiting loop")
			} else {
				log.Info("got error when reading from UDP listen: %s", err)
			}
			break
		}
	}

	return nil
}

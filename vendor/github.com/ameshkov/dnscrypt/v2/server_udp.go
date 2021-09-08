package dnscrypt

import (
	"bytes"
	"errors"
	"net"
	"runtime"
	"sync"
	"time"

	"github.com/AdguardTeam/golibs/log"
	"github.com/miekg/dns"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

type encryptionFunc func(m *dns.Msg, q EncryptedQuery) ([]byte, error)

// UDPResponseWriter is the ResponseWriter implementation for UDP
type UDPResponseWriter struct {
	udpConn *net.UDPConn    // UDP connection
	sess    *dns.SessionUDP // SessionUDP (necessary to use dns.WriteToSessionUDP)
	encrypt encryptionFunc  // DNSCrypt encryption function
	req     *dns.Msg        // DNS query that was processed
	query   EncryptedQuery  // DNSCrypt query properties
}

// type check
var _ ResponseWriter = &UDPResponseWriter{}

// LocalAddr is the server socket local address
func (w *UDPResponseWriter) LocalAddr() net.Addr {
	return w.udpConn.LocalAddr()
}

// RemoteAddr is the client's address
func (w *UDPResponseWriter) RemoteAddr() net.Addr {
	return w.sess.RemoteAddr()
}

// WriteMsg writes DNS message to the client
func (w *UDPResponseWriter) WriteMsg(m *dns.Msg) error {
	normalize("udp", w.req, m)

	res, err := w.encrypt(m, w.query)
	if err != nil {
		log.Tracef("Failed to encrypt the DNS query: %v", err)
		return err
	}
	_, err = dns.WriteToSessionUDP(w.udpConn, res, w.sess)
	return err
}

// ServeUDP listens to UDP connections, queries are then processed by Server.Handler.
// It blocks the calling goroutine and to stop it you need to close the listener
// or call Server.Shutdown.
func (s *Server) ServeUDP(l *net.UDPConn) error {
	err := s.prepareServeUDP(l)
	if err != nil {
		return err
	}

	// Tracks UDP handling goroutines
	udpWg := &sync.WaitGroup{}
	defer s.cleanUpUDP(udpWg, l)

	// Track active goroutine
	s.wg.Add(1)

	log.Info("Entering DNSCrypt UDP listening loop on udp://%s", l.LocalAddr())

	// Serialize the cert right away and prepare it to be sent to the client
	certTxt, err := s.getCertTXT()
	if err != nil {
		return err
	}

	for s.isStarted() {
		b, sess, err := s.readUDPMsg(l)

		// Check the error code and exit loop if necessary
		if err != nil {
			if !s.isStarted() {
				// Stopped gracefully
				return nil
			}
			var netErr net.Error
			if errors.As(err, &netErr) && netErr.Temporary() {
				// Note that timeout errors will be here (i.e. hitting ReadDeadline)
				continue
			}
			if isConnClosed(err) {
				log.Info("udpListen.ReadFrom() returned because we're reading from a closed connection, exiting loop")
			} else {
				log.Info("got error when reading from UDP listen: %s", err)
			}
			return err
		}

		if len(b) < minDNSPacketSize {
			// Ignore the packets that are too short
			continue
		}

		udpWg.Add(1)
		go func() {
			s.serveUDPMsg(b, certTxt, sess, l)
			udpWg.Done()
		}()
	}

	return nil
}

// prepareServeUDP prepares the server and listener to serving DNSCrypt
func (s *Server) prepareServeUDP(l *net.UDPConn) error {
	// Check that server is properly configured
	if !s.validate() {
		return ErrServerConfig
	}

	// set UDP options to allow receiving OOB data
	err := setUDPSocketOptions(l)
	if err != nil {
		return err
	}

	// Protect shutdown-related fields
	s.lock.Lock()
	defer s.lock.Unlock()
	s.initOnce.Do(s.init)

	// Mark the server as started.
	// Note that we don't check if it was started before as
	// Serve* methods can be called multiple times.
	s.started = true

	// Track an active UDP listener
	s.udpListeners[l] = struct{}{}
	return err
}

// cleanUpUDP waits until all UDP messages before cleaning up
func (s *Server) cleanUpUDP(udpWg *sync.WaitGroup, l *net.UDPConn) {
	// Wait until UDP messages are processed
	udpWg.Wait()

	// Not using it anymore so can be removed from the active listeners
	s.lock.Lock()
	delete(s.udpListeners, l)
	s.lock.Unlock()

	// The work is finished
	s.wg.Done()
}

// readUDPMsg reads incoming UDP message
func (s *Server) readUDPMsg(l *net.UDPConn) ([]byte, *dns.SessionUDP, error) {
	_ = l.SetReadDeadline(time.Now().Add(defaultReadTimeout))
	b := make([]byte, s.UDPSize)
	n, sess, err := dns.ReadFromSessionUDP(l, b)
	if err != nil {
		return nil, nil, err
	}

	return b[:n], sess, err
}

// serveUDPMsg handles incoming DNS message
func (s *Server) serveUDPMsg(b []byte, certTxt string, sess *dns.SessionUDP, l *net.UDPConn) {
	// First of all, check for "ClientMagic" in the incoming query
	if !bytes.Equal(b[:clientMagicSize], s.ResolverCert.ClientMagic[:]) {
		// If there's no ClientMagic in the packet, we assume this
		// is a plain DNS query requesting the certificate data
		reply, err := s.handleHandshake(b, certTxt)
		if err != nil {
			log.Tracef("failed to process a plain DNS query: %v", err)
		}
		if err == nil {
			// Ignore errors, we don't care and can't handle them anyway
			_, _ = dns.WriteToSessionUDP(l, reply, sess)
		}

		return
	}

	// If we got here, this is an encrypted DNSCrypt message
	// We should decrypt it first to get the plain DNS query
	m, q, err := s.decrypt(b)
	if err == nil {
		rw := &UDPResponseWriter{
			udpConn: l,
			sess:    sess,
			encrypt: s.encrypt,
			req:     m,
			query:   q,
		}
		err = s.serveDNS(rw, m)
		if err != nil {
			log.Tracef("failed to process a DNS query: %v", err)
		}
	} else {
		log.Tracef("failed to decrypt incoming message len=%d: %v", len(b), err)
	}
}

// setUDPSocketOptions method is necessary to be able to use dns.ReadFromSessionUDP / dns.WriteToSessionUDP
func setUDPSocketOptions(conn *net.UDPConn) error {
	if runtime.GOOS == "windows" {
		return nil
	}

	// We don't know if this a IPv4-only, IPv6-only or a IPv4-and-IPv6 connection.
	// Try enabling receiving of ECN and packet info for both IP versions.
	// We expect at least one of those syscalls to succeed.
	err6 := ipv6.NewPacketConn(conn).SetControlMessage(ipv6.FlagDst|ipv6.FlagInterface, true)
	err4 := ipv4.NewPacketConn(conn).SetControlMessage(ipv4.FlagDst|ipv4.FlagInterface, true)
	if err6 != nil && err4 != nil {
		return err4
	}
	return nil
}

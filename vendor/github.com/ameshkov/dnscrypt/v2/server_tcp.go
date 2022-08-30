package dnscrypt

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/AdguardTeam/golibs/log"
	"github.com/miekg/dns"
)

// TCPResponseWriter is the ResponseWriter implementation for TCP
type TCPResponseWriter struct {
	tcpConn net.Conn
	encrypt encryptionFunc
	req     *dns.Msg
	query   EncryptedQuery
}

// type check
var _ ResponseWriter = &TCPResponseWriter{}

// LocalAddr is the server socket local address
func (w *TCPResponseWriter) LocalAddr() net.Addr {
	return w.tcpConn.LocalAddr()
}

// RemoteAddr is the client's address
func (w *TCPResponseWriter) RemoteAddr() net.Addr {
	return w.tcpConn.RemoteAddr()
}

// WriteMsg writes DNS message to the client
func (w *TCPResponseWriter) WriteMsg(m *dns.Msg) error {
	normalize("tcp", w.req, m)

	res, err := w.encrypt(m, w.query)
	if err != nil {
		log.Tracef("Failed to encrypt the DNS query: %v", err)
		return err
	}

	return writePrefixed(res, w.tcpConn)
}

// ServeTCP listens to TCP connections, queries are then processed by Server.Handler.
// It blocks the calling goroutine and to stop it you need to close the listener
// or call Server.Shutdown.
func (s *Server) ServeTCP(l net.Listener) error {
	err := s.prepareServeTCP(l)
	if err != nil {
		return err
	}

	log.Info("Entering DNSCrypt TCP listening loop tcp://%s", l.Addr())

	// Tracks TCP connection handling goroutines
	tcpWg := &sync.WaitGroup{}
	defer s.cleanUpTCP(tcpWg, l)

	// Track active goroutine
	s.wg.Add(1)

	// Serialize the cert right away and prepare it to be sent to the client
	certTxt, err := s.getCertTXT()
	if err != nil {
		return err
	}

	for s.isStarted() {
		conn, err := l.Accept()

		// Check the error code and exit loop if necessary
		if err != nil {
			if !s.isStarted() {
				// Stopped gracefully
				break
			}
			var netErr net.Error
			if errors.As(err, &netErr) && netErr.Timeout() {
				// Note that timeout errors will be here (i.e. hitting ReadDeadline)
				continue
			}
			if isConnClosed(err) {
				log.Info("udpListen.ReadFrom() returned because we're reading from a closed connection, exiting loop")
			} else {
				log.Info("got error when reading from UDP listen: %s", err)
			}
			break
		}

		// If we got here, the connection is alive
		s.lock.Lock()
		// Track the connection to allow unblocking reads on shutdown.
		s.tcpConns[conn] = struct{}{}
		s.lock.Unlock()

		tcpWg.Add(1)
		go func() {
			// Ignore error here, it is most probably a legit one
			// if not, it's written to the debug log
			_ = s.handleTCPConnection(conn, certTxt)

			// Clean up
			_ = conn.Close()
			s.lock.Lock()
			delete(s.tcpConns, conn)
			s.lock.Unlock()
			tcpWg.Done()
		}()
	}

	return nil
}

// prepareServeTCP prepares the server and listener to serving DNSCrypt
func (s *Server) prepareServeTCP(l net.Listener) error {
	// Check that server is properly configured
	if !s.validate() {
		return ErrServerConfig
	}

	// Protect shutdown-related fields
	s.lock.Lock()
	defer s.lock.Unlock()
	s.initOnce.Do(s.init)

	// Mark the server as started if needed
	s.started = true

	// Track an active TCP listener
	s.tcpListeners[l] = struct{}{}
	return nil
}

// cleanUpTCP waits until all TCP messages before cleaning up
func (s *Server) cleanUpTCP(tcpWg *sync.WaitGroup, l net.Listener) {
	// Wait until all TCP connections are processed
	tcpWg.Wait()

	// Not using it anymore so can be removed from the active listeners
	s.lock.Lock()
	delete(s.tcpListeners, l)
	s.lock.Unlock()

	// The work is finished
	s.wg.Done()
}

// handleTCPMsg handles a single TCP message. If this method returns error
// the connection will be closed
func (s *Server) handleTCPMsg(b []byte, conn net.Conn, certTxt string) error {
	if len(b) < minDNSPacketSize {
		// Ignore the packets that are too short
		return ErrTooShort
	}

	// First of all, check for "ClientMagic" in the incoming query
	if !bytes.Equal(b[:clientMagicSize], s.ResolverCert.ClientMagic[:]) {
		// If there's no ClientMagic in the packet, we assume this
		// is a plain DNS query requesting the certificate data
		reply, err := s.handleHandshake(b, certTxt)
		if err != nil {
			return fmt.Errorf("failed to process a plain DNS query: %w", err)
		}
		err = writePrefixed(reply, conn)
		if err != nil {
			return fmt.Errorf("failed to write a response: %w", err)
		}
		return nil
	}

	// If we got here, this is an encrypted DNSCrypt message
	// We should decrypt it first to get the plain DNS query
	m, q, err := s.decrypt(b)
	if err != nil {
		return fmt.Errorf("failed to decrypt incoming message: %w", err)
	}
	rw := &TCPResponseWriter{
		tcpConn: conn,
		encrypt: s.encrypt,
		req:     m,
		query:   q,
	}
	err = s.serveDNS(rw, m)
	if err != nil {
		return fmt.Errorf("failed to process a DNS query: %w", err)
	}

	return nil
}

// handleTCPConnection handles all queries that are coming to the
// specified TCP connection.
func (s *Server) handleTCPConnection(conn net.Conn, certTxt string) error {
	timeout := defaultReadTimeout

	for s.isStarted() {
		_ = conn.SetReadDeadline(time.Now().Add(timeout))

		b, err := readPrefixed(conn)
		if err != nil {
			return err
		}

		err = s.handleTCPMsg(b, conn, certTxt)
		if err != nil {
			log.Debug("failed to process DNS query: %v", err)
			return err
		}

		timeout = defaultTCPIdleTimeout
	}

	return nil
}

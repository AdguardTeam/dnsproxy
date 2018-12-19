package proxy

import (
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/joomcode/errorx"
	"github.com/miekg/dns"
	log "github.com/sirupsen/logrus"

	"github.com/AdguardTeam/dnsproxy/upstream"
	"github.com/jmcvetta/randutil"
)

const (
	defaultTimeout   = 10 * time.Second
	minDNSPacketSize = 12 + 5
)

// Server combines the proxy server state and configuration
type Proxy struct {
	UDPListenAddr *net.UDPAddr // if nil, then it does not listen for UDP
	TCPListenAddr *net.TCPAddr // if nil, then it does not listen for TCP

	TLSListenAddr *net.TCPAddr // if nil, then it does not listen for TLS (DoT)
	TLSConfig     *tls.Config  // necessary for listening for TLS

	Upstreams []upstream.Upstream // list of upstreams

	upstreamsRtt      []int             // Average upstreams RTT (milliseconds)
	upstreamsWeighted []randutil.Choice // Weighted upstreams (depending on RTT)
	rttLock           sync.Mutex        // Synchronizes access to the upstreamsRtt/upstreamsWeighted arrays

	started   bool         // Started flag
	udpListen *net.UDPConn // UDP listen connection
	tcpListen net.Listener // TCP listener
	tlsListen net.Listener // TLS listener
	sync.RWMutex
}

// Starts the proxy server
func (p *Proxy) Start() error {
	p.Lock()
	defer p.Unlock()

	log.Println("Starting the DNS proxy server")

	if p.started {
		return errors.New("server has been already started")
	}

	if p.UDPListenAddr == nil && p.TCPListenAddr == nil && p.TLSListenAddr == nil {
		return errors.New("no listen address specified")
	}

	if len(p.Upstreams) == 0 {
		return errors.New("no upstreams specified")
	}

	if p.UDPListenAddr != nil {
		log.Printf("Creating the UDP server socket")
		udpAddr := p.UDPListenAddr
		udpListen, err := net.ListenUDP("udp", udpAddr)
		if err != nil {
			return errorx.Decorate(err, "couldn't listen to UDP socket")
		}
		p.udpListen = udpListen
		log.Printf("Listening on udp://%s", p.udpListen.LocalAddr())
	}

	if p.TCPListenAddr != nil {
		log.Printf("Creating the TCP server socket")
		tcpAddr := p.TCPListenAddr
		tcpListen, err := net.ListenTCP("tcp", tcpAddr)
		if err != nil {
			return errorx.Decorate(err, "couldn't listen to TCP socket")
		}
		p.tcpListen = tcpListen
		log.Printf("Listening on tcp://%s", p.tcpListen.Addr())
	}

	if p.TLSListenAddr != nil {
		log.Printf("Creating the TLS server socket")
		if p.TLSConfig == nil {
			return errors.New("cannot create a TLS listener without TLS config")
		}
		tlsAddr := p.TLSListenAddr
		tcpListen, err := net.ListenTCP("tcp", tlsAddr)
		if err != nil {
			return errorx.Decorate(err, "could not start TLS listener")
		}
		p.tlsListen = tls.NewListener(tcpListen, p.TLSConfig)
		log.Printf("Listening on tls://%s", p.tlsListen.Addr())
	}

	p.upstreamsRtt = make([]int, len(p.Upstreams))
	p.upstreamsWeighted = make([]randutil.Choice, len(p.Upstreams))
	for idx := range p.Upstreams {
		p.upstreamsWeighted[idx] = randutil.Choice{Weight: 1, Item: idx}
	}

	if p.udpListen != nil {
		go p.udpPacketLoop(p.udpListen)
	}

	if p.tcpListen != nil {
		go p.tcpPacketLoop(p.tcpListen)
	}

	if p.tlsListen != nil {
		go p.tcpPacketLoop(p.tlsListen)
	}

	p.started = true
	return nil
}

// Stops the proxy server
func (p *Proxy) Stop() error {
	log.Println("Stopping the DNS proxy server")

	p.Lock()
	defer p.Unlock()
	if p.udpListen == nil && p.tcpListen == nil {
		log.Println("The DNS proxy server is not started")
		return nil
	}

	var err error

	if p.tcpListen != nil {
		err = p.tcpListen.Close()
		p.tcpListen = nil
		if err != nil {
			return errorx.Decorate(err, "couldn't close TCP listening socket")
		}
	}

	if p.udpListen != nil {
		err = p.udpListen.Close()
		p.udpListen = nil
		if err != nil {
			return errorx.Decorate(err, "couldn't close UDP listening socket")
		}
	}

	if p.tlsListen != nil {
		err = p.tlsListen.Close()
		p.tlsListen = nil
		if err != nil {
			return errorx.Decorate(err, "couldn't close TLS listening socket")
		}
	}

	p.started = false
	log.Println("Stopped the DNS proxy server")
	return nil
}

// udpPacketLoop listens for incoming UDP packets
func (p *Proxy) udpPacketLoop(conn *net.UDPConn) {
	log.Printf("Entering the UDP listener loop on %s", conn.LocalAddr())
	b := make([]byte, dns.MaxMsgSize)
	for {
		p.RLock()
		if !p.started {
			return
		}
		p.RUnlock()

		n, addr, err := conn.ReadFrom(b)
		// documentation says to handle the packet even if err occurs, so do that first
		if n > 0 {
			// make a copy of all bytes because ReadFrom() will overwrite contents of b on next call
			// we need the contents to survive the call because we're handling them in goroutine
			packet := make([]byte, n)
			copy(packet, b)
			go p.handleUdpPacket(packet, addr, conn) // ignore errors
		}
		if err != nil {
			if isConnClosed(err) {
				log.Printf("udpListen.ReadFrom() returned because we're reading from a closed connection, exiting loop")
				break
			}
			log.Warnf("got error when reading from UDP listen: %s", err)
		}
	}
}

// handleUdpPacket processes the incoming UDP packet and sends a DNS response
func (p *Proxy) handleUdpPacket(packet []byte, addr net.Addr, conn *net.UDPConn) {

	log.Debugf("Start handling new UDP packet from %s", addr)
	reply, err := p.handlePacket(packet)

	if err != nil {
		log.Warnf("error handling UDP packet: %s", err)
	}

	if reply != nil {
		// we're good to respond
		err = p.respondUdp(reply, addr, conn)
		if err != nil {
			log.Warnf("Couldn't respond to UDP packet: %s", err)
		}
	}
}

// Writes a response to the client
func (p *Proxy) respondUdp(resp *dns.Msg, addr net.Addr, conn *net.UDPConn) error {
	bytes, err := resp.Pack()
	if err != nil {
		return errorx.Decorate(err, "couldn't convert message into wire format")
	}
	n, err := conn.WriteTo(bytes, addr)
	if n == 0 && isConnClosed(err) {
		return err
	}
	if err != nil {
		return errorx.Decorate(err, "conn.WriteTo() returned error")
	}
	if n != len(bytes) {
		return fmt.Errorf("conn.WriteTo() returned with %d != %d", n, len(bytes))
	}
	return nil
}

// tcpPacketLoop listens for incoming TCP packets
func (p *Proxy) tcpPacketLoop(l net.Listener) {
	log.Printf("Entering the TCP listener loop on %s", l.Addr())
	for {
		clientConn, err := l.Accept()

		if err != nil {
			if isConnClosed(err) {
				log.Printf("tcpListen.Accept() returned because we're reading from a closed connection, exiting loop")
				break
			}
			log.Warnf("got error when reading from TCP listen: %s", err)
		} else {
			go p.handleTcpConnection(clientConn)
		}
	}
}

// handleTcpConnection starts a loop that handles an incoming TCP connection
func (p *Proxy) handleTcpConnection(conn net.Conn) {
	log.Debugf("Start handling the new TCP connection %s", conn.RemoteAddr())
	defer conn.Close()

	for {
		p.RLock()
		if !p.started {
			return
		}
		p.RUnlock()

		conn.SetDeadline(time.Now().Add(defaultTimeout))
		packet, err := readPrefixed(&conn)
		if err != nil {
			return
		}

		reply, err := p.handlePacket(packet)
		if err != nil {
			log.Warnf("error handling TCP packet: %s", err)
			return
		}

		if err != nil {
			log.Warnf("error handling TCP packet: %s", err)
		}

		if reply != nil {
			// we're good to respond
			//noinspection GoUnhandledErrorResult
			conn.SetWriteDeadline(time.Now().Add(defaultTimeout))
			err = p.respondTcp(reply, conn)

			if err != nil {
				log.Warnf("Couldn't respond to TCP packet: %s", err)
			}
		}
	}
}

// Writes a response to the client
func (p *Proxy) respondTcp(resp *dns.Msg, conn net.Conn) error {
	bytes, err := resp.Pack()
	if err != nil {
		return errorx.Decorate(err, "couldn't convert message into wire format")
	}

	bytes, err = prefixWithSize(bytes)
	if err != nil {
		return errorx.Decorate(err, "couldn't add prefix with size")
	}

	n, err := conn.Write(bytes)
	if n == 0 && isConnClosed(err) {
		return err
	}
	if err != nil {
		return errorx.Decorate(err, "conn.Write() returned error")
	}
	if n != len(bytes) {
		return fmt.Errorf("conn.Write() returned with %d != %d", n, len(bytes))
	}
	return nil
}

// handlePacket processes the incoming packet bytes and returns with an optional response packet.
func (p *Proxy) handlePacket(packet []byte) (*dns.Msg, error) {

	msg := &dns.Msg{}
	err := msg.Unpack(packet)
	if err != nil {
		return nil, errorx.Decorate(err, "got invalid DNS packet")
	}

	if log.IsLevelEnabled(log.DebugLevel) {
		// Avoid calling String() if debug level is not enabled
		log.Debugf("IN: %s", msg.String())
	}

	//
	// DNS packet byte format is valid
	//
	// any errors below here require a response to client
	if len(msg.Question) != 1 {
		log.Warnf("Got invalid number of questions: %v", len(msg.Question))
		return p.genServerFailure(msg), nil
	}

	// we need dnsUpstream to resolve A records
	dnsUpstream, upstreamIdx := p.chooseUpstream()
	log.Debugf("Upstream: %s", dnsUpstream.Address())

	startTime := time.Now()
	reply, err := dnsUpstream.Exchange(msg)
	rtt := int(time.Since(startTime) / time.Millisecond)
	log.Debugf("RTT: %dms", rtt)

	// Update the upstreams weight
	p.calculateUpstreamWeights(upstreamIdx, rtt)

	if err != nil {
		log.Warnf("talking to dnsUpstream failed for request %s: %s", msg.String(), err)
		return p.genServerFailure(msg), err
	}

	if reply == nil {
		log.Warnf("SHOULD NOT HAPPEN dnsUpstream returned empty message for request %s", msg.String())
		return p.genServerFailure(msg), nil
	}

	if log.IsLevelEnabled(log.DebugLevel) {
		// Avoid calling String() if debug level is not enabled
		log.Debugf("OUT: %s", reply.String())
	}

	return reply, nil
}

func (p *Proxy) calculateUpstreamWeights(upstreamIdx int, rtt int) {
	p.rttLock.Lock()
	defer p.rttLock.Unlock()

	currentRtt := p.upstreamsRtt[upstreamIdx]
	if currentRtt == 0 {
		currentRtt = rtt
	} else {
		currentRtt = (currentRtt + rtt) / 2
	}
	p.upstreamsRtt[upstreamIdx] = currentRtt

	sum := 0
	for _, rtt := range p.upstreamsRtt {
		sum += rtt
	}

	for i, rtt := range p.upstreamsRtt {
		// Weight must be greater than 0
		weight := sum - rtt
		if weight <= 0 {
			weight = 1
		}
		p.upstreamsWeighted[i].Weight = weight
	}
}

// Chooses an upstream using weighted random choice algorithm
func (p *Proxy) chooseUpstream() (upstream.Upstream, int) {
	upstreams := p.Upstreams
	if len(upstreams) == 0 {
		panic("SHOULD NOT HAPPEN: no default upstreams specified")
	}
	if len(upstreams) == 1 {
		return upstreams[0], 0
	}

	// Use weighted random
	p.rttLock.Lock()
	c, err := randutil.WeightedChoice(p.upstreamsWeighted)
	p.rttLock.Unlock()

	if err != nil {
		log.Fatalf("SHOULD NOT HAPPEN: Weighted random returned an error: %s", err)
	}
	idx, ok := c.Item.(int)
	if !ok {
		panic("SHOULD NOT HAPPEN: non-integer in the randutil.Choice item")
	}

	return upstreams[idx], idx
}

func readPrefixed(conn *net.Conn) ([]byte, error) {
	buf := make([]byte, 2+dns.MaxMsgSize)
	packetLength, pos := -1, 0
	for {
		readnb, err := (*conn).Read(buf[pos:])
		if err != nil {
			return buf, err
		}
		pos += readnb
		if pos >= 2 && packetLength < 0 {
			packetLength = int(binary.BigEndian.Uint16(buf[0:2]))
			if packetLength >= dns.MaxMsgSize {
				return buf, errors.New("packet too large")
			}
			if packetLength < minDNSPacketSize {
				return buf, errors.New("packet too short")
			}
		}
		if packetLength >= 0 && pos >= 2+packetLength {
			return buf[2 : 2+packetLength], nil
		}
	}
}

func prefixWithSize(packet []byte) ([]byte, error) {
	packetLen := len(packet)
	if packetLen > 0xffff {
		return packet, errors.New("packet too large")
	}
	packet = append(append(packet, 0), 0)
	copy(packet[2:], packet[:len(packet)-2])
	binary.BigEndian.PutUint16(packet[0:2], uint16(len(packet)-2))
	return packet, nil
}

func (p *Proxy) genServerFailure(request *dns.Msg) *dns.Msg {
	resp := dns.Msg{}
	resp.SetRcode(request, dns.RcodeServerFailure)
	resp.RecursionAvailable = true
	return &resp
}

// Checks if the error signals of a closed server connecting
func isConnClosed(err error) bool {
	if err == nil {
		return false
	}
	nerr, ok := err.(*net.OpError)
	if !ok {
		return false
	}

	if strings.Contains(nerr.Err.Error(), "use of closed network connection") {
		return true
	}

	return false
}

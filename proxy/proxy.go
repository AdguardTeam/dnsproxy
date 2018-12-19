package proxy

import (
	"fmt"
	"github.com/joomcode/errorx"
	"github.com/miekg/dns"
	log "github.com/sirupsen/logrus"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/AdguardTeam/dnsproxy/upstream"
	"github.com/jmcvetta/randutil"
)

var (
	defaultUdpListenAddr = &net.UDPAddr{Port: 53}
)

// Server combines the proxy server state and configuration
type Proxy struct {
	UDPListenAddr *net.UDPAddr        // if nil, then default is is used (port 53 on *)
	Upstreams     []upstream.Upstream // list of upstreams

	upstreamsRtt      []int             // Average upstreams RTT (milliseconds)
	upstreamsWeighted []randutil.Choice // Weighted upstreams (depending on RTT)
	rttLock           sync.Mutex        // Synchronizes access to the upstreamsRtt/upstreamsWeighted arrays

	udpListen *net.UDPConn // UDP listen connection
	sync.RWMutex
}

// Starts the proxy server
func (p *Proxy) Start() error {
	p.Lock()
	defer p.Unlock()

	log.Println("Starting the DNS proxy server")

	if p.udpListen == nil {
		log.Printf("Creating the UDP socket")
		var err error
		addr := p.UDPListenAddr
		if addr == nil {
			addr = defaultUdpListenAddr
		}
		p.udpListen, err = net.ListenUDP("udp", addr)
		if err != nil {
			p.udpListen = nil
			return errorx.Decorate(err, "Couldn't listen to UDP socket")
		}

		p.upstreamsRtt = make([]int, len(p.Upstreams))
		p.upstreamsWeighted = make([]randutil.Choice, len(p.Upstreams))
		for idx := range p.Upstreams {
			p.upstreamsWeighted[idx] = randutil.Choice{Weight: 1, Item: idx}
		}

		log.Printf("Listening on %s %s", p.udpListen.LocalAddr(), p.UDPListenAddr)
	}

	go p.packetLoop()

	return nil
}

// Stops the proxy server
func (p *Proxy) Stop() error {
	log.Println("Stopping the DNS proxy server")

	p.Lock()
	defer p.Unlock()
	if p.udpListen != nil {
		err := p.udpListen.Close()
		p.udpListen = nil
		if err != nil {
			return errorx.Decorate(err, "couldn't close UDP listening socket")
		}

		log.Println("Stopped the DNS proxy server")
	} else {
		log.Println("The DNS proxy server is not started")
	}

	return nil
}

// The main function: packet loop
func (p *Proxy) packetLoop() {
	log.Printf("Entering the packet handle loop")
	b := make([]byte, dns.MaxMsgSize)
	for {
		p.RLock()
		conn := p.udpListen
		p.RUnlock()
		if conn == nil {
			log.Printf("udp socket has disappeared, exiting loop")
			break
		}
		n, addr, err := conn.ReadFrom(b)
		// documentation says to handle the packet even if err occurs, so do that first
		if n > 0 {
			// make a copy of all bytes because ReadFrom() will overwrite contents of b on next call
			// we need the contents to survive the call because we're handling them in goroutine
			packet := make([]byte, n)
			copy(packet, b)
			go p.handlePacket(packet, addr, conn) // ignore errors
		}
		if err != nil {
			if isConnClosed(err) {
				log.Printf("ReadFrom() returned because we're reading from a closed connection, exiting loop")
				// don't try to nullify p.udpListen here, because p.udpListen could be already re-bound to listen
				break
			}
			log.Printf("Got error when reading from udp listen: %s", err)
		}
	}
}

func (p *Proxy) handlePacket(packet []byte, addr net.Addr, conn *net.UDPConn) {

	msg := &dns.Msg{}
	err := msg.Unpack(packet)
	if err != nil {
		log.Printf("got invalid DNS packet: %s", err)
		return // do nothing
	}

	if log.IsLevelEnabled(log.DebugLevel) {
		// Avoid calling String() if debug level is not enabled
		log.Debugf("IN: %s", msg.String())
	}
	reply, err := p.handlePacketInternal(msg, addr, conn)

	if reply == nil {
		panic("SHOULD NOT HAPPEN: empty reply from the handlePacketInternal")
	}

	if log.IsLevelEnabled(log.DebugLevel) {
		// Avoid calling String() if debug level is not enabled
		log.Debugf("OUT: %s", reply.String())
	}

	// we're good to respond
	err = p.respond(reply, addr, conn)
	if err != nil {
		log.Printf("Couldn't respond to UDP packet: %s", err)
	}
}

// handlePacketInternal processes the incoming packet bytes and returns with an optional response packet.
//
// If an empty dns.Msg is returned, do not try to send anything back to client, otherwise send contents of dns.Msg.
//
// If an error is returned, log it, don't try to generate data based on that error.
func (p *Proxy) handlePacketInternal(msg *dns.Msg, addr net.Addr, conn *net.UDPConn) (*dns.Msg, error) {
	//
	// DNS packet byte format is valid
	//
	// any errors below here require a response to client
	if len(msg.Question) != 1 {
		log.Printf("Got invalid number of questions: %v", len(msg.Question))
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
		log.Printf("talking to dnsUpstream failed for request %s: %s", msg.String(), err)
		return p.genServerFailure(msg), err
	}
	if reply == nil {
		log.Printf("SHOULD NOT HAPPEN dnsUpstream returned empty message for request %s", msg.String())
		return p.genServerFailure(msg), nil
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

// Writes a response to the client
func (p *Proxy) respond(resp *dns.Msg, addr net.Addr, conn *net.UDPConn) error {
	resp.Compress = true
	bytes, err := resp.Pack()
	if err != nil {
		return errorx.Decorate(err, "Couldn't convert message into wire format")
	}
	n, err := conn.WriteTo(bytes, addr)
	if n == 0 && isConnClosed(err) {
		return err
	}
	if n != len(bytes) {
		return fmt.Errorf("WriteTo() returned with %d != %d", n, len(bytes))
	}
	if err != nil {
		return errorx.Decorate(err, "WriteTo() returned error")
	}
	return nil
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

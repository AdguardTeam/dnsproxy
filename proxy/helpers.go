package proxy

import (
	"encoding/binary"
	"errors"
	"net"
	"strings"

	"github.com/AdguardTeam/golibs/log"
	"github.com/miekg/dns"
)

const retryNoError = 60 // Retry time for NoError SOA

// CheckDisabledAAAARequest checks if AAAA requests should be disabled or not and sets NoError empty response to given DNSContext if needed
func CheckDisabledAAAARequest(ctx *DNSContext, ipv6Disabled bool) bool {
	if ipv6Disabled && ctx.Req.Question[0].Qtype == dns.TypeAAAA {
		log.Debug("IPv6 is disabled. Reply with NoError to %s AAAA request", ctx.Req.Question[0].Name)
		ctx.Res = genEmptyNoError(ctx.Req)
		return true
	}

	return false
}

// GenEmptyMessage generates empty message with given response code and retry time
func GenEmptyMessage(request *dns.Msg, rCode int, retry uint32) *dns.Msg {
	resp := dns.Msg{}
	resp.SetRcode(request, rCode)
	resp.RecursionAvailable = true
	resp.Ns = genSOA(request, retry)
	return &resp
}

// genEmptyNoError returns response without answer and NoError RCode
func genEmptyNoError(request *dns.Msg) *dns.Msg {
	return GenEmptyMessage(request, dns.RcodeSuccess, retryNoError)
}

// genSOA returns SOA for an authority section
func genSOA(request *dns.Msg, retry uint32) []dns.RR {
	zone := ""
	if len(request.Question) > 0 {
		zone = request.Question[0].Name
	}

	soa := dns.SOA{
		// values copied from verisign's nonexistent .com domain
		// their exact values are not important in our use case because they are used for domain transfers between primary/secondary DNS servers
		Refresh: 1800,
		Retry:   retry,
		Expire:  604800,
		Minttl:  86400,
		// copied from AdGuard DNS
		Ns:     "fake-for-negative-caching.adguard.com.",
		Serial: 100500,
		// rest is request-specific
		Hdr: dns.RR_Header{
			Name:   zone,
			Rrtype: dns.TypeSOA,
			Ttl:    10,
			Class:  dns.ClassINET,
		},
	}
	soa.Mbox = "hostmaster."
	if len(zone) > 0 && zone[0] != '.' {
		soa.Mbox += zone
	}
	return []dns.RR{&soa}
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

// getIPString is a helper function that extracts IP address from net.Addr
func getIPString(addr net.Addr) string {
	switch addr := addr.(type) {
	case *net.UDPAddr:
		return addr.IP.String()
	case *net.TCPAddr:
		return addr.IP.String()
	}
	return ""
}

// readPrefixed reads DNS message prefixed with its length (2 bytes)
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

// prefixWithSize adds 2-byte prefix with the packet length
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

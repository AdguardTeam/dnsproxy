package upstream

import (
	"fmt"
	"io"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/testutil"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestUpstream_plainDNS(t *testing.T) {
	srv := startDNSServer(t, func(w dns.ResponseWriter, req *dns.Msg) {
		resp := respondToTestMessage(req)

		err := w.WriteMsg(resp)

		pt := testutil.PanicT{}
		require.NoError(pt, err)
	})
	testutil.CleanupAndRequireSuccess(t, srv.Close)

	addr := fmt.Sprintf("127.0.0.1:%d", srv.port)
	u, err := AddressToUpstream(addr, &Options{
		Logger: testLogger,
	})
	require.NoError(t, err)
	testutil.CleanupAndRequireSuccess(t, u.Close)

	for range 10 {
		checkUpstream(t, u, addr, testTimeout)
	}
}

func TestUpstream_plainDNS_badID(t *testing.T) {
	req := createTestMessage()
	badIDResp := respondToTestMessage(req)
	badIDResp.Id++

	srv := startDNSServer(t, func(w dns.ResponseWriter, _ *dns.Msg) {
		require.NoError(testutil.PanicT{}, w.WriteMsg(badIDResp))
	})
	testutil.CleanupAndRequireSuccess(t, srv.Close)

	addr := fmt.Sprintf("127.0.0.1:%d", srv.port)
	u, err := AddressToUpstream(addr, &Options{
		Logger: testLogger,
		// Use a shorter timeout to speed up the test.
		Timeout: 100 * time.Millisecond,
	})
	require.NoError(t, err)
	testutil.CleanupAndRequireSuccess(t, u.Close)

	ctx := testutil.ContextWithTimeout(t, testTimeout)
	resp, err := u.Exchange(ctx, req)

	var netErr net.Error
	require.ErrorAs(t, err, &netErr)

	assert.True(t, netErr.Timeout())
	assert.Nil(t, resp)
}

func TestUpstream_plainDNS_fallbackToTCP(t *testing.T) {
	req := createTestMessage()
	goodResp := respondToTestMessage(req)

	truncResp := goodResp.Copy()
	truncResp.Truncated = true

	badQNameResp := goodResp.Copy()
	badQNameResp.Question[0].Name = "bad." + req.Question[0].Name

	badQTypeResp := goodResp.Copy()
	badQTypeResp.Question[0].Qtype = dns.TypeCNAME

	testCases := []struct {
		udpResp *dns.Msg
		name    string
		wantUDP int
		wantTCP int
	}{{
		udpResp: goodResp,
		name:    "all_right",
		wantUDP: 1,
		wantTCP: 0,
	}, {
		udpResp: truncResp,
		name:    "truncated_response",
		wantUDP: 1,
		wantTCP: 1,
	}, {
		udpResp: badQNameResp,
		name:    "bad_qname",
		wantUDP: 1,
		wantTCP: 1,
	}, {
		udpResp: badQTypeResp,
		name:    "bad_qtype",
		wantUDP: 1,
		wantTCP: 1,
	}}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			var udpReqNum, tcpReqNum atomic.Uint32
			srv := startDNSServer(t, func(w dns.ResponseWriter, _ *dns.Msg) {
				var resp *dns.Msg
				if w.RemoteAddr().Network() == networkUDP {
					udpReqNum.Add(1)
					resp = tc.udpResp
				} else {
					tcpReqNum.Add(1)
					resp = goodResp
				}

				require.NoError(testutil.PanicT{}, w.WriteMsg(resp))
			})
			testutil.CleanupAndRequireSuccess(t, srv.Close)

			addr := fmt.Sprintf("127.0.0.1:%d", srv.port)
			u, err := AddressToUpstream(addr, &Options{
				Logger: testLogger,
				// Use a shorter timeout to speed up the test.
				Timeout: 100 * time.Millisecond,
			})
			require.NoError(t, err)
			testutil.CleanupAndRequireSuccess(t, u.Close)

			ctx := testutil.ContextWithTimeout(t, testTimeout)
			resp, err := u.Exchange(ctx, req)
			require.NoError(t, err)
			requireResponse(t, req, resp)

			assert.Equal(t, tc.wantUDP, int(udpReqNum.Load()))
			assert.Equal(t, tc.wantTCP, int(tcpReqNum.Load()))
		})
	}
}

func TestUpstream_plainDNS_largeUDPResponse(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name string
		edns bool
	}{{
		name: "no_edns",
	}, {
		name: "edns_512",
		edns: true,
	}}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			addr := serveLargeUDP(t)
			u, err := AddressToUpstream(addr, &Options{
				Logger:  testLogger,
				Timeout: time.Second,
			})
			require.NoError(t, err)
			testutil.CleanupAndRequireSuccess(t, u.Close)

			req := createTestMessage()
			req.Question[0].Qtype = dns.TypeTXT
			if tc.edns {
				req.SetEdns0(dns.MinMsgSize, false)
			}

			ctx := testutil.ContextWithTimeout(t, testTimeout)
			resp, err := u.Exchange(ctx, req)
			require.NoError(t, err)
			require.Len(t, resp.Answer, 1)

			txt := testutil.RequireTypeAssert[*dns.TXT](t, resp.Answer[0])
			assert.Greater(t, len(strings.Join(txt.Txt, "")), dns.MinMsgSize)
		})
	}
}

// serveLargeUDP listens on UDP and answers every query with a TXT record larger
// than 512 bytes.  It returns the address to query.
func serveLargeUDP(tb testing.TB) (addr string) {
	tb.Helper()

	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(tb, err)
	testutil.CleanupAndRequireSuccess(tb, conn.Close)

	go func() {
		buf := make([]byte, dns.MaxMsgSize)
		for {
			n, peer, readErr := conn.ReadFrom(buf)
			if readErr != nil {
				return
			}

			out, ok := largeUDPResponse(buf[:n])
			if !ok {
				continue
			}

			_, _ = conn.WriteTo(out, peer)
		}
	}()

	return conn.LocalAddr().String()
}

// largeUDPResponse packs a TXT reply larger than 512 bytes for packet.
func largeUDPResponse(packet []byte) (out []byte, ok bool) {
	req := &dns.Msg{}
	if req.Unpack(packet) != nil || len(req.Question) != 1 {
		return nil, false
	}

	resp := (&dns.Msg{}).SetReply(req)
	resp.Answer = []dns.RR{largeTXT(req.Question[0].Name)}

	out, err := resp.Pack()
	if err != nil {
		return nil, false
	}

	return out, true
}

// largeTXT returns a TXT record whose character data is larger than 512 bytes.
func largeTXT(name string) (rr *dns.TXT) {
	const payloadLen = 700

	payload := strings.Repeat("x", payloadLen)
	chunks := make([]string, 0, payloadLen/255+1)
	for len(payload) > 0 {
		n := min(255, len(payload))
		chunks = append(chunks, payload[:n])
		payload = payload[n:]
	}

	return &dns.TXT{
		Hdr: dns.RR_Header{
			Name:   name,
			Rrtype: dns.TypeTXT,
			Class:  dns.ClassINET,
			Ttl:    60,
		},
		Txt: chunks,
	}
}

// testDNSServer is a simple DNS server that can be used in unit-tests.
type testDNSServer struct {
	udpListener net.PacketConn
	tcpListener net.Listener
	udpSrv      *dns.Server
	tcpSrv      *dns.Server
	port        int
}

// type check
var _ io.Closer = (*testDNSServer)(nil)

// startDNSServer a test DNS server.
func startDNSServer(tb testing.TB, handler dns.HandlerFunc) (s *testDNSServer) {
	tb.Helper()

	s = &testDNSServer{}

	udpListener, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(tb, err)

	s.port = testutil.RequireTypeAssert[*net.UDPAddr](tb, udpListener.LocalAddr()).Port
	s.udpListener = udpListener

	s.tcpListener, err = net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", s.port))
	require.NoError(tb, err)

	s.udpSrv = &dns.Server{
		PacketConn: s.udpListener,
		Handler:    handler,
	}

	s.tcpSrv = &dns.Server{
		Listener: s.tcpListener,
		Handler:  handler,
	}

	go func() {
		pt := testutil.PanicT{}
		require.NoError(pt, s.udpSrv.ActivateAndServe())
	}()

	go func() {
		pt := testutil.PanicT{}
		require.NoError(pt, s.tcpSrv.ActivateAndServe())
	}()

	return s
}

// Close implements the io.Closer interface for *testDNSServer.
func (s *testDNSServer) Close() (err error) {
	udpErr := s.udpSrv.Shutdown()
	tcpErr := s.tcpSrv.Shutdown()

	return errors.Join(udpErr, tcpErr)
}

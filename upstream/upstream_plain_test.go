package upstream

import (
	"fmt"
	"io"
	"net"
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
	u, err := AddressToUpstream(addr, &Options{})
	require.NoError(t, err)
	testutil.CleanupAndRequireSuccess(t, u.Close)

	for i := 0; i < 10; i++ {
		checkUpstream(t, u, addr)
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
		// Use a shorter timeout to speed up the test.
		Timeout: 100 * time.Millisecond,
	})
	require.NoError(t, err)
	testutil.CleanupAndRequireSuccess(t, u.Close)

	resp, err := u.Exchange(req)

	var netErr net.Error
	require.ErrorAs(t, err, &netErr)

	assert.True(t, netErr.Timeout())
	assert.Nil(t, resp)
}

func TestUpstream_plainDNS_fallback(t *testing.T) {
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
	}{{
		udpResp: goodResp,
		name:    "all_right",
	}, {
		udpResp: truncResp,
		name:    "truncated_response",
	}, {
		udpResp: badQNameResp,
		name:    "bad_qname",
	}, {
		udpResp: badQTypeResp,
		name:    "bad_qtype",
	}}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			srv := startDNSServer(t, func(w dns.ResponseWriter, _ *dns.Msg) {
				resp := goodResp
				if w.RemoteAddr().Network() == string(networkUDP) {
					resp = tc.udpResp
				}

				require.NoError(testutil.PanicT{}, w.WriteMsg(resp))
			})
			testutil.CleanupAndRequireSuccess(t, srv.Close)

			addr := fmt.Sprintf("127.0.0.1:%d", srv.port)
			u, err := AddressToUpstream(addr, &Options{
				// Use a shorter timeout to speed up the test.
				Timeout: 100 * time.Millisecond,
			})
			require.NoError(t, err)
			testutil.CleanupAndRequireSuccess(t, u.Close)

			resp, err := u.Exchange(req)
			require.NoError(t, err)
			requireResponse(t, req, resp)
		})
	}
}

// testDNSServer is a simple DNS server that can be used in unit-tests.
type testDNSServer struct {
	udpSrv *dns.Server
	tcpSrv *dns.Server

	port        int
	udpListener net.PacketConn
	tcpListener net.Listener
}

// type check
var _ io.Closer = (*testDNSServer)(nil)

// startDNSServer a test DNS server.
func startDNSServer(t *testing.T, handler dns.HandlerFunc) (s *testDNSServer) {
	t.Helper()

	s = &testDNSServer{}

	udpListener, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)

	s.port = udpListener.LocalAddr().(*net.UDPAddr).Port
	s.udpListener = udpListener

	s.tcpListener, err = net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", s.port))
	require.NoError(t, err)

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

	return errors.WithDeferred(udpErr, tcpErr)
}

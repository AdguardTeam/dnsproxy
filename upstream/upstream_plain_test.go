package upstream

import (
	"fmt"
	"io"
	"net"
	"testing"

	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/testutil"
	"github.com/miekg/dns"
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

func TestUpstream_plainDNS_truncatedResponse(t *testing.T) {
	srv := startDNSServer(t, func(w dns.ResponseWriter, req *dns.Msg) {
		resp := respondToTestMessage(req)

		if w.LocalAddr().Network() == "udp" {
			// Make sure the response is truncated.
			resp.Truncated = true
			resp.Answer = nil
		}

		err := w.WriteMsg(resp)

		pt := testutil.PanicT{}
		require.NoError(pt, err)
	})
	testutil.CleanupAndRequireSuccess(t, srv.Close)

	addr := fmt.Sprintf("127.0.0.1:%d", srv.port)
	u, err := AddressToUpstream(addr, &Options{})
	require.NoError(t, err)
	testutil.CleanupAndRequireSuccess(t, u.Close)

	// The plain DNS upstream must know how to fall back to TCP so even though
	// the response over UDP is truncated, it should re-request it over TCP and
	// get the full response.
	req := createTestMessage()
	resp, err := u.Exchange(req)
	require.NoError(t, err)
	requireResponse(t, req, resp)
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

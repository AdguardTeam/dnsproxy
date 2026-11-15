package proxy

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/AdguardTeam/dnsproxy/internal/dnsproxytest"
	"github.com/AdguardTeam/dnsproxy/upstream"
	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/testutil"
	"github.com/AdguardTeam/golibs/testutil/servicetest"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// timeoutError is a net.Error that reports a timeout.
type timeoutError struct{}

// Error implements the error interface for timeoutError.
func (timeoutError) Error() (msg string) { return "timeout" }

// Timeout implements the [net.Error] interface for timeoutError.
func (timeoutError) Timeout() (ok bool) { return true }

// Temporary implements the [net.Error] interface for timeoutError.
//
// TODO(dnsproxy): Remove when [net.Error.Temporary] is removed.
func (timeoutError) Temporary() (ok bool) { return true }

func TestUDPReadErrIsFatal(t *testing.T) {
	t.Parallel()

	assert.False(t, udpReadErrIsFatal(timeoutError{}))
	assert.True(t, udpReadErrIsFatal(net.ErrClosed))
	assert.True(t, udpReadErrIsFatal(errors.Error("read failed")))
}

// Log messages written by the UDP listener loop.
const (
	msgUDPTimeout    = "reading from udp timed out"
	msgUDPUnexpected = "udp listener stopped unexpectedly; reopening"
	msgUDPReopening  = "reopening udp listener"
)

// testLogRecord is a log record saved by [testLogRecorder].
type testLogRecord struct {
	time  time.Time
	msg   string
	level slog.Level
}

// testLogRecorder is a [slog.Handler] that saves all records.  It is safe for
// concurrent use.
type testLogRecorder struct {
	mu      *sync.Mutex
	records *[]testLogRecord
}

// newTestLogRecorder returns a new properly initialized *testLogRecorder.
func newTestLogRecorder() (r *testLogRecorder) {
	return &testLogRecorder{
		mu:      &sync.Mutex{},
		records: &[]testLogRecord{},
	}
}

// type check
var _ slog.Handler = (*testLogRecorder)(nil)

// Enabled implements the [slog.Handler] interface for *testLogRecorder.
func (r *testLogRecorder) Enabled(_ context.Context, _ slog.Level) (ok bool) { return true }

// Handle implements the [slog.Handler] interface for *testLogRecorder.
func (r *testLogRecorder) Handle(_ context.Context, rec slog.Record) (err error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	*r.records = append(*r.records, testLogRecord{
		time:  time.Now(),
		msg:   rec.Message,
		level: rec.Level,
	})

	return nil
}

// WithAttrs implements the [slog.Handler] interface for *testLogRecorder.
func (r *testLogRecorder) WithAttrs(_ []slog.Attr) (h slog.Handler) { return r }

// WithGroup implements the [slog.Handler] interface for *testLogRecorder.
func (r *testLogRecorder) WithGroup(_ string) (h slog.Handler) { return r }

// find returns the records with message msg.
func (r *testLogRecorder) find(msg string) (recs []testLogRecord) {
	r.mu.Lock()
	defer r.mu.Unlock()

	for _, rec := range *r.records {
		if rec.msg == msg {
			recs = append(recs, rec)
		}
	}

	return recs
}

// atLeast returns the messages of records at level lvl or higher.
func (r *testLogRecorder) atLeast(lvl slog.Level) (msgs []string) {
	r.mu.Lock()
	defer r.mu.Unlock()

	for _, rec := range *r.records {
		if rec.level >= lvl {
			msgs = append(msgs, rec.msg)
		}
	}

	return msgs
}

// newUDPTestProxy returns a new proxy listening on a random UDP port of
// localhost and writing logs to rec.
func newUDPTestProxy(t *testing.T, rec *testLogRecorder) (p *Proxy) {
	t.Helper()

	return mustNew(t, &Config{
		Logger:        slog.New(rec),
		UDPListenAddr: []*net.UDPAddr{dnsproxytest.LocalhostAnyPortUDP},
		UpstreamConfig: &UpstreamConfig{
			Upstreams: []upstream.Upstream{newTestUpstream(t)},
		},
		TrustedProxies: dnsproxytest.DefaultTrustedProxies,
	})
}

// firstUDPListener returns the first UDP listener of p.
func firstUDPListener(tb testing.TB, p *Proxy) (conn *net.UDPConn) {
	tb.Helper()

	p.mu.RLock()
	defer p.mu.RUnlock()

	require.NotEmpty(tb, p.udpListen)

	return p.udpListen[0]
}

// exchangeUDP sends a DNS query to addr over UDP and returns an error if no
// valid answer is received.
func exchangeUDP(addr string) (err error) {
	c := &dns.Client{Net: "udp", Timeout: 250 * time.Millisecond}
	resp, _, err := c.Exchange(dnsproxytest.NewTestRequest(), addr)
	if err != nil {
		return err
	}

	if len(resp.Answer) == 0 {
		return errors.Error("no answer")
	}

	return nil
}

// countUDPLoops returns the number of running [Proxy.udpPacketLoop]
// goroutines of p.  It relies on the receiver being the first argument in the
// goroutine stack traces.
func countUDPLoops(p *Proxy) (n int) {
	buf := make([]byte, 1<<20)
	for {
		l := runtime.Stack(buf, true)
		if l < len(buf) {
			buf = buf[:l]

			break
		}

		buf = make([]byte, 2*len(buf))
	}

	return strings.Count(string(buf), fmt.Sprintf("proxy.(*Proxy).udpPacketLoop(%p", p))
}

// waitTimeout is the time to wait for a UDP listener to be reopened or to
// stop.
const waitTimeout = 5 * time.Second

// pollIvl is the interval of polling in tests.
const pollIvl = 10 * time.Millisecond

func TestProxy_udpPacketLoop_unexpectedClose(t *testing.T) {
	t.Parallel()

	rec := newTestLogRecorder()
	p := newUDPTestProxy(t, rec)
	servicetest.RequireRun(t, p, dnsproxytest.Timeout)

	addr := p.Addr(ProtoUDP).String()
	require.NoError(t, exchangeUDP(addr))

	old := firstUDPListener(t, p)
	require.NoError(t, old.Close())

	require.Eventuallyf(t, func() (ok bool) {
		return exchangeUDP(addr) == nil
	}, waitTimeout, pollIvl, "udp service on %s did not resume", addr)

	assert.NotSame(t, old, firstUDPListener(t, p))
	assert.Equal(t, addr, p.Addr(ProtoUDP).String())

	unexpected := rec.find(msgUDPUnexpected)
	require.Len(t, unexpected, 1)
	assert.Equal(t, slog.LevelError, unexpected[0].level)
}

func TestProxy_udpPacketLoop_shutdown(t *testing.T) {
	t.Parallel()

	rec := newTestLogRecorder()
	p := newUDPTestProxy(t, rec)

	ctx := testutil.ContextWithTimeout(t, dnsproxytest.Timeout)
	require.NoError(t, p.Start(ctx))

	addr, ok := p.Addr(ProtoUDP).(*net.UDPAddr)
	require.True(t, ok)
	require.NoError(t, exchangeUDP(addr.String()))
	require.Equal(t, 1, countUDPLoops(p))

	ctx = testutil.ContextWithTimeout(t, dnsproxytest.Timeout)
	require.NoError(t, p.Shutdown(ctx))

	require.Eventually(t, func() (ok bool) {
		return countUDPLoops(p) == 0
	}, waitTimeout, pollIvl)

	// Give a wrongly started reopening time to bind.
	time.Sleep(3 * udpReopenMinIvl)

	conn, err := net.ListenUDP("udp", addr)
	require.NoError(t, err)
	require.NoError(t, conn.Close())

	assert.Empty(t, rec.atLeast(slog.LevelWarn))
	assert.Empty(t, rec.find(msgUDPReopening))
}

func TestProxy_udpPacketLoop_reopenRetry(t *testing.T) {
	t.Parallel()

	rec := newTestLogRecorder()
	p := newUDPTestProxy(t, rec)

	ctx := testutil.ContextWithTimeout(t, dnsproxytest.Timeout)
	require.NoError(t, p.Start(ctx))

	addr, ok := p.Addr(ProtoUDP).(*net.UDPAddr)
	require.True(t, ok)
	require.NoError(t, exchangeUDP(addr.String()))

	// Hold the lock so that the loop can only try to reopen the listener after
	// the port is taken.
	old := firstUDPListener(t, p)
	p.mu.Lock()
	require.NoError(t, old.Close())
	blocker, err := net.ListenUDP("udp", addr)
	p.mu.Unlock()
	require.NoError(t, err)
	testutil.CleanupAndRequireSuccess(t, blocker.Close)

	const wantAttempts = 3

	require.Eventually(t, func() (ok bool) {
		return len(rec.find(msgUDPReopening)) >= wantAttempts
	}, waitTimeout, pollIvl)

	attempts := rec.find(msgUDPReopening)
	ivl := udpReopenMinIvl
	for i := 1; i < wantAttempts; i++ {
		ivl *= 2
		gap := attempts[i].time.Sub(attempts[i-1].time)
		assert.GreaterOrEqualf(t, gap, ivl, "gap before attempt %d", i+1)
		assert.Equal(t, slog.LevelWarn, attempts[i].level)
	}

	require.Len(t, rec.find(msgUDPUnexpected), 1)

	ctx = testutil.ContextWithTimeout(t, dnsproxytest.Timeout)
	require.NoError(t, p.Shutdown(ctx))

	require.Eventually(t, func() (ok bool) {
		return countUDPLoops(p) == 0
	}, waitTimeout, pollIvl)

	n := len(rec.find(msgUDPReopening))
	time.Sleep(3 * udpReopenMinIvl)
	assert.Len(t, rec.find(msgUDPReopening), n)
}

func TestProxy_udpPacketLoop_timeout(t *testing.T) {
	t.Parallel()

	rec := newTestLogRecorder()
	p := newUDPTestProxy(t, rec)
	servicetest.RequireRun(t, p, dnsproxytest.Timeout)

	addr := p.Addr(ProtoUDP).String()
	require.NoError(t, exchangeUDP(addr))

	conn := firstUDPListener(t, p)
	require.NoError(t, conn.SetReadDeadline(time.Now()))
	require.Eventually(t, func() (ok bool) {
		return len(rec.find(msgUDPTimeout)) > 0
	}, waitTimeout, pollIvl)
	require.NoError(t, conn.SetReadDeadline(time.Time{}))

	require.NoError(t, exchangeUDP(addr))

	assert.Same(t, conn, firstUDPListener(t, p))
	assert.Empty(t, rec.atLeast(slog.LevelWarn))
}

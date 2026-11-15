package proxy

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/AdguardTeam/golibs/errors"
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

func TestProxy_handleUDPReadError(t *testing.T) {
	t.Parallel()

	p := &Proxy{
		logger: testLogger,
	}
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	require.NoError(t, err)

	ctx := context.Background()
	stop := p.handleUDPReadError(ctx, conn, timeoutError{})
	assert.False(t, stop)
	require.NoError(t, conn.SetReadDeadline(time.Now()))

	stop = p.handleUDPReadError(ctx, conn, errors.Error("read failed"))
	assert.True(t, stop)
	require.Error(t, conn.SetReadDeadline(time.Now()))

	stop = p.handleUDPReadError(ctx, conn, net.ErrClosed)
	assert.True(t, stop)
}

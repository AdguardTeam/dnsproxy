package upstream

import (
	"sync"
	"sync/atomic"
	"testing"

	"github.com/AdguardTeam/golibs/testutil"
	"github.com/quic-go/quic-go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// testConnOpener is used to mock the connection establishment.
type testConnOpener struct {
	OnOpenConnection func(conf *quic.Config) (conn quic.Connection, err error)
	OnOpenStream     func(conn quic.Connection) (stream quic.Stream, err error)
}

// type check
var _ quicConnOpener = (*testConnOpener)(nil)

// openConnection implements the [quicConnOpener] interface for
// [*testConnOpener].
func (tco *testConnOpener) openConnection(conf *quic.Config) (conn quic.Connection, err error) {
	return tco.OnOpenConnection(conf)
}

// openStream implements the [quicConnOpener] interface for [*testConnOpener].
func (tco *testConnOpener) openStream(conn quic.Connection) (stream quic.Stream, err error) {
	return tco.OnOpenStream(conn)
}

// testQUICConn is used to mock QUIC connections.
type testQUICConn struct {
	quic.Connection
}

// CloseWithError implements the [quic.Connection] interface for
// [*testQUICConn].
func (tqc *testQUICConn) CloseWithError(code quic.ApplicationErrorCode, msg string) (err error) {
	return nil
}

func TestQUICConnector(t *testing.T) {
	const (
		routineNum = 100
		triesNum   = 10
	)

	var connTriesNum atomic.Int32
	var beforeGet, afterGet sync.WaitGroup

	pt := testutil.PanicT{}

	emptyConn := &testQUICConn{}
	var returnedConn, wantConn quic.Connection
	var connErr, streamErr error

	opener := &testConnOpener{
		OnOpenConnection: func(_ *quic.Config) (conn quic.Connection, err error) {
			beforeGet.Wait()
			connTriesNum.Add(1)

			return returnedConn, connErr
		},
		OnOpenStream: func(conn quic.Connection) (stream quic.Stream, err error) {
			require.Same(pt, wantConn, conn)

			return nil, streamErr
		},
	}
	qc := newQUICConnector(opener, &quic.Config{
		KeepAlivePeriod: QUICKeepAlivePeriod,
		TokenStore:      newQUICTokenStore(),
	})

	t.Run("success", func(t *testing.T) {
		t.Cleanup(func() {
			connTriesNum.Store(0)
			returnedConn, connErr = nil, nil
			wantConn, streamErr = nil, nil
		})

		returnedConn, connErr = emptyConn, nil
		wantConn, streamErr = emptyConn, nil

		for i := 0; i < triesNum; i++ {
			qc.close()
			beforeGet.Add(routineNum)
			afterGet.Add(routineNum)

			for j := 0; j < routineNum; j++ {
				go func() {
					beforeGet.Done()
					defer afterGet.Done()

					_, err := qc.get()
					require.NoError(pt, err)
				}()
			}
			afterGet.Wait()

			assert.Equal(t, int32(i+1), connTriesNum.Load())
		}
	})

	t.Run("bad_streamer", func(t *testing.T) {
		t.Cleanup(func() {
			connTriesNum.Store(0)
			returnedConn, connErr = nil, nil
			wantConn, streamErr = nil, nil
		})

		returnedConn, connErr = emptyConn, nil
		wantConn, streamErr = emptyConn, assert.AnError

		for i := 0; i < triesNum; i++ {
			qc.close()
			beforeGet.Add(routineNum)
			afterGet.Add(routineNum)

			for j := 0; j < routineNum; j++ {
				go func() {
					beforeGet.Done()
					defer afterGet.Done()

					_, err := qc.get()
					require.Same(pt, assert.AnError, err)
				}()
			}
			afterGet.Wait()

			assert.Equal(t, int32(i+1)*routineNum, connTriesNum.Load())
		}
	})

	t.Run("error", func(t *testing.T) {
		prevOnOpenStream := opener.OnOpenStream
		t.Cleanup(func() {
			connTriesNum.Store(0)
			returnedConn, connErr = nil, nil
			opener.OnOpenStream = prevOnOpenStream
		})

		returnedConn, connErr = nil, assert.AnError
		opener.OnOpenStream = func(_ quic.Connection) (_ quic.Stream, _ error) {
			panic("should not be called")
		}

		for i := 0; i < triesNum; i++ {
			beforeGet.Add(routineNum)
			afterGet.Add(routineNum)

			for j := 0; j < routineNum; j++ {
				go func() {
					beforeGet.Done()
					defer afterGet.Done()

					conn, err := qc.get()
					require.Nil(pt, conn)
					require.Same(pt, assert.AnError, err)
				}()
			}
			afterGet.Wait()

			assert.Equal(t, int32(i+1)*routineNum, connTriesNum.Load())
		}
	})
}

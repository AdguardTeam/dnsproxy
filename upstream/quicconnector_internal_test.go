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

func TestQUICConnector_refactrored(t *testing.T) {
	const routineNum = 100

	pt := testutil.PanicT{}
	emptyConn := &testQUICConn{}

	testCases := []struct {
		returnConn    quic.Connection
		connErr       error
		onOpenStream  func(conn quic.Connection) (stream quic.Stream, err error)
		wantErr       error
		name          string
		wantConnTries int32
	}{{
		returnConn: emptyConn,
		connErr:    nil,
		onOpenStream: func(conn quic.Connection) (stream quic.Stream, err error) {
			require.Same(pt, emptyConn, conn)

			return nil, nil
		},
		wantErr:       nil,
		name:          "success",
		wantConnTries: 1,
	}, {
		returnConn: emptyConn,
		connErr:    nil,
		onOpenStream: func(conn quic.Connection) (stream quic.Stream, err error) {
			require.Same(pt, emptyConn, conn)

			return nil, assert.AnError
		},
		wantErr:       assert.AnError,
		name:          "bad_streamer",
		wantConnTries: routineNum,
	}, {
		returnConn: emptyConn,
		connErr:    assert.AnError,
		onOpenStream: func(conn quic.Connection) (stream quic.Stream, err error) {
			panic("should not be called")
		},
		wantErr:       assert.AnError,
		name:          "error",
		wantConnTries: routineNum,
	}}

	for _, tc := range testCases {
		tc := tc
		var beforeGet, afterGet sync.WaitGroup
		var connTriesNum atomic.Int32

		opener := &testConnOpener{
			OnOpenConnection: func(_ *quic.Config) (conn quic.Connection, err error) {
				beforeGet.Wait()
				connTriesNum.Add(1)

				return tc.returnConn, tc.connErr
			},
			OnOpenStream: tc.onOpenStream,
		}
		qc := newQUICConnector(opener, &quic.Config{
			KeepAlivePeriod: QUICKeepAlivePeriod,
			TokenStore:      newQUICTokenStore(),
		})

		t.Run(tc.name, func(t *testing.T) {
			t.Cleanup(func() { connTriesNum.Store(0) })

			qc.close()
			beforeGet.Add(routineNum)
			afterGet.Add(routineNum)

			for j := 0; j < routineNum; j++ {
				go func() {
					beforeGet.Done()
					defer afterGet.Done()

					_, err := qc.get()
					require.ErrorIs(pt, err, tc.wantErr)
				}()
			}
			afterGet.Wait()

			assert.Equal(t, tc.wantConnTries, connTriesNum.Load())
		})
	}
}

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
}

// type check
var _ quicConnOpener = (*testConnOpener)(nil)

// openConnection implements the [quicConnOpener] interface for
// [*testConnOpener].
func (tco *testConnOpener) openConnection(conf *quic.Config) (conn quic.Connection, err error) {
	return tco.OnOpenConnection(conf)
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

	t.Run("success", func(t *testing.T) {
		t.Cleanup(func() { connTriesNum.Store(0) })

		emptyConn := &testQUICConn{}

		opener := &testConnOpener{
			OnOpenConnection: func(_ *quic.Config) (conn quic.Connection, err error) {
				beforeGet.Wait()
				connTriesNum.Add(1)

				return emptyConn, nil
			},
		}
		qc := newQUICConnector(opener, &quic.Config{
			KeepAlivePeriod: QUICKeepAlivePeriod,
			TokenStore:      newQUICTokenStore(),
		})

		for i := 0; i < triesNum; i++ {
			t.Logf("try %d", i)
			qc.reset()
			beforeGet.Add(routineNum)
			afterGet.Add(routineNum)

			for j := 0; j < routineNum; j++ {
				go func() {
					beforeGet.Done()
					conn, err := qc.get()
					afterGet.Done()

					require.NoError(pt, err)
					require.Same(pt, emptyConn, conn)
				}()
			}
			afterGet.Wait()

			assert.Equal(t, int32(i+1), connTriesNum.Load())
		}
	})

	t.Run("error", func(t *testing.T) {
		t.Cleanup(func() { connTriesNum.Store(0) })

		opener := &testConnOpener{
			OnOpenConnection: func(_ *quic.Config) (conn quic.Connection, err error) {
				beforeGet.Wait()
				connTriesNum.Add(1)

				return nil, assert.AnError
			},
		}
		qc := newQUICConnector(opener, &quic.Config{
			KeepAlivePeriod: QUICKeepAlivePeriod,
			TokenStore:      newQUICTokenStore(),
		})

		for i := 0; i < triesNum; i++ {
			beforeGet.Add(routineNum)
			afterGet.Add(routineNum)

			for j := 0; j < routineNum; j++ {
				go func() {
					beforeGet.Done()
					conn, err := qc.get()
					afterGet.Done()

					require.Nil(pt, conn)
					require.Same(pt, assert.AnError, err)
				}()
			}
			afterGet.Wait()

			assert.Equal(t, int32(i+1), connTriesNum.Load())
		}
	})
}

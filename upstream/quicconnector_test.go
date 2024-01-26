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

// testConnHandler is used to mock the connection establishment.
type testConnHandler struct {
	OnOpenConnection func() (conn quic.Connection, err error)
	OnCloseConn      func(conn quic.Connection, err error)
}

// type check
var _ quicConnHandler = (*testConnHandler)(nil)

// openConnection implements quicConnOpener.
func (tco *testConnHandler) openConnection() (conn quic.Connection, err error) {
	return tco.OnOpenConnection()
}

// closeConn implements quicConnOpener.
func (tco *testConnHandler) closeConn(conn quic.Connection, err error) {
	tco.OnCloseConn(conn, err)
}

func TestQUICConnector(t *testing.T) {
	const (
		routineNum = 100
		triesNum   = 4
	)

	type testConn struct {
		quic.Connection
	}

	var connTriesNum atomic.Int32
	var beforeGet, afterGet sync.WaitGroup

	hdlr := &testConnHandler{
		OnCloseConn: func(conn quic.Connection, err error) {
			// do nothing
		},
	}
	pt := testutil.PanicT{}

	t.Run("success", func(t *testing.T) {
		t.Cleanup(func() { connTriesNum.Store(0) })

		emptyConn := &testConn{}

		hdlr.OnOpenConnection = func() (conn quic.Connection, err error) {
			beforeGet.Wait()

			connTriesNum.Add(1)

			return emptyConn, nil
		}

		sf := newQUICConnector(hdlr)

		for i := 0; i < triesNum; i++ {
			sf.reset()
			beforeGet.Add(routineNum)
			afterGet.Add(routineNum)

			for j := 0; j < routineNum; j++ {
				go func() {
					beforeGet.Done()
					conn, err := sf.get()
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

		hdlr.OnOpenConnection = func() (conn quic.Connection, err error) {
			beforeGet.Wait()

			connTriesNum.Add(1)

			return nil, assert.AnError
		}

		sf := newQUICConnector(hdlr)

		for i := 0; i < triesNum; i++ {
			beforeGet.Add(routineNum)
			afterGet.Add(routineNum)

			for j := 0; j < routineNum; j++ {
				go func() {
					beforeGet.Done()
					conn, err := sf.get()
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

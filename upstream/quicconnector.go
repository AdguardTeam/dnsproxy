package upstream

import (
	"sync"
	"sync/atomic"

	"github.com/AdguardTeam/golibs/errors"
	"github.com/quic-go/quic-go"
)

// quicConnResult is used to store the result of a single connection
// establishment.
type quicConnResult struct {
	conn quic.Connection
	err  error
}

// quicConnector is used to establish a single connection on several demands.
type quicConnector struct {
	value atomic.Pointer[quicConnResult]
	once  atomic.Pointer[sync.Once]
	open  func() (conn quic.Connection, err error)
}

// newQUICConnector creates a new quicConnector.
func newQUICConnector(open func() (quic.Connection, error)) (sf *quicConnector) {
	sf = &quicConnector{
		value: atomic.Pointer[quicConnResult]{},
		once:  atomic.Pointer[sync.Once]{},
		open:  open,
	}
	sf.value.Store(&quicConnResult{
		conn: nil,
		err:  errors.Error("not initialized"),
	})
	sf.once.Store(&sync.Once{})

	return sf
}

// reset enforces the next call to get to re-establish the connection.
func (sf *quicConnector) reset() {
	sf.once.Store(&sync.Once{})
}

// get returns the connection.  If the connection is not established yet, it
// will be established.  If the connection establishment fails, the next call
// to get will try to establish the connection again.
func (sf *quicConnector) get() (c quic.Connection, err error) {
	sf.once.Load().Do(sf.do)
	res := sf.value.Load()

	return res.conn, res.err
}

// do actually opens the connection and stores the result.  It also check the
// error and resets the connector if the connection establishment failed.
func (sf *quicConnector) do() {
	res := &quicConnResult{}
	res.conn, res.err = sf.open()

	sf.value.Store(res)
	if res.err != nil {
		sf.reset()
	}
}

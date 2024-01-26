package upstream

import (
	"sync"

	"github.com/AdguardTeam/golibs/errors"
	"github.com/quic-go/quic-go"
)

type quicConnHandler interface {
	openConnection() (conn quic.Connection, err error)
	closeConn(conn quic.Connection, err error)
}

// quicConnector is used to establish a single connection on several demands.
type quicConnector struct {
	res         quic.Connection
	err         error
	connHandler quicConnHandler
	openCh      chan struct{}
	resetCh     chan struct{}
	mu          sync.RWMutex
}

// newQUICConnector creates a new quicConnector.
func newQUICConnector(hdlr quicConnHandler) (qc *quicConnector) {
	qc = &quicConnector{
		connHandler: hdlr,
		res:         nil,
		err:         errors.Error("not initialized"),
		openCh:      make(chan struct{}, 1),
		resetCh:     make(chan struct{}, 1),
	}
	qc.openCh <- struct{}{}

	return qc
}

// reset enforces the next call to get to re-establish the connection.
func (qc *quicConnector) reset() {
	select {
	case <-qc.resetCh:
		qc.openCh <- struct{}{}
	default:
		// Already reset.
	}
}

// get returns the connection.  If the connection is not established yet, it
// will be established.  If the connection establishment fails, the next call
// to get will try to establish the connection again.
func (qc *quicConnector) get() (c quic.Connection, err error) {
	select {
	case <-qc.openCh:
		qc.mu.Lock()
		defer qc.mu.Unlock()

		if qc.res != nil {
			qc.connHandler.closeConn(qc.res, qc.err)
		}

		qc.res, qc.err = qc.connHandler.openConnection()
		qc.resetCh <- struct{}{}
		if qc.err != nil {
			qc.reset()
		}
	default:
		qc.mu.RLock()
		defer qc.mu.RUnlock()
	}

	return qc.res, qc.err
}

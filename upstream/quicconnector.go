package upstream

import (
	"sync"

	"github.com/AdguardTeam/golibs/errors"
	"github.com/quic-go/quic-go"
)

// ready is a semantic alias for a sign of a ready action.
type ready = struct{}

type quicConnHandler interface {
	openConnection() (conn quic.Connection, err error)
	closeConnWithError(conn quic.Connection, err error)
}

// quicConnector is used to establish a single connection on several demands.
type quicConnector struct {
	conn        quic.Connection
	err         error
	connHandler quicConnHandler
	reopenReady chan ready
	resetReady  chan ready
	mu          *sync.RWMutex
}

// newQUICConnector creates a new quicConnector.
func newQUICConnector(hdlr quicConnHandler) (qc *quicConnector) {
	qc = &quicConnector{
		conn:        nil,
		err:         errors.Error("not initialized"),
		connHandler: hdlr,
		reopenReady: make(chan ready, 1),
		resetReady:  make(chan ready, 1),
		mu:          &sync.RWMutex{},
	}
	qc.reopenReady <- ready{}

	return qc
}

// reset enforces the next call to get to re-establish the connection.
func (qc *quicConnector) reset() {
	select {
	case <-qc.resetReady:
		qc.reopenReady <- ready{}
	default:
		// Already reset.
	}
}

// get returns the connection.  If the connection is not established yet, it
// will be established.  If the connection establishment fails, the next call
// to get will try to establish the connection again.
func (qc *quicConnector) get() (conn quic.Connection, err error) {
	select {
	case <-qc.reopenReady:
		qc.mu.Lock()
		defer qc.mu.Unlock()

		return qc.reopen()
	default:
		return qc.current()
	}
}

func (qc *quicConnector) reopen() (conn quic.Connection, err error) {
	if qc.conn != nil {
		qc.connHandler.closeConnWithError(qc.conn, qc.err)
	}

	qc.conn, qc.err = qc.connHandler.openConnection()
	if qc.err != nil {
		qc.reopenReady <- ready{}
	} else {
		qc.resetReady <- ready{}
	}

	return qc.conn, qc.err
}

func (qc *quicConnector) current() (conn quic.Connection, err error) {
	qc.mu.RLock()
	defer qc.mu.RUnlock()

	return qc.conn, qc.err
}

func (qc *quicConnector) close() {
	qc.mu.Lock()
	defer qc.mu.Unlock()

	if qc.conn != nil {
		qc.connHandler.closeConnWithError(qc.conn, qc.err)
	}
}

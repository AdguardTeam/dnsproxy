package upstream

import (
	"sync"

	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/log"
	"github.com/quic-go/quic-go"
)

// quicConnOpener is used to open a QUIC connection.
type quicConnOpener interface {
	// openConnection opens a QUIC connection with the specified configuration.
	openConnection(conf *quic.Config) (conn quic.Connection, err error)
}

// ready is a semantic alias for a sign of a ready action.
type ready = struct{}

// quicConnector is used to establish a single connection on several demands.
type quicConnector struct {
	// conf is the QUIC configuration that is used for establishing connections
	// to the upstream.  This configuration includes the TokenStore that needs
	// to be stored for re-creatin the connection on 0-RTT rejection.
	conf *quic.Config

	// mu protects the last establishment result.
	mu *sync.RWMutex

	// conn is the last established connection.  It is nil if the connection is
	// not established yet, closed or last connection establishment failed.
	conn quic.Connection

	// err is the error that occurred during the last connection establishment.
	err error

	// opener is used to open a new QUIC connection.
	opener quicConnOpener

	// openReady signs that the connection is ready to be established and either
	// the last connection establishment failed or the connection was reset.
	openReady chan ready

	// resetReady signs that the connection can be closed for future
	// establishment.
	resetReady chan ready
}

// newQUICConnector creates a new quicConnector.
func newQUICConnector(opener quicConnOpener, conf *quic.Config) (qc *quicConnector) {
	qc = &quicConnector{
		conf:       conf,
		mu:         &sync.RWMutex{},
		conn:       nil,
		err:        errors.Error("not initialized"),
		opener:     opener,
		openReady:  make(chan ready, 1),
		resetReady: make(chan ready, 1),
	}
	qc.openReady <- ready{}

	return qc
}

// reset enforces the next call to get to re-establish the connection.
func (qc *quicConnector) reset() {
	select {
	case <-qc.resetReady:
		qc.closeConn()
		qc.openReady <- ready{}
	default:
		// Already reset.
	}
}

// get returns the connection.  If the connection is not established yet, it
// will be established.  If the connection establishment fails, the next call
// to get will try to establish the connection again.
func (qc *quicConnector) get() (conn quic.Connection, err error) {
	select {
	case <-qc.openReady:
		qc.mu.Lock()
		defer qc.mu.Unlock()

		qc.conn, qc.err = qc.opener.openConnection(qc.conf)
		if qc.err != nil {
			qc.openReady <- ready{}
		} else {
			qc.resetReady <- ready{}
		}

		return qc.conn, qc.err
	default:
		return qc.current()
	}
}

// current returns the last established connection and connecting error.
func (qc *quicConnector) current() (conn quic.Connection, err error) {
	qc.mu.RLock()
	defer qc.mu.RUnlock()

	return qc.conn, qc.err
}

// closeConn closes the connection with the specified error.
func (qc *quicConnector) closeConn() {
	qc.mu.Lock()
	defer qc.mu.Unlock()

	if qc.conn == nil {
		return
	}

	code := QUICCodeNoError
	if qc.err != nil {
		code = QUICCodeInternalError
	}

	if errors.Is(qc.err, quic.Err0RTTRejected) {
		// Reset the TokenStore only if 0-RTT was rejected.
		qc.conf = qc.conf.Clone()
		qc.conf.TokenStore = newQUICTokenStore()
	}

	err := qc.conn.CloseWithError(code, "")
	if err != nil {
		log.Error("dnsproxy: closing quic conn: %v", err)
	}

	qc.conn = nil
}

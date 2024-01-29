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

	// openStream opens a QUIC stream on the specified connection.
	openStream(conn quic.Connection) (stream quic.Stream, err error)
}

// quicConnector is used to establish a single connection on several demands.
type quicConnector struct {
	// mu protects all the fields.
	mu *sync.Mutex

	// conf is the QUIC configuration that is used for establishing connections
	// to the upstream.  This configuration includes the TokenStore that needs
	// to be stored for re-creatin the connection on 0-RTT rejection.
	conf *quic.Config

	// conn is the last established connection.  It is nil if the connection is
	// not established yet, closed or last connection establishment failed.
	conn quic.Connection

	// opener is used to open a new QUIC connection.
	opener quicConnOpener

	// isOpened signs that there is a connection ready to open a stream on.
	isOpened bool
}

// newQUICConnector creates a new quicConnector.
func newQUICConnector(opener quicConnOpener, conf *quic.Config) (qc *quicConnector) {
	qc = &quicConnector{
		mu:       &sync.Mutex{},
		conf:     conf,
		conn:     nil,
		opener:   opener,
		isOpened: false,
	}

	return qc
}

// get returns the connection.  If the connection is not established yet, it
// will be established.  If the connection establishment fails, the next call
// to get will try to establish the connection again.
func (qc *quicConnector) get() (stream quic.Stream, err error) {
	qc.mu.Lock()
	defer qc.mu.Unlock()

	if !qc.isOpened {
		qc.conn, err = qc.opener.openConnection(qc.conf)
		if err != nil {
			qc.closeConnWithErr(err)

			return nil, err
		} else {
			qc.isOpened = true
		}
	}

	stream, err = qc.opener.openStream(qc.conn)
	if err != nil {
		// We can get here if the old QUIC connection is not valid anymore.  We
		// should try to re-create the connection again in this case.
		log.Debug("dnsproxy: opening quic stream: %s", err)
		qc.closeConnWithErr(err)

		return nil, err
	}

	return stream, nil
}

// close closes the connector and the active connection.
func (qc *quicConnector) close() {
	qc.mu.Lock()
	defer qc.mu.Unlock()

	qc.closeConnWithErr(nil)
}

// closeConnWithErr closes the connection with the specified error.  err can be
// nil.
func (qc *quicConnector) closeConnWithErr(err error) {
	qc.isOpened = false
	if qc.conn == nil {
		log.Debug("dnsproxy: closing not opened quic connection")

		return
	}

	code := QUICCodeNoError
	if err != nil {
		code = QUICCodeInternalError
	}

	if errors.Is(err, quic.Err0RTTRejected) {
		// Reset the TokenStore only if 0-RTT was rejected.
		qc.conf = qc.conf.Clone()
		qc.conf.TokenStore = newQUICTokenStore()
	}

	err = qc.conn.CloseWithError(code, "")
	if err != nil {
		log.Error("dnsproxy: closing quic conn: %v", err)
	}
}

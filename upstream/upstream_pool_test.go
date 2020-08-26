package upstream

import (
	"testing"
	"time"
)

func TestTLSPoolReconnect(t *testing.T) {
	u, err := AddressToUpstream("tls://one.one.one.one", Options{Bootstrap: []string{"8.8.8.8:53"}, Timeout: timeout})
	if err != nil {
		t.Fatalf("cannot create upstream: %s", err)
	}

	// Send the first test message
	req := createTestMessage()
	reply, err := u.Exchange(req)
	if err != nil {
		t.Fatalf("first DNS message failed: %s", err)
	}
	assertResponse(t, reply)

	// Now let's close the pooled connection and return it back to the pool
	p := u.(*dnsOverTLS)
	conn, _ := p.pool.Get()
	conn.Close()
	p.pool.Put(conn)

	// Send the second test message
	req = createTestMessage()
	reply, err = u.Exchange(req)
	if err != nil {
		t.Fatalf("second DNS message failed: %s", err)
	}
	assertResponse(t, reply)

	// Now assert that the number of connections in the pool is not changed
	if len(p.pool.conns) != 1 {
		t.Fatal("wrong number of pooled connections")
	}
}

func TestTLSPoolDeadLine(t *testing.T) {
	// Create TLS upstream
	u, err := AddressToUpstream("tls://one.one.one.one", Options{Bootstrap: []string{"8.8.8.8:53"}, Timeout: timeout})
	if err != nil {
		t.Fatalf("cannot create upstream: %s", err)
	}

	// Send the first test message
	req := createTestMessage()
	response, err := u.Exchange(req)
	if err != nil {
		t.Fatalf("first DNS message failed: %s", err)
	}
	assertResponse(t, response)

	p := u.(*dnsOverTLS)

	// Now let's get connection from the pool and use it
	conn, err := p.pool.Get()
	if err != nil {
		t.Fatalf("couldn't get connection from pool: %s", err)
	}
	response, err = p.exchangeConn(conn, req)
	if err != nil {
		t.Fatalf("first DNS message failed: %s", err)
	}
	assertResponse(t, response)

	// Update connection's deadLine and put it back to the pool
	err = conn.SetDeadline(time.Now().Add(10 * time.Hour))
	if err != nil {
		t.Fatalf("can't set new deadLine for connection. Looks like it's already closed: %s", err)
	}
	p.pool.Put(conn)

	// Get connection from the pool and reuse it
	conn, err = p.pool.Get()
	if err != nil {
		t.Fatalf("couldn't get connection from pool: %s", err)
	}
	response, err = p.exchangeConn(conn, req)
	if err != nil {
		t.Fatalf("first DNS message failed: %s", err)
	}
	assertResponse(t, response)

	// Set connection's deadLine to the past and try to reuse it
	err = conn.SetDeadline(time.Now().Add(-10 * time.Hour))
	if err != nil {
		t.Fatalf("can't set new deadLine for connection. Looks like it's already closed: %s", err)
	}

	// Connection with expired deadLine can't be used
	response, err = p.exchangeConn(conn, req)
	if err == nil {
		t.Fatalf("this connection should be already closed, got response %s", response)
	}
}

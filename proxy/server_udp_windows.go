package proxy

import "net"

func udpGetOOBSize() int {
	return 0
}

func udpSetOptions(c *net.UDPConn) error {
	return nil
}

func (p *Proxy) udpRead(c *net.UDPConn, buf []byte) (int, net.IP, *net.UDPAddr, error) {
	n, addr, err := c.ReadFrom(buf)
	var udpAddr *net.UDPAddr
	if addr != nil {
		udpAddr = addr.(*net.UDPAddr)
	}
	return n, nil, udpAddr, err
}

func udpWrite(bytes []byte, d *DNSContext) (int, error) {
	conn := d.Conn.(*net.UDPConn)
	return conn.WriteTo(bytes, d.Addr)
}

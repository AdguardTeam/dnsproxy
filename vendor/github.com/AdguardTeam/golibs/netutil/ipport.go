package netutil

import (
	"net"

	"golang.org/x/exp/slices"
)

// IPPort And Utilities

// IPPort is a convenient type for network addresses that contain an IP address
// and a port, like "1.2.3.4:56789" or "[1234::cdef]:12345".
//
// Deprecated: use netip.AddrPort.
type IPPort struct {
	IP   net.IP
	Port int
}

// IPPortFromAddr returns an *IPPort from a if its underlying type is either
// *net.TCPAddr or *net.UDPAddr.  Otherwise, it returns nil.
func IPPortFromAddr(a net.Addr) (ipp *IPPort) {
	ip, port := IPAndPortFromAddr(a)
	if ip == nil {
		return nil
	}

	return &IPPort{
		IP:   slices.Clone(ip),
		Port: port,
	}
}

// ParseIPPort parses an *IPPort from addr.  Any error returned will have the
// underlying type of *AddrError.
func ParseIPPort(addr string) (ipp *IPPort, err error) {
	defer makeAddrError(&err, addr, AddrKindIPPort)

	var host string
	var port int
	host, port, err = SplitHostPort(addr)
	if err != nil {
		return nil, err
	}

	var ip net.IP
	ip, err = ParseIP(host)
	if err != nil {
		return nil, err
	}

	return &IPPort{
		IP:   ip,
		Port: port,
	}, nil
}

// CloneIPPorts returns a deep copy of ipps.
func CloneIPPorts(ipps []*IPPort) (clone []*IPPort) {
	if ipps == nil {
		return nil
	}

	clone = make([]*IPPort, len(ipps))
	for i, hp := range ipps {
		clone[i] = hp.Clone()
	}

	return clone
}

// Clone returns a clone of ipp.
func (ipp *IPPort) Clone() (clone *IPPort) {
	if ipp == nil {
		return nil
	}

	return &IPPort{
		IP:   slices.Clone(ipp.IP),
		Port: ipp.Port,
	}
}

// MarshalText implements the encoding.TextMarshaler interface for IPPort.
func (ipp IPPort) MarshalText() (b []byte, err error) {
	return []byte(ipp.String()), nil
}

// String implements the fmt.Stringer interface for *IPPort.
func (ipp IPPort) String() (s string) {
	var ipStr string
	if ipp.IP != nil {
		ipStr = ipp.IP.String()
	}

	return JoinHostPort(ipStr, ipp.Port)
}

// TCP returns a *net.TCPAddr with a clone of ipp's IP address and its port.
func (ipp *IPPort) TCP() (a *net.TCPAddr) {
	return &net.TCPAddr{
		IP:   slices.Clone(ipp.IP),
		Port: ipp.Port,
	}
}

// UDP returns a *net.UDPAddr with a clone of ipp's IP address and its port.
func (ipp *IPPort) UDP() (a *net.UDPAddr) {
	return &net.UDPAddr{
		IP:   slices.Clone(ipp.IP),
		Port: ipp.Port,
	}
}

// UnmarshalText implements the encoding.TextUnmarshaler interface for *IPPort.
// Any error returned will have the underlying type of *AddrError.
func (ipp *IPPort) UnmarshalText(b []byte) (err error) {
	var newIPP *IPPort
	newIPP, err = ParseIPPort(string(b))
	if err != nil {
		return err
	}

	*ipp = *newIPP

	return nil
}

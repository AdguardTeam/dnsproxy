package netutil

import (
	"net"
)

// ipArr is a representation of an IP address as an array of bytes.
type ipArr [16]byte

// String implements the fmt.Stringer interface for ipArr.
func (a ipArr) String() (s string) {
	return net.IP(a[:]).String()
}

// ipToArr converts a net.IP into an ipArr.
//
// TODO(a.garipov): Use the slice-to-array conversion in Go 1.17.
func ipToArr(ip net.IP) (a ipArr) {
	copy(a[:], ip.To16())

	return a
}

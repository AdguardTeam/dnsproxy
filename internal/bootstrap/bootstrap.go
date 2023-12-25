// Package bootstrap provides types and functions to resolve upstream hostnames
// and to dial retrieved addresses.
package bootstrap

// Network is a network type for use in [Resolver]'s methods.
type Network = string

const (
	// NetworkIP is a network type for both address families.
	NetworkIP Network = "ip"

	// NetworkIP4 is a network type for IPv4 address family.
	NetworkIP4 Network = "ip4"

	// NetworkIP6 is a network type for IPv6 address family.
	NetworkIP6 Network = "ip6"

	// NetworkTCP is a network type for TCP connections.
	NetworkTCP Network = "tcp"

	// NetworkUDP is a network type for UDP connections.
	NetworkUDP Network = "udp"
)

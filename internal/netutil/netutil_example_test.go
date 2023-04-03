package netutil_test

import (
	"fmt"
	"net"

	"github.com/AdguardTeam/dnsproxy/internal/netutil"
)

func ExampleSortIPAddrs() {
	printAddrs := func(header string, addrs []net.IPAddr) {
		fmt.Printf("%s:\n", header)
		for i, a := range addrs {
			fmt.Printf("%d: %s\n", i+1, a.IP)
		}

		fmt.Println()
	}

	addrs := []net.IPAddr{{
		IP: net.ParseIP("1.2.3.4"),
	}, {
		IP: net.ParseIP("1.2.3.5"),
	}, {
		IP: net.ParseIP("2a00::1234"),
	}, {
		IP: net.ParseIP("2a00::1235"),
	}, {
		IP: nil,
	}}
	netutil.SortIPAddrs(addrs, false)
	printAddrs("IPv4 preferred", addrs)

	netutil.SortIPAddrs(addrs, true)
	printAddrs("IPv6 preferred", addrs)

	// Output:
	//
	// IPv4 preferred:
	// 1: 1.2.3.4
	// 2: 1.2.3.5
	// 3: 2a00::1234
	// 4: 2a00::1235
	// 5: <nil>
	//
	// IPv6 preferred:
	// 1: 2a00::1234
	// 2: 2a00::1235
	// 3: 1.2.3.4
	// 4: 1.2.3.5
	// 5: <nil>
}

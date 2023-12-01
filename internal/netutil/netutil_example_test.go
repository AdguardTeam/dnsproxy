package netutil_test

import (
	"fmt"
	"net/netip"

	"github.com/AdguardTeam/dnsproxy/internal/netutil"
)

func ExampleSortNetIPAddrs() {
	printAddrs := func(header string, addrs []netip.Addr) {
		fmt.Printf("%s:\n", header)
		for i, a := range addrs {
			fmt.Printf("%d: %s\n", i+1, a)
		}

		fmt.Println()
	}

	addrs := []netip.Addr{
		netip.MustParseAddr("1.2.3.4"),
		netip.MustParseAddr("1.2.3.5"),
		netip.MustParseAddr("2a00::1234"),
		netip.MustParseAddr("2a00::1235"),
		{},
	}
	netutil.SortNetIPAddrs(addrs, false)
	printAddrs("IPv4 preferred", addrs)

	netutil.SortNetIPAddrs(addrs, true)
	printAddrs("IPv6 preferred", addrs)

	// Output:
	//
	// IPv4 preferred:
	// 1: 1.2.3.4
	// 2: 1.2.3.5
	// 3: 2a00::1234
	// 4: 2a00::1235
	// 5: invalid IP
	//
	// IPv6 preferred:
	// 1: 2a00::1234
	// 2: 2a00::1235
	// 3: 1.2.3.4
	// 4: 1.2.3.5
	// 5: invalid IP
}

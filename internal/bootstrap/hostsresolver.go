package bootstrap

import (
	"context"
	"fmt"
	"io/fs"
	"net/netip"

	"github.com/AdguardTeam/dnsproxy/internal/netutil"
	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/hostsfile"
	"github.com/AdguardTeam/golibs/log"
	"golang.org/x/exp/slices"
)

// HostsResolver is a [Resolver] that uses [netutil.Hosts] as a source of IP.
type HostsResolver struct {
	// addrs is an actual source of IP addresses.
	addrs map[string][]netip.Addr
}

// NewHostsResolver is the resolver based on system hosts files.
func NewHostsResolver(hosts *netutil.Hosts) (hr *HostsResolver) {
	hr = &HostsResolver{}
	_, hr.addrs = hosts.Mappings()

	return hr
}

// NewDefaultHostsResolver returns a resolver based on system hosts files
// provided by the [hostsfile.DefaultHostsPaths] and read from rootFSys.
//
// TODO(e.burkov):  Use.
func NewDefaultHostsResolver(rootFSys fs.FS) (hr *HostsResolver, err error) {
	paths, err := hostsfile.DefaultHostsPaths()
	if err != nil {
		return nil, fmt.Errorf("getting default hosts paths: %w", err)
	}

	hosts, _ := netutil.NewHosts()
	for _, name := range paths {
		err = parseHostsFile(rootFSys, hosts, name)
		if err != nil {
			// Don't wrap the error since it's already informative enough as is.
			return nil, err
		}
	}

	return NewHostsResolver(hosts), nil
}

// parseHostsFile reads a single hosts file from fsys and parses it into hosts.
func parseHostsFile(fsys fs.FS, hosts *netutil.Hosts, name string) (err error) {
	f, err := fsys.Open(name)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			log.Debug("hosts file %q doesn't exist", name)

			return nil
		}

		// Don't wrap the error since it's already informative enough as is.
		return err
	}

	// TODO(e.burkov):  Use [errors.Join] when it will be supported by all
	// dependencies.
	defer func() { err = errors.WithDeferred(err, f.Close()) }()

	return hostsfile.Parse(hosts, f, nil)
}

// type check
var _ Resolver = (*HostsResolver)(nil)

// LookupNetIP implements the [Resolver] interface for *hostsResolver.
func (hr *HostsResolver) LookupNetIP(
	context context.Context,
	network string,
	host string,
) (addrs []netip.Addr, err error) {
	var checkIP func(netip.Addr) (ok bool)
	switch network {
	case "ip4":
		addrs, checkIP = slices.Clone(hr.addrs[host]), netip.Addr.Is6
	case "ip6":
		addrs, checkIP = slices.Clone(hr.addrs[host]), netip.Addr.Is4
	case "ip":
		return slices.Clone(hr.addrs[host]), nil
	default:
		return nil, fmt.Errorf("unsupported network %q", network)
	}

	return slices.DeleteFunc(addrs, checkIP), nil
}

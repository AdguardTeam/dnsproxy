package upstream

import (
	"context"
	"fmt"
	"io/fs"
	"net/netip"
	"slices"

	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/hostsfile"
	"github.com/AdguardTeam/golibs/log"
)

// HostsResolver is a [Resolver] that looks into system hosts files, see
// [hostsfile].
type HostsResolver struct {
	// strg contains all the hosts file data needed for lookups.
	strg hostsfile.Storage
}

// NewHostsResolver is the resolver based on system hosts files.
func NewHostsResolver(hosts hostsfile.Storage) (hr *HostsResolver) {
	return &HostsResolver{
		strg: hosts,
	}
}

// NewDefaultHostsResolver returns a resolver based on system hosts files
// provided by the [hostsfile.DefaultHostsPaths] and read from rootFSys.
func NewDefaultHostsResolver(rootFSys fs.FS) (hr *HostsResolver, err error) {
	paths, err := hostsfile.DefaultHostsPaths()
	if err != nil {
		return nil, fmt.Errorf("getting default hosts paths: %w", err)
	}

	// The error is always nil here since no readers passed.
	strg, _ := hostsfile.NewDefaultStorage()
	for _, filename := range paths {
		err = parseHostsFile(rootFSys, strg, filename)
		if err != nil {
			// Don't wrap the error since it's already informative enough as is.
			return nil, err
		}
	}

	return NewHostsResolver(strg), nil
}

// parseHostsFile reads a single hosts file from fsys and parses it into hosts.
func parseHostsFile(fsys fs.FS, hosts hostsfile.Set, filename string) (err error) {
	f, err := fsys.Open(filename)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			log.Debug("hosts file %q doesn't exist", filename)

			return nil
		}

		// Don't wrap the error since it's already informative enough as is.
		return err
	}

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
	var ipMatches func(netip.Addr) (ok bool)
	switch network {
	case "ip4":
		ipMatches = netip.Addr.Is4
	case "ip6":
		ipMatches = netip.Addr.Is6
	case "ip":
		return slices.Clone(hr.strg.ByName(host)), nil
	default:
		return nil, fmt.Errorf("unsupported network %q", network)
	}

	for _, addr := range hr.strg.ByName(host) {
		if ipMatches(addr) {
			addrs = append(addrs, addr)
		}
	}

	return addrs, nil
}

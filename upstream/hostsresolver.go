package upstream

import (
	"context"
	"fmt"
	"io/fs"
	"log/slog"
	"net/netip"
	"slices"

	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/hostsfile"
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
// provided by the [hostsfile.DefaultHostsPaths] and read from rootFSys.  In
// case the file by any default path doesn't exist it adds a log debug record.
// If l is nil, [slog.Default] is used.
func NewDefaultHostsResolver(rootFSys fs.FS, l *slog.Logger) (hr *HostsResolver, err error) {
	if l == nil {
		l = slog.Default()
	}

	paths, err := hostsfile.DefaultHostsPaths()
	if err != nil {
		return nil, fmt.Errorf("getting default hosts paths: %w", err)
	}

	// The error is always nil here since no readers passed.
	strg, _ := hostsfile.NewDefaultStorage()
	for _, filename := range paths {
		err = parseHostsFile(rootFSys, strg, filename, l)
		if err != nil {
			// Don't wrap the error since it's already informative enough as is.
			return nil, err
		}
	}

	return NewHostsResolver(strg), nil
}

// parseHostsFile reads a single hosts file from fsys and parses it into hosts.
func parseHostsFile(fsys fs.FS, hosts hostsfile.Set, filename string, l *slog.Logger) (err error) {
	f, err := fsys.Open(filename)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			l.Debug("hosts file does not exist", "filename", filename)

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

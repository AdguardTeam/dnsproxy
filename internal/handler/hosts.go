package handler

import (
	"context"
	"fmt"
	"net/netip"
	"os"
	"slices"
	"strings"

	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/hostsfile"
	"github.com/AdguardTeam/golibs/logutil/slogutil"
	"github.com/AdguardTeam/golibs/netutil"
	"github.com/miekg/dns"
)

// emptyStorage is a [hostsfile.Storage] that contains no records.
//
// TODO(e.burkov):  Move to [hostsfile].
type emptyStorage [0]hostsfile.Record

// type check
var _ hostsfile.Storage = emptyStorage{}

// ByAddr implements the [hostsfile.Storage] interface for [emptyStorage].
func (emptyStorage) ByAddr(_ netip.Addr) (names []string) {
	return nil
}

// ByName implements the [hostsfile.Storage] interface for [emptyStorage].
func (emptyStorage) ByName(_ string) (addrs []netip.Addr) {
	return nil
}

// ReadHosts reads the hosts files from the file system and returns a storage
// with parsed records.  strg is always usable even if an error occurred.
func ReadHosts(paths []string) (strg hostsfile.Storage, err error) {
	// Don't check the error since it may only appear when any readers used.
	defaultStrg, _ := hostsfile.NewDefaultStorage()

	var errs []error
	for _, path := range paths {
		err = readHostsFile(defaultStrg, path)
		if err != nil {
			// Don't wrap the error since it's informative enough as is.
			errs = append(errs, err)
		}
	}

	// TODO(e.burkov):  Add method for length.
	isEmpty := true
	defaultStrg.RangeAddrs(func(_ string, _ []netip.Addr) (cont bool) {
		isEmpty = false

		return false
	})

	if isEmpty {
		return emptyStorage{}, errors.Join(errs...)
	}

	return defaultStrg, errors.Join(errs...)
}

// readHostsFile reads the hosts file at path and parses it into strg.
func readHostsFile(strg *hostsfile.DefaultStorage, path string) (err error) {
	// #nosec G304 -- Trust the file path from the configuration file.
	f, err := os.Open(path)
	if err != nil {
		// Don't wrap the error since it's informative enough as is.
		return err
	}

	defer func() { err = errors.WithDeferred(err, f.Close()) }()

	err = hostsfile.Parse(strg, f, nil)
	if err != nil {
		return fmt.Errorf("parsing hosts file %q: %w", path, err)
	}

	return nil
}

// resolveFromHosts resolves the DNS query from the hosts file.  It fills the
// response with the A, AAAA, and PTR records from the hosts file.
func (h *Default) resolveFromHosts(ctx context.Context, req *dns.Msg) (resp *dns.Msg) {
	var addrs []netip.Addr
	var ptrs []string

	q := req.Question[0]
	name := strings.TrimSuffix(q.Name, ".")
	switch q.Qtype {
	case dns.TypeA:
		addrs = slices.Clone(h.hosts.ByName(name))
		addrs = slices.DeleteFunc(addrs, netip.Addr.Is6)
	case dns.TypeAAAA:
		addrs = slices.Clone(h.hosts.ByName(name))
		addrs = slices.DeleteFunc(addrs, netip.Addr.Is4)
	case dns.TypePTR:
		addr, err := netutil.IPFromReversedAddr(name)
		if err != nil {
			h.logger.DebugContext(ctx, "failed parsing ptr", slogutil.KeyError, err)

			return nil
		}

		ptrs = h.hosts.ByAddr(addr)
	default:
		return nil
	}

	switch {
	case len(addrs) > 0:
		resp = h.messages.NewIPResponse(req, addrs)
	case len(ptrs) > 0:
		resp = h.messages.NewCompressedResponse(req, dns.RcodeSuccess)
		name = req.Question[0].Name
		for _, ptr := range ptrs {
			resp.Answer = append(resp.Answer, h.messages.NewPTRAnswer(name, dns.Fqdn(ptr)))
		}
	default:
		h.logger.DebugContext(ctx, "no hosts records found", "name", name, "qtype", q.Qtype)
	}

	return resp
}

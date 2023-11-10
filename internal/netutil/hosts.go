package netutil

import (
	"fmt"
	"io"
	"net/netip"
	"strings"

	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/hostsfile"
	"github.com/AdguardTeam/golibs/log"
	"golang.org/x/exp/slices"
)

// unit is a convenient alias for empty struct.
type unit = struct{}

// set is a helper type that removes duplicates.
type set[K string | netip.Addr] map[K]unit

// orderedSet is a helper type for storing values in original adding order and
// dealing with duplicates.
type orderedSet[K string | netip.Addr] struct {
	set  set[K]
	vals []K
}

// add adds val to os if it's not already there.
func (os *orderedSet[K]) add(key, val K) {
	if _, ok := os.set[key]; !ok {
		os.set[key] = unit{}
		os.vals = append(os.vals, val)
	}
}

// Convenience aliases for [orderedSet].
type (
	namesSet = orderedSet[string]
	addrsSet = orderedSet[netip.Addr]
)

// Hosts is a [hostsfile.HandleSet] that removes duplicates.
//
// It must be initialized with [NewHosts].
//
// TODO(e.burkov):  Think of storing only slices.
//
// TODO(e.burkov):  Move to netutil/hostsfile in module golibs as a default
// implementation of some storage interface.
type Hosts struct {
	// names maps each address to its names in original case and in original
	// adding order without duplicates.
	names map[netip.Addr]*namesSet

	// addrs maps each host to its addresses in original adding order without
	// duplicates.
	addrs map[string]*addrsSet
}

// NewHosts parses hosts files from r and returns a new Hosts set.  readers are
// optional, the error is only returned in case of parsing error.
func NewHosts(readers ...io.Reader) (h *Hosts, err error) {
	h = &Hosts{
		names: map[netip.Addr]*namesSet{},
		addrs: map[string]*addrsSet{},
	}

	for i, r := range readers {
		if err = hostsfile.Parse(h, r, nil); err != nil {
			return nil, fmt.Errorf("reader at index %d: %w", i, err)
		}
	}

	return h, nil
}

// type check
var _ hostsfile.HandleSet = (*Hosts)(nil)

// Add implements the [hostsfile.Set] interface for *Hosts.
func (h *Hosts) Add(rec *hostsfile.Record) {
	names := h.names[rec.Addr]
	if names == nil {
		names = &namesSet{set: set[string]{}}
		h.names[rec.Addr] = names
	}

	for _, name := range rec.Names {
		lowered := strings.ToLower(name)
		names.add(lowered, name)

		addrs := h.addrs[lowered]
		if addrs == nil {
			addrs = &addrsSet{
				vals: []netip.Addr{},
				set:  set[netip.Addr]{},
			}
			h.addrs[lowered] = addrs
		}
		addrs.add(rec.Addr, rec.Addr)
	}
}

// HandleInvalid implements the [hostsfile.HandleSet] interface for *Hosts.
func (h *Hosts) HandleInvalid(srcName string, _ []byte, err error) {
	lineErr := &hostsfile.LineError{}
	if !errors.As(err, &lineErr) {
		log.Debug("hostset: unexpected error from hostsfile: %s", err)

		return
	}

	if errors.Is(err, hostsfile.ErrEmptyLine) {
		// Ignore empty lines and comments.
		return
	}

	log.Debug("hostset: source %q: %s", srcName, lineErr)
}

// ByAddr returns each host for addr in original case, in original adding order
// without duplicates.  It returns nil if h doesn't contain the addr.
func (h *Hosts) ByAddr(addr netip.Addr) (hosts []string) {
	if hostsSet, ok := h.names[addr]; ok {
		return hostsSet.vals
	}

	return nil
}

// ByName returns each address for host in original adding order without
// duplicates.  It returns nil if h doesn't contain the host.
func (h *Hosts) ByName(host string) (addrs []netip.Addr) {
	if addrsSet, ok := h.addrs[strings.ToLower(host)]; ok {
		return addrsSet.vals
	}

	return nil
}

// Mappings returns a deep clone of the internal mappings.
func (h *Hosts) Mappings() (names map[netip.Addr][]string, addrs map[string][]netip.Addr) {
	names = make(map[netip.Addr][]string, len(h.names))
	addrs = make(map[string][]netip.Addr, len(h.addrs))

	for addr, namesSet := range h.names {
		names[addr] = slices.Clone(namesSet.vals)
	}

	for name, addrsSet := range h.addrs {
		addrs[name] = slices.Clone(addrsSet.vals)
	}

	return names, addrs
}

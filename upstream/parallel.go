package upstream

import (
	"context"
	"net"
	"time"

	"github.com/hmage/golibs/log"
	"github.com/joomcode/errorx"
	"github.com/miekg/dns"
)

// exchangeResult is a structure that represents result of exchange
type exchangeResult struct {
	reply   *dns.Msg
	elapsed time.Duration
	err     error
}

// ExchangeParallel function is called to parallel exchange dns request by many upstreams
// First answer without error will be returned
// We will return nil and error if count of errors equals count of upstreams
func ExchangeParallel(u []Upstream, req *dns.Msg) (*dns.Msg, error) {
	size := len(u)
	ch := make(chan *exchangeResult, size)

	for _, f := range u {
		go exchange(f, req, ch)
	}

	var count int
	for {
		select {
		case rep := <-ch:
			reply := rep.reply
			err := rep.err
			if err != nil {
				log.Printf("fail to exchange : %s", err)
				count++
			}

			if count == size {
				return nil, errorx.Decorate(err, "all upstreams failed to exchange")
			}

			if reply != nil && err == nil {
				return reply, nil
			}
		}
	}
}

// exchange tries to resolve DNS request with one upstream and send result to resp channel
func exchange(u Upstream, req *dns.Msg, resp chan *exchangeResult) {
	start := time.Now()
	reply, err := u.Exchange(req)
	elapsed := time.Since(start)
	resp <- &exchangeResult{
		reply:   reply,
		elapsed: elapsed,
		err:     err,
	}
}

// lookupResult is a structure that represents result of lookup
type lookupResult struct {
	err     error
	address []net.IPAddr
}

// LookupParallel starts parallel lookup for host ip with many resolvers
// First answer without error will be returned
// Return nil and error if count of errors equals count of resolvers
func LookupParallel(ctx context.Context, resolvers []*net.Resolver, host string) ([]net.IPAddr, error) {
	size := len(resolvers)

	ch := make(chan *lookupResult, size)

	resolver := resolvers // no need to check for nil resolver -- documented that nil is default resolver
	for _, res := range resolver {
		go lookup(ctx, res, host, ch)
	}

	var count int
	for {
		select {
		case result := <-ch:
			addr := result.address
			err := result.err
			if err != nil {
				log.Printf("fail to lookup : %s", err)
				count++
			}

			if count == size {
				return nil, errorx.Decorate(err, "all resolvers failed to lookup")
			}

			if addr != nil && err == nil {
				return addr, nil
			}
		}
	}
}

// lookup tries to lookup for host ip with one resolver and sends lookupResult to res channel
func lookup(ctx context.Context, resolver *net.Resolver, host string, res chan *lookupResult) {
	address, err := resolver.LookupIPAddr(ctx, host)
	res <- &lookupResult{
		err:     err,
		address: address,
	}
}

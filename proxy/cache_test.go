package proxy

import (
	"strings"
	"testing"
	"time"

	"github.com/go-test/deep"
	"github.com/miekg/dns"
)

func TestCacheSanity(t *testing.T) {
	testCache := cache{}
	request := dns.Msg{}
	request.SetQuestion("google.com.", dns.TypeA)
	_, ok := testCache.Get(&request)
	if ok {
		t.Fatal("empty cache replied with positive response")
	}
}

func TestServeCached(t *testing.T) {
	// Prepare the proxy server
	dnsProxy := createTestProxy(t, nil)
	dnsProxy.CacheEnabled = true // just one request per second is allowed

	// Start listening
	err := dnsProxy.Start()
	if err != nil {
		t.Fatalf("cannot start the DNS proxy: %s", err)
	}

	// Fill the cache
	reply := dns.Msg{}
	reply.SetQuestion("google.com.", dns.TypeA)
	reply.Response = true
	reply.Answer = []dns.RR{newRR("google.com. 3600 IN A 8.8.8.8")}
	dnsProxy.cache.Set(&reply)

	// Create a DNS-over-UDP client connection
	addr := dnsProxy.Addr("udp")
	client := &dns.Client{Net: "udp", Timeout: 500 * time.Millisecond}

	// Create a DNS request
	request := dns.Msg{}
	request.Id = dns.Id()
	request.RecursionDesired = true
	request.SetQuestion("google.com.", dns.TypeA)

	r, _, err := client.Exchange(&request, addr.String())
	if err != nil {
		t.Fatalf("error in the first request: %s", err)
	}

	if diff := deepEqualMsg(r, &reply); diff != nil {
		t.Error(diff)
	}

	// Stop the proxy
	err = dnsProxy.Stop()
	if err != nil {
		t.Fatalf("cannot stop the DNS proxy: %s", err)
	}
}

func TestCache(t *testing.T) {
	tests := testCases{
		cache: []testEntry{
			{q: "google.com.", t: dns.TypeA, a: []dns.RR{newRR("google.com. 3600 IN A 8.8.8.8")}},
		},
		cases: []testCase{
			{q: "google.com.", t: dns.TypeA, a: []dns.RR{newRR("google.com. 3600 IN A 8.8.8.8")}, ok: true},
			{q: "google.com.", t: dns.TypeMX, ok: false},
		},
	}
	runTests(t, tests)
}

func TestCacheMixedCase(t *testing.T) {
	tests := testCases{
		cache: []testEntry{
			{q: "gOOgle.com.", t: dns.TypeA, a: []dns.RR{newRR("google.com. 3600 IN A 8.8.8.8")}},
		},
		cases: []testCase{
			{q: "gOOgle.com.", t: dns.TypeA, a: []dns.RR{newRR("google.com. 3600 IN A 8.8.8.8")}, ok: true},
			{q: "google.com.", t: dns.TypeA, a: []dns.RR{newRR("google.com. 3600 IN A 8.8.8.8")}, ok: true},
			{q: "GOOGLE.COM.", t: dns.TypeA, a: []dns.RR{newRR("google.com. 3600 IN A 8.8.8.8")}, ok: true},
			{q: "gOOgle.com.", t: dns.TypeMX, ok: false},
			{q: "google.com.", t: dns.TypeMX, ok: false},
			{q: "GOOGLE.COM.", t: dns.TypeMX, ok: false},
		},
	}
	runTests(t, tests)
}

func TestZeroTTL(t *testing.T) {
	tests := testCases{
		cache: []testEntry{
			{q: "gOOgle.com.", t: dns.TypeA, a: []dns.RR{newRR("google.com. 0 IN A 8.8.8.8")}},
		},
		cases: []testCase{
			{q: "google.com.", t: dns.TypeA, ok: false},
			{q: "google.com.", t: dns.TypeA, ok: false},
			{q: "google.com.", t: dns.TypeA, ok: false},
			{q: "google.com.", t: dns.TypeMX, ok: false},
			{q: "google.com.", t: dns.TypeMX, ok: false},
			{q: "google.com.", t: dns.TypeMX, ok: false},
		},
	}
	runTests(t, tests)
}

func runTests(t *testing.T, tests testCases) {
	t.Helper()
	testCache := cache{}
	for _, tc := range tests.cache {
		reply := dns.Msg{}
		reply.SetQuestion(tc.q, tc.t)
		reply.Response = true
		reply.Answer = tc.a
		testCache.Set(&reply)
	}
	for _, tc := range tests.cases {
		request := dns.Msg{}
		request.SetQuestion(tc.q, tc.t)
		val, ok := testCache.Get(&request)
		if diff := deep.Equal(ok, tc.ok); diff != nil {
			t.Error(diff)
		}
		if tc.a != nil {
			if ok == false {
				continue
			}
			reply := dns.Msg{}
			reply.SetQuestion(tc.q, tc.t)
			reply.Response = true
			reply.Answer = tc.a
			testCache.Set(&reply)
			if diff := deepEqualMsg(val, &reply); diff != nil {
				t.Error(diff)
			} else {
				if diff := deep.Equal(val, reply); diff == nil {
					t.Error("different message ID were not caught")
				}
			}
		}
	}
}

type testCases struct {
	cache []testEntry
	cases []testCase
}

type testEntry struct {
	q string
	t uint16
	a []dns.RR
}

type testCase struct {
	q  string
	t  uint16
	a  []dns.RR
	ok bool
}

func newRR(rr string) dns.RR {
	r, err := dns.NewRR(rr)
	if err != nil {
		panic(err)
	}
	return r
}

// deepEqual is same as deep.Equal, except:
//  * ignores Id when comparing
//  * ignores Rdlength
//  * question names are not case sensetive
func deepEqualMsg(left *dns.Msg, right *dns.Msg) []string {
	temp := *left
	temp.Id = right.Id
	if len(temp.Answer) == 1 && len(right.Answer) == 1 {
		temp.Answer[0].Header().Rdlength = right.Answer[0].Header().Rdlength
	}
	for i := range left.Question {
		left.Question[i].Name = strings.ToLower(left.Question[i].Name)
	}
	for i := range right.Question {
		right.Question[i].Name = strings.ToLower(right.Question[i].Name)
	}
	return deep.Equal(&temp, right)
}

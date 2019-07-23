/*
Package mobile contains a simple mobile API for github.com/AdguardTeam/dnsproxy
*/
package mobile

import (
	"errors"
	"fmt"
	"net"
	"runtime/debug"
	"strings"
	"sync"
	"time"

	"github.com/AdguardTeam/dnsproxy/proxy"
	"github.com/AdguardTeam/dnsproxy/upstream"
	"github.com/AdguardTeam/golibs/log"
	"github.com/AdguardTeam/urlfilter"
	"github.com/joomcode/errorx"
	"github.com/miekg/dns"
)

//nolint
func init() {
	// https://github.com/golang/go/issues/21489
	debug.SetGCPercent(5)

	// Load a limited set of root CAs (in order to consume less memory)
	upstream.RootCAs = loadSystemRootCAs()
	upstream.DohMaxConnsPerHost = 2

	// TODO after GO 1.13 release TLS 1.3 will be enabled by default. Remove this afterward
	//os.Setenv("GODEBUG", os.Getenv("GODEBUG")+",tls13=1")
}

// DNSProxy represents a proxy with it's configuration
type DNSProxy struct {
	Config          *Config          // Proxy configuration
	FilteringConfig *FilteringConfig // Filtering configuration

	dnsProxy *proxy.Proxy
	sync.RWMutex

	filteringEngine *filteringEngine // Filtering structures and properties
}

// Config is the DNS proxy configuration which uses only the subset of types that is supported by gomobile
// In Java API this structure becomes an object that needs to be configured and set as field of DNSProxy
type Config struct {
	ListenAddr        string // IP address to listen to
	ListenPort        int    // Port to listen to
	BootstrapDNS      string // A list of bootstrap DNS (i.e. 8.8.8.8:53 each on a new line)
	Fallbacks         string // A list of fallback resolvers that will be used if the main one is not available (i.e. 1.1.1.1:53 each on a new line)
	Upstreams         string // A list of upstream resolvers (each on a new line)
	Timeout           int    // Default timeout for all resolvers (milliseconds)
	CacheSizeBytes    int    // Cache size (in bytes). Default: 64k
	AllServers        bool   // If true, parallel queries to all configured upstream servers are enabled
	MaxGoroutines     int    // Maximum number of parallel goroutines that process the requests
	SystemResolvers   string // A list of system resolvers for ipv6-only network (each on new line). We need to specify it to use dns.Client instead of default net.Resolver
	DetectDNS64Prefix bool   // If true, DNS64 prefix detection is enabled
}

// FilteringConfig is the filteringEngine configuration
type FilteringConfig struct {
	FilteringRulesFilesJSON   string // Filtering rules files JSON (list of "id": filterListID, "path": "path/to/filter")
	FilteringRulesStringsJSON string // Filtering rules string JSON (list of "id": filterListID, "content": "filtering rules one per line")
	BlockType                 int    // Block type for filtering rules
}

// Start starts the DNS proxy
func (d *DNSProxy) Start() error {
	d.Lock()
	defer d.Unlock()

	if d.dnsProxy != nil {
		return errors.New("DNS proxy is already started")
	}

	// Create filtering engine
	err := d.createFilteringEngine(d.FilteringConfig)
	if err != nil {
		return fmt.Errorf("cannot start the DNS proxy: %s", err)
	}

	// Start proxy
	return d.startProxy()
}

// createFilteringEngine create and set filteringEngine
func (d *DNSProxy) createFilteringEngine(f *FilteringConfig) error {
	if f != nil && (len(f.FilteringRulesStringsJSON) > 0 || len(f.FilteringRulesFilesJSON) > 0) {
		if f.BlockType != BlockTypeUnspecifiedIP && f.BlockType != BlockTypeRule && f.BlockType != BlockTypeNXDomain {
			return fmt.Errorf("unknown block type %d", f.BlockType)
		}

		engine := &filteringEngine{}
		ruleLists := []urlfilter.RuleList{}
		err := addFileRuleLists(f.FilteringRulesFilesJSON, &ruleLists)
		if err != nil {
			return fmt.Errorf("failed to initialize DNS Filtering Engine: %v", err)
		}

		err = addStringRuleLists(f.FilteringRulesStringsJSON, &ruleLists)
		if err != nil {
			return fmt.Errorf("failed to initialize DNS Filtering Engine: %v", err)
		}

		rs, err := urlfilter.NewRuleStorage(ruleLists)
		if err != nil {
			return fmt.Errorf("failed to initialize Rules Storage: %v", err)
		}

		engine.rulesStorage = rs
		engine.dnsEngine = urlfilter.NewDNSEngine(rs)
		engine.blockType = f.BlockType
		d.filteringEngine = engine
		return nil
	}
	return nil
}

// Stop stops the DNS proxy
func (d *DNSProxy) Stop() error {
	d.Lock()
	defer d.Unlock()

	errs := []error{}

	// Stop proxy
	err := d.stopProxy()
	if err != nil {
		errs = append(errs, err)
	}

	// Stop filtering engine
	if d.filteringEngine != nil {
		err := d.filteringEngine.close()
		if err != nil {
			errs = append(errs, errorx.Decorate(err, "couldn't close filtering rules rulesStorage"))
		}
	}

	if len(errs) != 0 {
		return errorx.DecorateMany("Failed to stop DNSProxy", errs...)
	}

	return nil
}

// Restart proxy with new configuration without filteringEngine recreation
func (d *DNSProxy) Restart(config *Config) error {
	d.Lock()
	defer d.Unlock()

	// Stop proxy
	err := d.stopProxy()
	if err != nil {
		return err
	}

	// Set new config
	d.Config = config

	// Start proxy
	return d.startProxy()
}

func (d *DNSProxy) stopProxy() error {
	errs := []error{}

	if d.dnsProxy != nil {
		err := d.dnsProxy.Stop()
		d.dnsProxy = nil
		if err != nil {
			errs = append(errs, err)
		}
	}

	if len(errs) != 0 {
		return errorx.DecorateMany("Failed to stop DNSProxy", errs...)
	}

	return nil
}

func (d *DNSProxy) startProxy() error {
	c, err := createConfig(d.Config)
	if err != nil {
		return fmt.Errorf("cannot start the DNS proxy: %s", err)
	}

	c.RequestHandler = d.handleDNSRequest
	d.dnsProxy = &proxy.Proxy{Config: *c}

	// Start the proxy
	err = d.dnsProxy.Start()
	if err == nil && d.Config.DetectDNS64Prefix {
		go calculateNAT64Prefix(d.dnsProxy, d.Config.SystemResolvers)
	}
	return err
}

// Addr gets the address proxy is currently listening to
func (d *DNSProxy) Addr() string {
	d.Lock()
	defer d.Unlock()

	if d.dnsProxy == nil {
		return ""
	}

	addr := d.dnsProxy.Addr(proxy.ProtoUDP)
	if addr == nil {
		return ""
	}

	return addr.String()
}

// Resolve resolves the specified DNS request using the configured (and started) dns proxy
// packet - DNS query bytes
// returns response or error
func (d *DNSProxy) Resolve(packet []byte) ([]byte, error) {
	msg := &dns.Msg{}
	err := msg.Unpack(packet)
	if err != nil {
		return nil, err
	}

	if len(msg.Question) != 1 {
		return nil, fmt.Errorf("got invalid number of questions: %v", len(msg.Question))
	}

	log.Tracef("IN: %s", msg)

	ctx := &proxy.DNSContext{
		Proto:     "udp",
		Req:       msg,
		StartTime: time.Now(),
	}
	err = d.handleDNSRequest(d.dnsProxy, ctx)
	if err != nil {
		return nil, err
	}
	if ctx.Res == nil {
		return nil, fmt.Errorf("got no response")
	}

	log.Tracef("OUT: %s", ctx.Res)

	bytes, err := ctx.Res.Pack()
	if err != nil {
		return nil, errorx.Decorate(err, "couldn't convert message into wire format")
	}

	return bytes, nil
}

// createProxyConfig creates proxy.Config from mobile.Config values
func createConfig(config *Config) (*proxy.Config, error) {
	listenIP := net.ParseIP(config.ListenAddr)
	if listenIP == nil {
		return nil, fmt.Errorf("cannot parse %s", config.ListenAddr)
	}
	timeout := time.Duration(config.Timeout) * time.Millisecond

	// Init listen addresses and upstreams
	listenUDPAddr := &net.UDPAddr{Port: config.ListenPort, IP: listenIP}
	listenTCPAddr := &net.TCPAddr{Port: config.ListenPort, IP: listenIP}
	upstreams := make([]upstream.Upstream, 0)

	// Check bootstraps list for empty strings
	bootstrapLines := strings.Split(config.BootstrapDNS, "\n")
	var bootstraps []string
	for _, line := range bootstrapLines {
		if line == "" {
			continue
		}

		bootstraps = append(bootstraps, line)
	}

	lines := strings.Split(config.Upstreams, "\n")

	for i, line := range lines {
		if line == "" {
			continue
		}

		dnsUpstream, err := upstream.AddressToUpstream(line, upstream.Options{Bootstrap: bootstraps, Timeout: timeout})
		if err != nil {
			return nil, fmt.Errorf("cannot prepare the upstream %s (%s): %s", line, config.BootstrapDNS, err)
		}
		log.Printf("Upstream %d: %s", i, dnsUpstream.Address())
		upstreams = append(upstreams, dnsUpstream)
	}

	// Create the config
	proxyConfig := proxy.Config{
		UDPListenAddr:  listenUDPAddr,
		TCPListenAddr:  listenTCPAddr,
		Upstreams:      upstreams,
		AllServers:     config.AllServers,
		CacheSizeBytes: config.CacheSizeBytes,
		CacheEnabled:   config.CacheSizeBytes > 0,
		MaxGoroutines:  config.MaxGoroutines,
		Ratelimit:      0,
	}

	if config.Fallbacks != "" {
		fallbacks := []upstream.Upstream{}
		lines = strings.Split(config.Fallbacks, "\n")
		for i, line := range lines {
			if line == "" {
				continue
			}

			fallback, err := upstream.AddressToUpstream(line, upstream.Options{Timeout: timeout})
			if err != nil {
				return nil, fmt.Errorf("cannot parse the fallback %s (%s): %s", line, config.BootstrapDNS, err)
			}

			log.Printf("Fallback %d: %s", i, fallback.Address())
			fallbacks = append(fallbacks, fallback)
		}
		proxyConfig.Fallbacks = fallbacks
	}

	return &proxyConfig, nil
}

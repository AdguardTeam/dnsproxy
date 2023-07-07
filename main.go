// Package main is responsible for command-line interface of dnsproxy.
package main

import (
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/http/pprof"
	"net/netip"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/AdguardTeam/dnsproxy/proxy"
	"github.com/AdguardTeam/dnsproxy/upstream"
	"github.com/AdguardTeam/golibs/log"
	"github.com/AdguardTeam/golibs/mathutil"
	"github.com/AdguardTeam/golibs/netutil"
	"github.com/AdguardTeam/golibs/timeutil"
	"github.com/ameshkov/dnscrypt/v2"
	goFlags "github.com/jessevdk/go-flags"
	"gopkg.in/yaml.v3"
)

// Options represents console arguments.  For further additions, please do not
// use the default option since it will cause some problems when config files
// are used.
type Options struct {
	// Configuration file path (yaml), the config path should be read without
	// using goFlags in order not to have default values overriding yaml
	// options.
	ConfigPath string `long:"config-path" description:"yaml configuration file. Minimal working configuration in config.yaml.dist. Options passed through command line will override the ones from this file." default:""`

	// Log settings
	// --

	// Should we write
	Verbose bool `yaml:"verbose" short:"v" long:"verbose" description:"Verbose output (optional)" optional:"yes" optional-value:"true"`

	// Path to a log file
	LogOutput string `yaml:"output" short:"o" long:"output" description:"Path to the log file. If not set, write to stdout."`

	// Listen addrs
	// --

	// Server listen address
	ListenAddrs []string `yaml:"listen-addrs" short:"l" long:"listen" description:"Listening addresses"`

	// Server listen ports
	ListenPorts []int `yaml:"listen-ports" short:"p" long:"port" description:"Listening ports. Zero value disables TCP and UDP listeners"`

	// HTTPS listen ports
	HTTPSListenPorts []int `yaml:"https-port" short:"s" long:"https-port" description:"Listening ports for DNS-over-HTTPS"`

	// TLS listen ports
	TLSListenPorts []int `yaml:"tls-port" short:"t" long:"tls-port" description:"Listening ports for DNS-over-TLS"`

	// QUIC listen ports
	QUICListenPorts []int `yaml:"quic-port" short:"q" long:"quic-port" description:"Listening ports for DNS-over-QUIC"`

	// DNSCrypt listen ports
	DNSCryptListenPorts []int `yaml:"dnscrypt-port" short:"y" long:"dnscrypt-port" description:"Listening ports for DNSCrypt"`

	// Encryption config
	// --

	// Path to the .crt with the certificate chain
	TLSCertPath string `yaml:"tls-crt" short:"c" long:"tls-crt" description:"Path to a file with the certificate chain"`

	// Path to the file with the private key
	TLSKeyPath string `yaml:"tls-key" short:"k" long:"tls-key" description:"Path to a file with the private key"`

	// Minimum TLS version
	TLSMinVersion float32 `yaml:"tls-min-version" long:"tls-min-version" description:"Minimum TLS version, for example 1.0" optional:"yes"`

	// Maximum TLS version
	TLSMaxVersion float32 `yaml:"tls-max-version" long:"tls-max-version" description:"Maximum TLS version, for example 1.3" optional:"yes"`

	// Disable TLS certificate verification
	Insecure bool `yaml:"insecure" long:"insecure" description:"Disable secure TLS certificate validation" optional:"yes" optional-value:"false"`

	// Path to the DNSCrypt configuration file
	DNSCryptConfigPath string `yaml:"dnscrypt-config" short:"g" long:"dnscrypt-config" description:"Path to a file with DNSCrypt configuration. You can generate one using https://github.com/ameshkov/dnscrypt"`

	// HTTP3 controls whether HTTP/3 is enabled for this instance of dnsproxy.
	// It enables HTTP/3 support for both the DoH upstreams and the DoH server.
	HTTP3 bool `yaml:"http3" long:"http3" description:"Enable HTTP/3 support" optional:"yes" optional-value:"false"`

	// Upstream DNS servers settings
	// --

	// DNS upstreams
	Upstreams []string `yaml:"upstream" short:"u" long:"upstream" description:"An upstream to be used (can be specified multiple times). You can also specify path to a file with the list of servers" optional:"false"`

	// Bootstrap DNS
	BootstrapDNS []string `yaml:"bootstrap" short:"b" long:"bootstrap" description:"Bootstrap DNS for DoH and DoT, can be specified multiple times (default: 8.8.8.8:53)"`

	// Fallback DNS resolver
	Fallbacks []string `yaml:"fallback" short:"f" long:"fallback" description:"Fallback resolvers to use when regular ones are unavailable, can be specified multiple times. You can also specify path to a file with the list of servers"`

	// PrivateRDNSUpstreams are upstreams to use for reverse DNS lookups of
	// private addresses.
	PrivateRDNSUpstreams []string `yaml:"private-rdns-upstream" long:"private-rdns-upstream" description:"Private DNS upstreams to use for reverse DNS lookups of private addresses, can be specified multiple times"`

	// If true, parallel queries to all configured upstream servers
	AllServers bool `yaml:"all-servers" long:"all-servers" description:"If specified, parallel queries to all configured upstream servers are enabled" optional:"yes" optional-value:"true"`

	// Respond to A or AAAA requests only with the fastest IP address
	//  detected by ICMP response time or TCP connection time
	FastestAddress bool `yaml:"fastest-addr" long:"fastest-addr" description:"Respond to A or AAAA requests only with the fastest IP address" optional:"yes" optional-value:"true"`

	// Timeout for outbound DNS queries to remote upstream servers in a
	// human-readable form.  Default is 10s.
	Timeout timeutil.Duration `yaml:"timeout" long:"timeout" description:"Timeout for outbound DNS queries to remote upstream servers in a human-readable form" default:"10s"`

	// Cache settings
	// --

	// If true, DNS cache is enabled
	Cache bool `yaml:"cache" long:"cache" description:"If specified, DNS cache is enabled" optional:"yes" optional-value:"true"`

	// Cache size value
	CacheSizeBytes int `yaml:"cache-size" long:"cache-size" description:"Cache size (in bytes). Default: 64k"`

	// DNS cache minimum TTL value - overrides record value
	CacheMinTTL uint32 `yaml:"cache-min-ttl" long:"cache-min-ttl" description:"Minimum TTL value for DNS entries, in seconds. Capped at 3600. Artificially extending TTLs should only be done with careful consideration."`

	// DNS cache maximum TTL value - overrides record value
	CacheMaxTTL uint32 `yaml:"cache-max-ttl" long:"cache-max-ttl" description:"Maximum TTL value for DNS entries, in seconds."`

	// CacheOptimistic, if set to true, enables the optimistic DNS cache. That means that cached results will be served even if their cache TTL has already expired.
	CacheOptimistic bool `yaml:"cache-optimistic" long:"cache-optimistic" description:"If specified, optimistic DNS cache is enabled" optional:"yes" optional-value:"true"`

	// Anti-DNS amplification measures
	// --

	// Ratelimit value
	Ratelimit int `yaml:"ratelimit" short:"r" long:"ratelimit" description:"Ratelimit (requests per second)"`

	// If true, refuse ANY requests
	RefuseAny bool `yaml:"refuse-any" long:"refuse-any" description:"If specified, refuse ANY requests" optional:"yes" optional-value:"true"`

	// ECS settings
	// --

	// Use EDNS Client Subnet extension
	EnableEDNSSubnet bool `yaml:"edns" long:"edns" description:"Use EDNS Client Subnet extension" optional:"yes" optional-value:"true"`

	// Use Custom EDNS Client Address
	EDNSAddr string `yaml:"edns-addr" long:"edns-addr" description:"Send EDNS Client Address"`

	// DNS64 settings
	// --

	// Defines whether DNS64 functionality is enabled or not
	DNS64 bool `yaml:"dns64" long:"dns64" description:"If specified, dnsproxy will act as a DNS64 server" optional:"yes" optional-value:"true"`

	// DNS64Prefix defines the DNS64 prefixes that dnsproxy should use when it
	// acts as a DNS64 server.  If not specified, dnsproxy uses the default
	// Well-Known Prefix.  This option can be specified multiple times.
	DNS64Prefix []string `yaml:"dns64-prefix" long:"dns64-prefix" description:"Prefix used to handle DNS64. If not specified, dnsproxy uses the 'Well-Known Prefix' 64:ff9b::.  Can be specified multiple times" required:"false"`

	// Other settings and options
	// --

	// Set Server header for the HTTPS server
	HTTPSServerName string `yaml:"https-server-name" long:"https-server-name" description:"Set the Server header for the responses from the HTTPS server." default:"dnsproxy"`

	// If true, all AAAA requests will be replied with NoError RCode and empty answer
	IPv6Disabled bool `yaml:"ipv6-disabled" long:"ipv6-disabled" description:"If specified, all AAAA requests will be replied with NoError RCode and empty answer" optional:"yes" optional-value:"true"`

	// Transform responses that contain at least one of the given IP addresses into NXDOMAIN
	BogusNXDomain []string `yaml:"bogus-nxdomain" long:"bogus-nxdomain" description:"Transform the responses containing at least a single IP that matches specified addresses and CIDRs into NXDOMAIN.  Can be specified multiple times."`

	// UDP buffer size value
	UDPBufferSize int `yaml:"udp-buf-size" long:"udp-buf-size" description:"Set the size of the UDP buffer in bytes. A value <= 0 will use the system default."`

	// The maximum number of go routines
	MaxGoRoutines int `yaml:"max-go-routines" long:"max-go-routines" description:"Set the maximum number of go routines. A value <= 0 will not not set a maximum."`

	// Pprof defines whether the pprof information needs to be exposed via
	// localhost:6060 or not.
	Pprof bool `yaml:"pprof" long:"pprof" description:"If present, exposes pprof information on localhost:6060." optional:"yes" optional-value:"true"`

	// Print DNSProxy version (just for the help)
	Version bool `yaml:"version" long:"version" description:"Prints the program version"`
}

// VersionString will be set through ldflags, contains current version
var VersionString = "dev" // nolint:gochecknoglobals

const (
	defaultLocalTimeout = 1 * time.Second
)

func main() {
	options := &Options{}

	for _, arg := range os.Args {
		if arg == "--version" {
			fmt.Printf("dnsproxy version: %s\n", VersionString)
			os.Exit(0)
		}

		// TODO(e.burkov, a.garipov):  Use flag package and remove the manual
		// options parsing.
		//
		// See https://github.com/AdguardTeam/dnsproxy/issues/182.
		if len(arg) > 13 {
			if arg[:13] == "--config-path" {
				fmt.Printf("Path: %s\n", arg[14:])
				b, err := os.ReadFile(arg[14:])
				if err != nil {
					log.Fatalf("failed to read the config file %s: %v", arg[14:], err)
				}
				err = yaml.Unmarshal(b, options)
				if err != nil {
					log.Fatalf("failed to unmarshal the config file %s: %v", arg[14:], err)
				}
			}
		}
	}

	parser := goFlags.NewParser(options, goFlags.Default)
	_, err := parser.Parse()
	if err != nil {
		if flagsErr, ok := err.(*goFlags.Error); ok && flagsErr.Type == goFlags.ErrHelp {
			os.Exit(0)
		}

		os.Exit(1)
	}

	run(options)
}

func run(options *Options) {
	if options.Verbose {
		log.SetLevel(log.DEBUG)
	}
	if options.LogOutput != "" {
		file, err := os.OpenFile(options.LogOutput, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o644)
		if err != nil {
			log.Fatalf("cannot create a log file: %s", err)
		}
		defer file.Close() //nolint
		log.SetOutput(file)
	}

	runPprof(options)

	log.Info("Starting dnsproxy %s", VersionString)

	// Prepare the proxy server and its configuration.
	config := createProxyConfig(options)
	dnsProxy := &proxy.Proxy{Config: config}

	// Add extra handler if needed.
	if options.IPv6Disabled {
		ipv6Configuration := ipv6Configuration{ipv6Disabled: options.IPv6Disabled}
		dnsProxy.RequestHandler = ipv6Configuration.handleDNSRequest
	}

	// Start the proxy server.
	err := dnsProxy.Start()
	if err != nil {
		log.Fatalf("cannot start the DNS proxy due to %s", err)
	}

	signalChannel := make(chan os.Signal, 1)
	signal.Notify(signalChannel, syscall.SIGINT, syscall.SIGTERM)
	<-signalChannel

	// Stopping the proxy.
	err = dnsProxy.Stop()
	if err != nil {
		log.Fatalf("cannot stop the DNS proxy due to %s", err)
	}
}

// runPprof runs pprof server on localhost:6060 if it's enabled in the options.
func runPprof(options *Options) {
	if !options.Pprof {
		return
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/debug/pprof/", pprof.Index)
	mux.HandleFunc("/debug/pprof/cmdline", pprof.Cmdline)
	mux.HandleFunc("/debug/pprof/profile", pprof.Profile)
	mux.HandleFunc("/debug/pprof/symbol", pprof.Symbol)
	mux.HandleFunc("/debug/pprof/trace", pprof.Trace)
	mux.Handle("/debug/pprof/allocs", pprof.Handler("allocs"))
	mux.Handle("/debug/pprof/block", pprof.Handler("block"))
	mux.Handle("/debug/pprof/goroutine", pprof.Handler("goroutine"))
	mux.Handle("/debug/pprof/heap", pprof.Handler("heap"))
	mux.Handle("/debug/pprof/mutex", pprof.Handler("mutex"))
	mux.Handle("/debug/pprof/threadcreate", pprof.Handler("threadcreate"))

	go func() {
		log.Info("pprof: listening on localhost:6060")
		srv := &http.Server{
			Addr:        "localhost:6060",
			ReadTimeout: 60 * time.Second,
			Handler:     mux,
		}
		err := srv.ListenAndServe()
		log.Error("error while running the pprof server: %s", err)
	}()
}

// createProxyConfig creates proxy.Config from the command line arguments
func createProxyConfig(options *Options) proxy.Config {
	// Create the config
	config := proxy.Config{
		Ratelimit:       options.Ratelimit,
		CacheEnabled:    options.Cache,
		CacheSizeBytes:  options.CacheSizeBytes,
		CacheMinTTL:     options.CacheMinTTL,
		CacheMaxTTL:     options.CacheMaxTTL,
		CacheOptimistic: options.CacheOptimistic,
		RefuseAny:       options.RefuseAny,
		HTTP3:           options.HTTP3,
		// TODO(e.burkov):  The following CIDRs are aimed to match any
		// address.  This is not quite proper approach to be used by
		// default so think about configuring it.
		TrustedProxies:         []string{"0.0.0.0/0", "::0/0"},
		EnableEDNSClientSubnet: options.EnableEDNSSubnet,
		UDPBufferSize:          options.UDPBufferSize,
		HTTPSServerName:        options.HTTPSServerName,
		MaxGoroutines:          options.MaxGoRoutines,
	}

	// TODO(e.burkov):  Make these methods of [Options].
	initUpstreams(&config, options)
	initEDNS(&config, options)
	initBogusNXDomain(&config, options)
	initTLSConfig(&config, options)
	initDNSCryptConfig(&config, options)
	initListenAddrs(&config, options)
	initDNS64(&config, options)

	return config
}

// containsUpstreams returns true if uc contains at least a single upstream.
// Otherwise it's considered nil.
//
// TODO(e.burkov):  Think of a better way to validate the config.  Perhaps,
// return an error from [ParseUpstreamsConfig] if no upstreams were initialized.
func containsUpstreams(uc *proxy.UpstreamConfig) (ok bool) {
	return len(uc.Upstreams) > 0 ||
		len(uc.DomainReservedUpstreams) > 0 ||
		len(uc.SpecifiedDomainUpstreams) > 0
}

// initUpstreams inits upstream-related config
func initUpstreams(config *proxy.Config, options *Options) {
	// Init upstreams

	httpVersions := upstream.DefaultHTTPVersions
	if options.HTTP3 {
		httpVersions = []upstream.HTTPVersion{
			upstream.HTTPVersion3,
			upstream.HTTPVersion2,
			upstream.HTTPVersion11,
		}
	}

	var err error

	timeout := options.Timeout.Duration
	upsOpts := &upstream.Options{
		HTTPVersions:       httpVersions,
		InsecureSkipVerify: options.Insecure,
		Bootstrap:          options.BootstrapDNS,
		Timeout:            timeout,
	}
	upstreams := loadServersList(options.Upstreams)
	config.UpstreamConfig, err = proxy.ParseUpstreamsConfig(upstreams, upsOpts)
	if err != nil {
		log.Fatalf("error while parsing upstreams configuration: %s", err)
	}

	privUpsOpts := &upstream.Options{
		HTTPVersions: httpVersions,
		Bootstrap:    options.BootstrapDNS,
		Timeout:      mathutil.Min(defaultLocalTimeout, timeout),
	}
	privUpstreams := loadServersList(options.PrivateRDNSUpstreams)
	private, err := proxy.ParseUpstreamsConfig(privUpstreams, privUpsOpts)
	if err != nil {
		log.Fatalf("error while parsing private rdns upstreams configuration: %s", err)
	}
	if containsUpstreams(private) {
		config.PrivateRDNSUpstreamConfig = private
	}

	fallbackUpstreams := loadServersList(options.Fallbacks)
	fallbacks, err := proxy.ParseUpstreamsConfig(fallbackUpstreams, upsOpts)
	if err != nil {
		log.Fatalf("error while parsing fallback upstreams configuration: %s", err)
	}
	if containsUpstreams(fallbacks) {
		config.Fallbacks = fallbacks
	}

	if options.AllServers {
		config.UpstreamMode = proxy.UModeParallel
	} else if options.FastestAddress {
		config.UpstreamMode = proxy.UModeFastestAddr
	} else {
		config.UpstreamMode = proxy.UModeLoadBalance
	}
}

// initEDNS inits EDNS-related config
func initEDNS(config *proxy.Config, options *Options) {
	if options.EDNSAddr != "" {
		if options.EnableEDNSSubnet {
			ednsIP := net.ParseIP(options.EDNSAddr)
			if ednsIP == nil {
				log.Fatalf("cannot parse %s", options.EDNSAddr)
			}
			config.EDNSAddr = ednsIP
		} else {
			log.Printf("--edns-addr=%s need --edns to work", options.EDNSAddr)
		}
	}
}

// initBogusNXDomain inits BogusNXDomain structure
func initBogusNXDomain(config *proxy.Config, options *Options) {
	if len(options.BogusNXDomain) == 0 {
		return
	}

	for _, s := range options.BogusNXDomain {
		subnet, err := netutil.ParseSubnet(s)
		if err != nil {
			log.Error("%s", err)

			continue
		}

		config.BogusNXDomain = append(config.BogusNXDomain, subnet)
	}
}

// initTLSConfig inits the TLS config
func initTLSConfig(config *proxy.Config, options *Options) {
	if options.TLSCertPath != "" && options.TLSKeyPath != "" {
		tlsConfig, err := newTLSConfig(options)
		if err != nil {
			log.Fatalf("failed to load TLS config: %s", err)
		}
		config.TLSConfig = tlsConfig
	}
}

// initDNSCryptConfig inits the DNSCrypt config
func initDNSCryptConfig(config *proxy.Config, options *Options) {
	if options.DNSCryptConfigPath == "" {
		return
	}

	b, err := os.ReadFile(options.DNSCryptConfigPath)
	if err != nil {
		log.Fatalf("failed to read DNSCrypt config %s: %v", options.DNSCryptConfigPath, err)
	}

	rc := &dnscrypt.ResolverConfig{}
	err = yaml.Unmarshal(b, rc)
	if err != nil {
		log.Fatalf("failed to unmarshal DNSCrypt config: %v", err)
	}

	cert, err := rc.CreateCert()
	if err != nil {
		log.Fatalf("failed to create DNSCrypt certificate: %v", err)
	}

	config.DNSCryptResolverCert = cert
	config.DNSCryptProviderName = rc.ProviderName
}

// initListenAddrs inits listen addrs
func initListenAddrs(config *proxy.Config, options *Options) {
	listenIPs := []net.IP{}

	if len(options.ListenAddrs) == 0 {
		// If ListenAddrs has not been parsed through config file nor command
		// line we set it to "0.0.0.0".
		options.ListenAddrs = []string{"0.0.0.0"}
	}

	if len(options.ListenPorts) == 0 {
		// If ListenPorts has not been parsed through config file nor command
		// line we set it to 53.
		options.ListenPorts = []int{53}
	}

	for _, a := range options.ListenAddrs {
		ip := net.ParseIP(a)
		if ip == nil {
			log.Fatalf("cannot parse %s", a)
		}
		listenIPs = append(listenIPs, ip)
	}

	if len(options.ListenPorts) != 0 && options.ListenPorts[0] != 0 {
		for _, port := range options.ListenPorts {
			for _, ip := range listenIPs {

				ua := &net.UDPAddr{Port: port, IP: ip}
				config.UDPListenAddr = append(config.UDPListenAddr, ua)

				ta := &net.TCPAddr{Port: port, IP: ip}
				config.TCPListenAddr = append(config.TCPListenAddr, ta)
			}
		}
	}

	if config.TLSConfig != nil {
		for _, port := range options.TLSListenPorts {
			for _, ip := range listenIPs {
				a := &net.TCPAddr{Port: port, IP: ip}
				config.TLSListenAddr = append(config.TLSListenAddr, a)
			}
		}

		for _, port := range options.HTTPSListenPorts {
			for _, ip := range listenIPs {
				a := &net.TCPAddr{Port: port, IP: ip}
				config.HTTPSListenAddr = append(config.HTTPSListenAddr, a)
			}
		}

		for _, port := range options.QUICListenPorts {
			for _, ip := range listenIPs {
				a := &net.UDPAddr{Port: port, IP: ip}
				config.QUICListenAddr = append(config.QUICListenAddr, a)
			}
		}
	}

	if config.DNSCryptResolverCert != nil && config.DNSCryptProviderName != "" {
		for _, port := range options.DNSCryptListenPorts {
			for _, ip := range listenIPs {
				tcp := &net.TCPAddr{Port: port, IP: ip}
				config.DNSCryptTCPListenAddr = append(config.DNSCryptTCPListenAddr, tcp)

				udp := &net.UDPAddr{Port: port, IP: ip}
				config.DNSCryptUDPListenAddr = append(config.DNSCryptUDPListenAddr, udp)
			}
		}
	}
}

// initDNS64 sets the DNS64 configuration into conf.
func initDNS64(conf *proxy.Config, options *Options) {
	if conf.UseDNS64 = options.DNS64; !conf.UseDNS64 {
		return
	}

	if len(conf.PrivateRDNSUpstreamConfig.Upstreams) == 0 {
		log.Fatalf("at least one private upstream must be configured to use dns64")
	}

	var prefs []netip.Prefix
	for i, p := range options.DNS64Prefix {
		pref, err := netip.ParsePrefix(p)
		if err != nil {
			log.Fatalf("parsing prefix at index %d: %v", i, err)
		}

		prefs = append(prefs, pref)
	}

	conf.DNS64Prefs = prefs
}

// IPv6 configuration
type ipv6Configuration struct {
	ipv6Disabled bool // If true, all AAAA requests will be replied with NoError RCode and empty answer
}

// handleDNSRequest checks IPv6 configuration for current session before resolve
func (c *ipv6Configuration) handleDNSRequest(p *proxy.Proxy, ctx *proxy.DNSContext) error {
	if proxy.CheckDisabledAAAARequest(ctx, c.ipv6Disabled) {
		return nil
	}

	return p.Resolve(ctx)
}

// NewTLSConfig returns a TLS config that includes a certificate
// Use for server TLS config or when using a client certificate
// If caPath is empty, system CAs will be used
func newTLSConfig(options *Options) (*tls.Config, error) {
	// Set default TLS min/max versions
	tlsMinVersion := tls.VersionTLS10 // Default for crypto/tls
	tlsMaxVersion := tls.VersionTLS13 // Default for crypto/tls
	switch options.TLSMinVersion {
	case 1.1:
		tlsMinVersion = tls.VersionTLS11
	case 1.2:
		tlsMinVersion = tls.VersionTLS12
	case 1.3:
		tlsMinVersion = tls.VersionTLS13
	}
	switch options.TLSMaxVersion {
	case 1.0:
		tlsMaxVersion = tls.VersionTLS10
	case 1.1:
		tlsMaxVersion = tls.VersionTLS11
	case 1.2:
		tlsMaxVersion = tls.VersionTLS12
	}

	cert, err := loadX509KeyPair(options.TLSCertPath, options.TLSKeyPath)
	if err != nil {
		return nil, fmt.Errorf("could not load TLS cert: %s", err)
	}

	return &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: uint16(tlsMinVersion), MaxVersion: uint16(tlsMaxVersion)}, nil
}

// loadX509KeyPair reads and parses a public/private key pair from a pair
// of files. The files must contain PEM encoded data. The certificate file
// may contain intermediate certificates following the leaf certificate to
// form a certificate chain. On successful return, Certificate.Leaf will
// be nil because the parsed form of the certificate is not retained.
func loadX509KeyPair(certFile, keyFile string) (tls.Certificate, error) {
	certPEMBlock, err := os.ReadFile(certFile)
	if err != nil {
		return tls.Certificate{}, err
	}
	keyPEMBlock, err := os.ReadFile(keyFile)
	if err != nil {
		return tls.Certificate{}, err
	}
	return tls.X509KeyPair(certPEMBlock, keyPEMBlock)
}

// loadServersList loads a list of DNS servers from the specified list.
// the thing is that the user may specify either a server address
// or path to a file with a list of addresses. This method takes care of it,
// reads the file, loads servers from it if needed.
func loadServersList(sources []string) []string {
	var servers []string

	for _, source := range sources {
		data, err := os.ReadFile(source)
		if err != nil {
			// Ignore errors, just consider it a server address
			// and not a file
			servers = append(servers, source)
		}

		lines := strings.Split(string(data), "\n")
		for _, line := range lines {
			line = strings.TrimSpace(line)

			// Ignore comments in the file
			if line == "" ||
				strings.HasPrefix(line, "!") ||
				strings.HasPrefix(line, "#") {
				continue
			}

			servers = append(servers, line)
		}
	}

	return servers
}

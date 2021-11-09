package main

import (
	"crypto/tls"
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/AdguardTeam/dnsproxy/proxy"
	"github.com/AdguardTeam/dnsproxy/upstream"
	"github.com/AdguardTeam/golibs/log"
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

	// Minimum TLS version
	TLSMaxVersion float32 `yaml:"tls-max-version" long:"tls-max-version" description:"Maximum TLS version, for example 1.3" optional:"yes"`

	// Disable TLS certificate verification
	Insecure bool `yaml:"insecure" long:"insecure" description:"Disable secure TLS certificate validation" optional:"yes" optional-value:"false"`

	// Path to the DNSCrypt configuration file
	DNSCryptConfigPath string `yaml:"dnscrypt-config" short:"g" long:"dnscrypt-config" description:"Path to a file with DNSCrypt configuration. You can generate one using https://github.com/ameshkov/dnscrypt"`

	// Upstream DNS servers settings
	// --

	// DNS upstreams
	Upstreams []string `yaml:"upstream" short:"u" long:"upstream" description:"An upstream to be used (can be specified multiple times). You can also specify path to a file with the list of servers" optional:"false"`

	// Bootstrap DNS
	BootstrapDNS []string `yaml:"bootstrap" short:"b" long:"bootstrap" description:"Bootstrap DNS for DoH and DoT, can be specified multiple times (default: 8.8.8.8:53)"`

	// Fallback DNS resolver
	Fallbacks []string `yaml:"fallback" short:"f" long:"fallback" description:"Fallback resolvers to use when regular ones are unavailable, can be specified multiple times. You can also specify path to a file with the list of servers"`

	// If true, parallel queries to all configured upstream servers
	AllServers bool `yaml:"all-servers" long:"all-servers" description:"If specified, parallel queries to all configured upstream servers are enabled" optional:"yes" optional-value:"true"`

	// Respond to A or AAAA requests only with the fastest IP address
	//  detected by ICMP response time or TCP connection time
	FastestAddress bool `yaml:"fastest-addr" long:"fastest-addr" description:"Respond to A or AAAA requests only with the fastest IP address" optional:"yes" optional-value:"true"`

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

	// DNS64Prefix defines the DNS64 prefix that dnsproxy should use when it acts as a DNS64 server
	DNS64Prefix string `yaml:"dns64-prefix" long:"dns64-prefix" description:"If specified, this is the DNS64 prefix dnsproxy will be using when it works as a DNS64 server. If not specified, dnsproxy uses the 'Well-Known Prefix' 64:ff9b::" required:"false"`

	// Other settings and options
	// --

	// If true, all AAAA requests will be replied with NoError RCode and empty answer
	IPv6Disabled bool `yaml:"ipv6-disabled" long:"ipv6-disabled" description:"If specified, all AAAA requests will be replied with NoError RCode and empty answer" optional:"yes" optional-value:"true"`

	// Transform responses that contain at least one of the given IP addresses into NXDOMAIN
	BogusNXDomain []string `yaml:"bogus-nxdomain" long:"bogus-nxdomain" description:"Transform responses that contain at least one of the given IP addresses into NXDOMAIN. Can be specified multiple times."`

	// UDP buffer size value
	UDPBufferSize int `yaml:"udp-buf-size" long:"udp-buf-size" description:"Set the size of the UDP buffer in bytes. A value <= 0 will use the system default."`

	// The maximum number of go routines
	MaxGoRoutines int `yaml:"max-go-routines" long:"max-go-routines" description:"Set the maximum number of go routines. A value <= 0 will not not set a maximum."`

	// Print DNSProxy version (just for the help)
	Version bool `yaml:"version" long:"version" description:"Prints the program version"`
}

// VersionString will be set through ldflags, contains current version
var VersionString = "dev" // nolint:gochecknoglobals

const defaultTimeout = 10 * time.Second

// defaultDNS64Prefix is a so-called "Well-Known Prefix" for DNS64.
// if dnsproxy operates as a DNS64 server, we'll be using it.
const defaultDNS64Prefix = "64:ff9b::/96"

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
				b, err := ioutil.ReadFile(arg[14:])
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
		} else {
			os.Exit(1)
		}
	}
	run(options)
}

func run(options *Options) {
	if options.Verbose {
		log.SetLevel(log.DEBUG)
	}
	if options.LogOutput != "" {
		file, err := os.OpenFile(options.LogOutput, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0644)
		if err != nil {
			log.Fatalf("cannot create a log file: %s", err)
		}
		defer file.Close() //nolint
		log.SetOutput(file)
	}

	// Log the dnsproxy startup + version
	log.Info("Starting dnsproxy %s", VersionString)

	// Prepare the proxy server
	config := createProxyConfig(options)
	dnsProxy := &proxy.Proxy{Config: config}

	// Init DNS64 if needed
	initDNS64(dnsProxy, options)

	// Add extra handler if needed
	if options.IPv6Disabled {
		ipv6Configuration := ipv6Configuration{ipv6Disabled: options.IPv6Disabled}
		dnsProxy.RequestHandler = ipv6Configuration.handleDNSRequest
	}

	// Start the proxy
	err := dnsProxy.Start()
	if err != nil {
		log.Fatalf("cannot start the DNS proxy due to %s", err)
	}

	signalChannel := make(chan os.Signal, 1)
	signal.Notify(signalChannel, syscall.SIGINT, syscall.SIGTERM)
	<-signalChannel

	// Stopping the proxy
	err = dnsProxy.Stop()
	if err != nil {
		log.Fatalf("cannot stop the DNS proxy due to %s", err)
	}
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
		// TODO(e.burkov):  The following CIDRs are aimed to match any
		// address.  This is not quite proper approach to be used by
		// default so think about configuring it.
		TrustedProxies:         []string{"0.0.0.0/0", "::0/0"},
		EnableEDNSClientSubnet: options.EnableEDNSSubnet,
		UDPBufferSize:          options.UDPBufferSize,
		MaxGoroutines:          options.MaxGoRoutines,
	}

	initUpstreams(&config, options)
	initEDNS(&config, options)
	initBogusNXDomain(&config, options)
	initTLSConfig(&config, options)
	initDNSCryptConfig(&config, options)
	initListenAddrs(&config, options)

	return config
}

// initUpstreams inits upstream-related config
func initUpstreams(config *proxy.Config, options *Options) {
	// Init upstreams
	upstreams := loadServersList(options.Upstreams)
	upsOpts := &upstream.Options{
		InsecureSkipVerify: options.Insecure,
		Bootstrap:          options.BootstrapDNS,
		Timeout:            defaultTimeout,
	}
	upstreamConfig, err := proxy.ParseUpstreamsConfig(upstreams, upsOpts)
	if err != nil {
		log.Fatalf("error while parsing upstreams configuration: %s", err)
	}
	config.UpstreamConfig = upstreamConfig

	if options.AllServers {
		config.UpstreamMode = proxy.UModeParallel
	} else if options.FastestAddress {
		config.UpstreamMode = proxy.UModeFastestAddr
	} else {
		config.UpstreamMode = proxy.UModeLoadBalance
	}

	if options.Fallbacks != nil {
		fallbacks := []upstream.Upstream{}
		for i, f := range loadServersList(options.Fallbacks) {
			// Use the same options for fallback servers as for
			// upstream servers until it is possible to configure it
			// separately.
			//
			// See https://github.com/AdguardTeam/dnsproxy/issues/161.
			fallback, err := upstream.AddressToUpstream(f, upsOpts)
			if err != nil {
				log.Fatalf("cannot parse the fallback %s (%s): %s", f, options.BootstrapDNS, err)
			}
			log.Printf("Fallback %d is %s", i, fallback.Address())
			fallbacks = append(fallbacks, fallback)
		}
		config.Fallbacks = fallbacks
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
	if len(options.BogusNXDomain) > 0 {
		bogusIP := []net.IP{}
		for _, s := range options.BogusNXDomain {
			ip := net.ParseIP(s)
			if ip == nil {
				log.Error("Invalid IP: %s", s)
			} else {
				bogusIP = append(bogusIP, ip)
			}
		}
		config.BogusNXDomain = bogusIP
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

	b, err := ioutil.ReadFile(options.DNSCryptConfigPath)
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

// initDNS64 inits the DNS64 configuration for dnsproxy
func initDNS64(p *proxy.Proxy, options *Options) {
	if !options.DNS64 {
		return
	}

	dns64Prefix := options.DNS64Prefix
	if dns64Prefix == "" {
		dns64Prefix = defaultDNS64Prefix
	}

	// DNS64 prefix may be specified as a CIDR: "64:ff9b::/96"
	ip, _, err := net.ParseCIDR(dns64Prefix)
	if err != nil {
		// Or it could be specified as an IP address: "64:ff9b::"
		ip = net.ParseIP(dns64Prefix)
	}

	if ip == nil || len(ip) < net.IPv6len {
		log.Fatalf("Invalid DNS64 prefix: %s", dns64Prefix)
		return
	}

	p.SetNAT64Prefix(ip[:proxy.NAT64PrefixLength])
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
	certPEMBlock, err := ioutil.ReadFile(certFile)
	if err != nil {
		return tls.Certificate{}, err
	}
	keyPEMBlock, err := ioutil.ReadFile(keyFile)
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
		data, err := ioutil.ReadFile(source)
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

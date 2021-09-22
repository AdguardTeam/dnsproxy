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

	"github.com/BurntSushi/toml"
	goFlags "github.com/jessevdk/go-flags"
	"gopkg.in/yaml.v3"
)

// Options represents console arguments

type ConsoleArgs struct {
	// Print DNSProxy version (just for the help)
	Version  bool   `long:"version" description:"Prints the program version"`
	TomlPath string `short:"c" description:"Path to the toml configuration file (optional)." default:"/etc/dnsproxy/dnsproxy.toml" ` //
}

// Program options. They will be taken from the toml file

type Options struct {
	// Log settings
	// --
	Verbose   bool   // Should we write
	LogOutput string // Path to a log file

	// Listen addrs
	// --
	ListenAddrs         []string // Server listen address
	ListenPorts         []int    // Server listen ports
	HTTPSListenPorts    []int    // HTTPS listen ports
	TLSListenPorts      []int    // TLS listen ports
	QUICListenPorts     []int    // QUIC listen ports
	DNSCryptListenPorts []int    // DNSCrypt listen ports

	// Encryption config
	// --

	TLSCertPath   string  // Path to the .crt with the certificate chain
	TLSKeyPath    string  // Path to the file with the private key
	TLSMinVersion float32 // Minimum TLS version
	TLSMaxVersion float32 // Minimum TLS version
	Insecure      bool    // Disable TLS certificate verification

	// Path to the DNSCrypt configuration file
	DNSCryptConfigPath string // Path to the DNSCrypt configuration file

	// Upstream DNS servers settings
	// --
	// DoH Upstream Authentication

	TLSAuthCertPath string // Path to the .crt with the clien-side certificate for upstream client authentication
	TLSAuthKeyPath  string // Path to the file with the clien-side private key for upstream client authentication

	Upstreams      []string // DNS upstreams
	BootstrapDNS   []string // Bootstrap DNS
	Fallbacks      []string // Fallback DNS resolver to use when regular ones are unavailable, can be specified multiple times. You can also specify path to a file with the list of servers
	AllServers     bool     // If true, parallel queries to all configured upstream servers
	FastestAddress bool     // Respond to A or AAAA requests only with the fastest IP address, detected by ICMP response time or TCP connection time

	// Cache settings
	// --

	// If true, DNS cache is enabled
	Cache           bool   // If true, DNS cache is enabled
	CacheSizeBytes  int    //Cache size (in bytes). Default: 64k"
	CacheMinTTL     uint32 // Minimum TTL value for DNS entries, in seconds. Capped at 3600. Artificially extending TTLs should only be done with careful consideration
	CacheMaxTTL     uint32 // Maximum TTL value for DNS entries, in seconds.
	CacheOptimistic bool   // CacheOptimistic, if set to true, enables the optimistic DNS cache. That means that cached results will be served even if their cache TTL has already expired

	// Anti-DNS amplification measures
	// --

	Ratelimit int  // Ratelimit (requests per second)
	RefuseAny bool //`long:"refuse-any" description:"If specified, refuse ANY requests" optional:"yes" optional-value:"true"`

	// ECS settings
	// --

	EnableEDNSSubnet bool   //Use EDNS Client Subnet extension
	EDNSAddr         string //Send EDNS custom client address

	// DNS64 settings
	// --

	DNS64       bool   // If specified, dnsproxy will act as a DNS64 server
	DNS64Prefix string //If specified, this is the DNS64 prefix dnsproxy will be using when it works as a DNS64 server. If not specified, dnsproxy uses the 'Well-Known Prefix' 64:ff9b::

	// Other settings and options
	// --

	IPv6Disabled  bool     // If true, all AAAA requests will be replied with NoError RCode and empty answer
	BogusNXDomain []string // Transform responses that contain at least one of the given IP addresses into NXDOMAIN. Can be specified multiple times.
	UDPBufferSize int      // Set the size of the UDP buffer in bytes. A value <= 0 will use the system default.
	MaxGoRoutines int      // Set the maximum number of go routines. A value <= 0 will not not set a maximum default to 0

}

// VersionString will be set through ldflags, contains current version
var VersionString = "undefined" // nolint:gochecknoglobals

const defaultTimeout = 10 * time.Second

var dohauth = false

// defaultDNS64Prefix is a so-called "Well-Known Prefix" for DNS64.
// if dnsproxy operates as a DNS64 server, we'll be using it.
const defaultDNS64Prefix = "64:ff9b::/96"

func main() {

	consoleargs := &ConsoleArgs{}
	parser := goFlags.NewParser(consoleargs, goFlags.Default)

	if len(os.Args) > 1 && os.Args[1] == "--version" {
		fmt.Printf("dnsproxy version: %s\n", VersionString)
		os.Exit(0)
	}

	_, err := parser.Parse()
	if err != nil {
		if flagsErr, ok := err.(*goFlags.Error); ok && flagsErr.Type == goFlags.ErrHelp {
			os.Exit(0)
		} else {
			os.Exit(1)
		}
	}

	fmt.Printf("config path: %s\n", consoleargs.TomlPath)

	var options Options
	if _, err := toml.DecodeFile(consoleargs.TomlPath, &options); err != nil {
		fmt.Println(err)
		return
	}

	log.Println("Starting the DNS proxy")
	run(&options)
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

	initDoHClientTLSConfig(&config, options)
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

	log.Printf("dohauth : ", dohauth)
	upstreams := loadServersList(options.Upstreams)
	upstreamConfig, err := proxy.ParseUpstreamsConfig(
		upstreams,
		&upstream.Options{
			InsecureSkipVerify: options.Insecure,
			Bootstrap:          options.BootstrapDNS,
			Timeout:            defaultTimeout,
			DoHClientTLSConfig: config.DoHClientTLSConfig,
			DoHClient:          dohauth,
		})
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
			fallback, err := upstream.AddressToUpstream(
				f,
				&upstream.Options{Timeout: defaultTimeout},
			)
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
		tlsConfig, err := newTLSConfig(options, false)
		if err != nil {
			log.Fatalf("failed to load TLS config: %s", err)
		}
		config.TLSConfig = tlsConfig
	}
}

// initTLSConfig inits the DoH Client Auth TLS config
func initDoHClientTLSConfig(config *proxy.Config, options *Options) {
	log.Printf("Config certificates : ", options.TLSAuthCertPath)
	log.Printf("Config certificates : ", options.TLSAuthKeyPath)

	if options.TLSAuthCertPath != "" && options.TLSAuthKeyPath != "" {
		tlsConfig, err := newTLSConfig(options, true)
		if err != nil {
			log.Fatalf("failed to load DDoH Client-auth TLS config: %s", err)
		}
		dohauth = true
		log.Printf("dohauth true")
		config.DoHClientTLSConfig = tlsConfig
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
func newTLSConfig(options *Options, auth bool) (*tls.Config, error) {
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

	cert, err := loadX509KeyPair("", "")

	if auth {
		cert, err = loadX509KeyPair(options.TLSAuthCertPath, options.TLSAuthKeyPath)
		if err != nil {
			return nil, fmt.Errorf("could not load TLS cert for DoH auth: %s", err)
		}
	} else {
		cert, err = loadX509KeyPair(options.TLSCertPath, options.TLSKeyPath)
		if err != nil {
			return nil, fmt.Errorf("could not load TLS cert for TLS server: %s", err)
		}
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

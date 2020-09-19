package main

import (
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/AdguardTeam/dnsproxy/proxy"
	"github.com/AdguardTeam/dnsproxy/upstream"
	"github.com/AdguardTeam/golibs/log"
	goFlags "github.com/jessevdk/go-flags"
)

// Options represents console arguments
type Options struct {
	// Log settings
	// --

	// Should we write
	Verbose bool `short:"v" long:"verbose" description:"Verbose output (optional)" optional:"yes" optional-value:"true"`

	// Path to a log file
	LogOutput string `short:"o" long:"output" description:"Path to the log file. If not set, write to stdout." default:""`

	// Server settings
	// --

	// Server listen address
	ListenAddrs []string `short:"l" long:"listen" description:"Listening addresses" default:"0.0.0.0"`

	// Server listen ports
	ListenPorts []int `short:"p" long:"port" description:"Listening ports. Zero value disables TCP and UDP listeners" default:"53"`

	// HTTPS listen ports
	HTTPSListenPorts []int `short:"h" long:"https-port" description:"Listening ports for DNS-over-HTTPS"`

	// TLS listen ports
	TLSListenPorts []int `short:"t" long:"tls-port" description:"Listening ports for DNS-over-TLS"`

	// QUIC listen ports
	QUICListenPorts []int `short:"q" long:"quic-port" description:"Listening ports for DNS-over-QUIC"`

	// Path to the .crt with the certificate chain
	TLSCertPath string `short:"c" long:"tls-crt" description:"Path to a file with the certificate chain"`

	// Path to the file with the private key
	TLSKeyPath string `short:"k" long:"tls-key" description:"Path to a file with the private key"`

	// Upstream DNS servers settings
	// --

	// DNS upstreams
	Upstreams []string `short:"u" long:"upstream" description:"An upstream to be used (can be specified multiple times)" required:"true"`

	// Bootstrap DNS
	BootstrapDNS []string `short:"b" long:"bootstrap" description:"Bootstrap DNS for DoH and DoT, can be specified multiple times (default: 8.8.8.8:53)"`

	// Fallback DNS resolver
	Fallbacks []string `short:"f" long:"fallback" description:"Fallback resolvers to use when regular ones are unavailable, can be specified multiple times"`

	// If true, parallel queries to all configured upstream servers
	AllServers bool `long:"all-servers" description:"If specified, parallel queries to all configured upstream servers are enabled" optional:"yes" optional-value:"true"`

	// Respond to A or AAAA requests only with the fastest IP address
	//  detected by ICMP response time or TCP connection time
	FastestAddress bool `long:"fastest-addr" description:"Respond to A or AAAA requests only with the fastest IP address" optional:"yes" optional-value:"true"`

	// Cache settings
	// --

	// If true, DNS cache is enabled
	Cache bool `long:"cache" description:"If specified, DNS cache is enabled" optional:"yes" optional-value:"true"`

	// Cache size value
	CacheSizeBytes int `long:"cache-size" description:"Cache size (in bytes). Default: 64k"`

	// DNS cache minimum TTL value - overrides record value
	CacheMinTTL uint32 `long:"cache-min-ttl" description:"Minimum TTL value for DNS entries, in seconds. Capped at 3600. Artificially extending TTLs should only be done with careful consideration."`

	// DNS cache maximum TTL value - overrides record value
	CacheMaxTTL uint32 `long:"cache-max-ttl" description:"Maximum TTL value for DNS entries, in seconds."`

	// Anti-DNS amplification measures
	// --

	// Ratelimit value
	Ratelimit int `short:"r" long:"ratelimit" description:"Ratelimit (requests per second)" default:"0"`

	// If true, refuse ANY requests
	RefuseAny bool `long:"refuse-any" description:"If specified, refuse ANY requests" optional:"yes" optional-value:"true"`

	// ECS settings
	// --

	// Use EDNS Client Subnet extension
	EnableEDNSSubnet bool `long:"edns" description:"Use EDNS Client Subnet extension" optional:"yes" optional-value:"true"`

	// Use Custom EDNS Client Address
	EDNSAddr string `long:"edns-addr" description:"Send EDNS Client Address"`

	// Add user-specific EDNS exstension
	EDNSOpt []string `long:"ednsopt" description:"List of EDNS extensions to send along with the DNS query (ex: 8:deadbeaf)"`

	// Other settings and options
	// --

	// If true, all AAAA requests will be replied with NoError RCode and empty answer
	IPv6Disabled bool `long:"ipv6-disabled" description:"If specified, all AAAA requests will be replied with NoError RCode and empty answer" optional:"yes" optional-value:"true"`

	// Transform responses that contain only given IP addresses into NXDOMAIN
	BogusNXDomain []string `long:"bogus-nxdomain" description:"Transform responses that contain only given IP addresses into NXDOMAIN. Can be specified multiple times."`

	// Print DNSProxy version (just for the help)
	Version bool `long:"version" description:"Prints the program version"`
}

// VersionString will be set through ldflags, contains current version
var VersionString = "undefined" // nolint:gochecknoglobals

const defaultTimeout = 10 * time.Second

func main() {
	var options Options
	var parser = goFlags.NewParser(&options, goFlags.Default)

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

	log.Println("Starting the DNS proxy")
	run(options)
}

func run(options Options) {
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
	dnsProxy := proxy.Proxy{Config: config}

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
// nolint (gocyclo)
func createProxyConfig(options Options) proxy.Config {
	// Init upstreams
	upstreamConfig, err := proxy.ParseUpstreamsConfig(options.Upstreams, options.BootstrapDNS, defaultTimeout)
	if err != nil {
		log.Fatalf("error while parsing upstreams configuration: %s", err)
	}

	// Create the config
	config := proxy.Config{
		UpstreamConfig:         &upstreamConfig,
		Ratelimit:              options.Ratelimit,
		CacheEnabled:           options.Cache,
		CacheSizeBytes:         options.CacheSizeBytes,
		CacheMinTTL:            options.CacheMinTTL,
		CacheMaxTTL:            options.CacheMaxTTL,
		RefuseAny:              options.RefuseAny,
		EnableEDNSClientSubnet: options.EnableEDNSSubnet,
	}
	if options.AllServers {
		config.UpstreamMode = proxy.UModeParallel
	} else if options.FastestAddress {
		config.UpstreamMode = proxy.UModeFastestAddr
	}

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

	if len(options.EDNSOpt) > 0 {
		config.EDNSOpts = make(map[uint16][]byte)
		for _, s := range options.EDNSOpt {
			kv := strings.Split(s, ":")
			if len(kv) != 2 {
				log.Fatalf("parse error for '%s', --ednsopt must be of the form: option-code:base64encodeddata (ex: --ednsopt 8:SGVsbG8gd29ybGQK)", s)
			} else {
				r, err := strconv.ParseUint(kv[0], 10, 16)
				if err != nil {
					log.Fatalf("parse error for '%s', --ednsopt option-code must be a valid 16 bits numbers (between 0 and 65535)", kv[0])
				}
				optionCode := uint16(r)
				data, err := base64.StdEncoding.DecodeString(kv[1])
				if err != nil {
					log.Fatalf("parse error for '%s', --ednsopt data must be a valid base64 encoded string: (%s)", kv[1], err)
				}
				config.EDNSOpts[optionCode] = data
			}
		}
	}

	if options.Fallbacks != nil {
		fallbacks := []upstream.Upstream{}
		for i, f := range options.Fallbacks {
			fallback, err := upstream.AddressToUpstream(f, upstream.Options{Timeout: defaultTimeout})
			if err != nil {
				log.Fatalf("cannot parse the fallback %s (%s): %s", f, options.BootstrapDNS, err)
			}
			log.Printf("Fallback %d is %s", i, fallback.Address())
			fallbacks = append(fallbacks, fallback)
		}
		config.Fallbacks = fallbacks
	}

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

	// Prepare the TLS config
	if options.TLSCertPath != "" && options.TLSKeyPath != "" {
		tlsConfig, err := newTLSConfig(options.TLSCertPath, options.TLSKeyPath)
		if err != nil {
			log.Fatalf("failed to load TLS config: %s", err)
		}
		config.TLSConfig = tlsConfig
	}

	listenIPs := []net.IP{}
	for _, a := range options.ListenAddrs {
		ip := net.ParseIP(a)
		if ip == nil {
			log.Fatalf("cannot parse %s", a)
		}
		listenIPs = append(listenIPs, ip)
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

	return config
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
func newTLSConfig(certPath, keyPath string) (*tls.Config, error) {
	cert, err := loadX509KeyPair(certPath, keyPath)
	if err != nil {
		return nil, fmt.Errorf("could not load TLS cert: %s", err)
	}

	return &tls.Config{Certificates: []tls.Certificate{cert}}, nil
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

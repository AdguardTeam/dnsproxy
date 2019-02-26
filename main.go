package main

import (
	"crypto/tls"
	"fmt"
	"io/ioutil"
	stdlog "log"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/AdguardTeam/dnsproxy/proxy"
	"github.com/AdguardTeam/dnsproxy/upstream"
	"github.com/hmage/golibs/log"
	goFlags "github.com/jessevdk/go-flags"
)

// Options represents console arguments
type Options struct {
	// Should we write
	Verbose bool `short:"v" long:"verbose" description:"Verbose output (optional)" optional:"yes" optional-value:"true"`

	// Path to a log file
	LogOutput string `short:"o" long:"output" description:"Path to the log file. If not set, write to stdout." default:""`

	// Server listen address
	ListenAddr string `short:"l" long:"listen" description:"Listen address" default:"0.0.0.0"`

	// Server listen port
	ListenPort int `short:"p" long:"port" description:"Listen port" default:"53"`

	// HTTPS listen port (0 to disable DOH server)
	HTTPSListenPort int `short:"h" long:"https-port" description:"Listen port for DNS-over-HTTPS" default:"0"`

	// TLS listen port (0 to disable DOH server)
	TLSListenPort int `short:"t" long:"tls-port" description:"Listen port for DNS-over-TLS" default:"0"`

	// Path to the .crt with the certificate chain
	TLSCertPath string `short:"c" long:"tls-crt" description:"Path to a file with the certificate chain"`

	// Path to the file with the private key
	TLSKeyPath string `short:"k" long:"tls-key" description:"Path to a file with the private key"`

	// Bootstrap DNS
	BootstrapDNS []string `short:"b" long:"bootstrap" description:"Bootstrap DNS for DoH and DoT, can be specified multiple times (default: 8.8.8.8:53)"`

	// Ratelimit value
	Ratelimit int `short:"r" long:"ratelimit" description:"Ratelimit (requests per second)" default:"0"`

	// If true, DNS cache is enabled
	Cache bool `short:"z" long:"cache" description:"If specified, DNS cache is enabled" optional:"yes" optional-value:"true"`

	// If true, refuse ANY requests
	RefuseAny bool `short:"a" long:"refuse-any" description:"If specified, refuse ANY requests" optional:"yes" optional-value:"true"`

	// DNS upstreams
	Upstreams []string `short:"u" long:"upstream" description:"An upstream to be used (can be specified multiple times)" required:"true"`

	// Fallback DNS resolver
	Fallbacks []string `short:"f" long:"fallback" description:"Fallback resolvers to use when regular ones are unavailable, can be specified multiple times"`

	// If true, parallel queries to all configured upstream servers
	AllServers bool `short:"s" long:"all-servers" description:"If specified, parallel queries to all configured upstream servers are enabled" optional:"yes" optional-value:"true"`

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
		log.Verbose = true
	}
	if options.LogOutput != "" {
		file, err := os.OpenFile(options.LogOutput, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0755)
		if err != nil {
			log.Fatalf("cannot create a log file: %s", err)
		}
		defer file.Close() //nolint
		stdlog.SetOutput(file)
	}

	enableTLS13()
	// Prepare the proxy server
	config := createProxyConfig(options)
	dnsProxy := proxy.Proxy{Config: config}

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
func createProxyConfig(options Options) proxy.Config {

	listenIP := net.ParseIP(options.ListenAddr)
	if listenIP == nil {
		log.Fatalf("cannot parse %s", options.ListenAddr)
	}

	// Init listen addresses and upstreams
	listenUDPAddr := &net.UDPAddr{Port: options.ListenPort, IP: listenIP}
	listenTCPAddr := &net.TCPAddr{Port: options.ListenPort, IP: listenIP}
	upstreams := make([]upstream.Upstream, 0)

	for i, u := range options.Upstreams {
		dnsUpstream, err := upstream.AddressToUpstream(u, upstream.Options{Bootstrap: options.BootstrapDNS, Timeout: defaultTimeout})
		if err != nil {
			log.Fatalf("cannot prepare the upstream %s (%s): %s", u, options.BootstrapDNS, err)
		}
		log.Printf("Upstream %d: %s", i, dnsUpstream.Address())
		upstreams = append(upstreams, dnsUpstream)
	}

	// Create the config
	config := proxy.Config{
		UDPListenAddr: listenUDPAddr,
		TCPListenAddr: listenTCPAddr,
		Upstreams:     upstreams,
		Ratelimit:     options.Ratelimit,
		CacheEnabled:  options.Cache,
		RefuseAny:     options.RefuseAny,
		AllServers:    options.AllServers,
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

	// Prepare the TLS config
	if options.TLSCertPath != "" && options.TLSKeyPath != "" {
		tlsConfig, err := newTLSConfig(options.TLSCertPath, options.TLSKeyPath)
		if err != nil {
			log.Fatalf("failed to load TLS config: %s", err)
		}
		config.TLSConfig = tlsConfig
	}

	if options.TLSListenPort > 0 && config.TLSConfig != nil {
		config.TLSListenAddr = &net.TCPAddr{Port: options.TLSListenPort, IP: listenIP}
	}

	if options.HTTPSListenPort > 0 && config.TLSConfig != nil {
		config.HTTPSListenAddr = &net.TCPAddr{Port: options.HTTPSListenPort, IP: listenIP}
	}

	return config
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

// TODO after GO 1.13 release TLS 1.3 will be enabled by default. Remove this afterward
func enableTLS13() {
	err := os.Setenv("GODEBUG", os.Getenv("GODEBUG")+",tls13=1")
	if err != nil {
		log.Fatalf("Failed to enable TLS 1.3: %s", err)
	}
}

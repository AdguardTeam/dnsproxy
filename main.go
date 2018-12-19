package main

import (
	"github.com/jessevdk/go-flags"
	"net"
	"os"
	"os/signal"
	"syscall"

	log "github.com/sirupsen/logrus"

	"github.com/AdguardTeam/dnsproxy/proxy"
	"github.com/AdguardTeam/dnsproxy/upstream"
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

	// Bootstrap DNS
	BootstrapDNS string `short:"b" long:"bootstrap" description:"Bootstrap DNS for DoH and DoT" default:"8.8.8.8:53"`

	// DNS upstreams
	Upstreams []string `short:"u" long:"upstream" description:"An upstream to be used (can be specified multiple times)" required:"true"`
}

func main() {

	log.Println("Starting the DNS proxy")

	var options Options
	var parser = flags.NewParser(&options, flags.Default)

	_, err := parser.Parse()

	if err != nil {
		if flagsErr, ok := err.(*flags.Error); ok && flagsErr.Type == flags.ErrHelp {
			os.Exit(0)
		} else {
			os.Exit(1)
		}
	}

	run(options)
}

func run(options Options) {

	if options.Verbose {
		log.SetLevel(log.TraceLevel)
	}

	if options.LogOutput != "" {
		file, err := os.OpenFile(options.LogOutput, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0755)
		if err != nil {
			log.Fatalf("cannot create a log file: %s", err)
		}
		defer file.Close()
		log.SetOutput(file)
	}

	listenIp := net.ParseIP(options.ListenAddr)
	if listenIp == nil {
		log.Fatalf("cannot parse %s", options.ListenAddr)
	}

	listenAddr := &net.UDPAddr{Port: options.ListenPort, IP: listenIp}
	upstreams := make([]upstream.Upstream, 0)

	for i, u := range options.Upstreams {
		dnsUpstream, err := upstream.AddressToUpstream(u, options.BootstrapDNS)
		if err != nil {
			log.Fatalf("cannot prepare the upstream %s (%s): %s", u, options.BootstrapDNS, err)
		}
		log.Printf("Upstream %d: %s", i, dnsUpstream.Address())
		upstreams = append(upstreams, dnsUpstream)
	}

	// Prepare the proxy server
	dnsProxy := proxy.Proxy{UDPListenAddr: listenAddr, Upstreams: upstreams}
	err := dnsProxy.Start()

	if err != nil {
		log.Fatalf("cannot start the DNS proxy due to %s", err)
	}

	signalChannel := make(chan os.Signal)
	signal.Notify(signalChannel, syscall.SIGINT, syscall.SIGTERM)
	<-signalChannel

	// Stopping the proxy
	dnsProxy.Stop()
}

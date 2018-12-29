/*
Package mobile contains a simple mobile API for github.com/AdguardTeam/dnsproxy
*/
package mobile

import (
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/AdguardTeam/dnsproxy/proxy"
	"github.com/AdguardTeam/dnsproxy/upstream"
	"github.com/hashicorp/logutils"
)

// DNSProxy represents a proxy with it's configuration
type DNSProxy struct {
	Config *Config // Proxy configuration

	logFile  *os.File // Log file (if it's open)
	dnsProxy *proxy.Proxy
	sync.RWMutex
}

// Config is the DNS proxy configuration which uses only the subset of types that is supported by gomobile
type Config struct {
	Verbose      bool   // true if verbose output is enabled
	LogOutput    string // Path to the log file
	ListenAddr   string // IP address to listen to
	ListenPort   int    // Port to listen to
	BootstrapDNS string // Bootstrap DNS (i.e. 8.8.8.8:53)
	Fallback     string // Fallback resolver that will be used if the main one is not available (i.e. 1.1.1.1:53)
	Upstreams    string // A list of upstream resolvers (each on a new line)
	Timeout      int    // Default timeout for all resolvers (milliseconds)
}

// Start starts the DNS proxy
func (d *DNSProxy) Start() error {
	d.Lock()
	defer d.Unlock()

	if d.dnsProxy != nil {
		return errors.New("DNS proxy is already started")
	}

	err := d.updateLogLevel(d.Config)
	if err != nil {
		return fmt.Errorf("cannot start the DNS proxy: %s", err)
	}

	c, err := createConfig(d.Config)
	if err != nil {
		return fmt.Errorf("cannot start the DNS proxy: %s", err)
	}
	d.dnsProxy = &proxy.Proxy{Config: *c}

	// Start the proxy
	return d.dnsProxy.Start()
}

// Stop stops the DNS proxy
func (d *DNSProxy) Stop() error {
	d.Lock()
	defer d.Unlock()

	var err error

	if d.dnsProxy != nil {
		err = d.dnsProxy.Stop()
		d.dnsProxy = nil
	}

	if d.logFile != nil {
		d.logFile.Close()
		d.logFile = nil
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

	addr := d.dnsProxy.Addr("udp")
	if addr == nil {
		return ""
	}

	return addr.String()
}

// updateLogLevel updates log level and creates a log file
func (d *DNSProxy) updateLogLevel(config *Config) error {
	filter := &logutils.LevelFilter{
		Levels:   []logutils.LogLevel{"DEBUG", "INFO", "WARN", "ERROR"},
		MinLevel: logutils.LogLevel("INFO"),
		Writer:   os.Stderr,
	}
	if config.Verbose {
		filter.MinLevel = logutils.LogLevel("DEBUG")
	}
	if config.LogOutput != "" {
		file, err := os.OpenFile(config.LogOutput, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0755)
		if err != nil {
			return fmt.Errorf("cannot create a log file: %s", err)
		}
		filter.Writer = file
	}
	log.SetOutput(filter)
	return nil
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

	lines := strings.Split(config.Upstreams, "\n")

	for i, line := range lines {
		if line == "" {
			continue
		}

		dnsUpstream, err := upstream.AddressToUpstream(line, config.BootstrapDNS, timeout)
		if err != nil {
			return nil, fmt.Errorf("cannot prepare the upstream %s (%s): %s", line, config.BootstrapDNS, err)
		}
		log.Printf("Upstream %d: %s", i, dnsUpstream.Address())
		upstreams = append(upstreams, dnsUpstream)
	}

	// Create the config
	proxyConfig := proxy.Config{
		UDPListenAddr: listenUDPAddr,
		TCPListenAddr: listenTCPAddr,
		Upstreams:     upstreams,
	}

	if config.Fallback != "" {
		fallback, err := upstream.AddressToUpstream(config.Fallback, config.BootstrapDNS, timeout)
		if err != nil {
			return nil, fmt.Errorf("cannot parse the fallback %s (%s): %s", config.Fallback, config.BootstrapDNS, err)
		}
		log.Printf("Fallback is %s", fallback.Address())
		proxyConfig.Fallback = fallback
	}

	return &proxyConfig, nil
}

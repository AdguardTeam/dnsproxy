package cmd

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/AdguardTeam/dnsproxy/internal/version"
	"github.com/AdguardTeam/golibs/osutil"
	"github.com/AdguardTeam/golibs/timeutil"
	goFlags "github.com/jessevdk/go-flags"
)

const (
	defaultLocalTimeout = 1 * time.Second

	argConfigPath = "--config-path="
	argVersion    = "--version"
)

// Options represents console arguments.  For further additions, please do not
// use the default option since it will cause some problems when config files
// are used.
//
// TODO(a.garipov): Consider extracting conf blocks for better fieldalignment.
type Options struct {
	// Configuration file path (yaml), the config path should be read without
	// using goFlags in order not to have default values overriding yaml
	// options.
	ConfigPath string `long:"config-path" description:"yaml configuration file. Minimal working configuration in config.yaml.dist. Options passed through command line will override the ones from this file." default:""`

	// LogOutput is the path to the log file.
	LogOutput string `yaml:"output" short:"o" long:"output" description:"Path to the log file. If not set, write to stdout."`

	// TLSCertPath is the path to the .crt with the certificate chain.
	TLSCertPath string `yaml:"tls-crt" short:"c" long:"tls-crt" description:"Path to a file with the certificate chain"`

	// TLSKeyPath is the path to the file with the private key.
	TLSKeyPath string `yaml:"tls-key" short:"k" long:"tls-key" description:"Path to a file with the private key"`

	// HTTPSServerName sets Server header for the HTTPS server.
	HTTPSServerName string `yaml:"https-server-name" long:"https-server-name" description:"Set the Server header for the responses from the HTTPS server." default:"dnsproxy"`

	// HTTPSUserinfo is the sole permitted userinfo for the DoH basic
	// authentication.  If it is set, all DoH queries are required to have this
	// basic authentication information.
	HTTPSUserinfo string `yaml:"https-userinfo" long:"https-userinfo" description:"If set, all DoH queries are required to have this basic authentication information."`

	// DNSCryptConfigPath is the path to the DNSCrypt configuration file.
	DNSCryptConfigPath string `yaml:"dnscrypt-config" short:"g" long:"dnscrypt-config" description:"Path to a file with DNSCrypt configuration. You can generate one using https://github.com/ameshkov/dnscrypt"`

	// EDNSAddr is the custom EDNS Client Address to send.
	EDNSAddr string `yaml:"edns-addr" long:"edns-addr" description:"Send EDNS Client Address"`

	// UpstreamMode determines the logic through which upstreams will be used.
	// If not specified the [proxy.UpstreamModeLoadBalance] is used.
	UpstreamMode string `yaml:"upstream-mode" long:"upstream-mode" description:"Defines the upstreams logic mode, possible values: load_balance, parallel, fastest_addr (default: load_balance)" optional:"yes" optional-value:"load_balance"`

	// ListenAddrs is the list of server's listen addresses.
	ListenAddrs []string `yaml:"listen-addrs" short:"l" long:"listen" description:"Listening addresses"`

	// ListenPorts are the ports server listens on.
	ListenPorts []int `yaml:"listen-ports" short:"p" long:"port" description:"Listening ports. Zero value disables TCP and UDP listeners"`

	// HTTPSListenPorts are the ports server listens on for DNS-over-HTTPS.
	HTTPSListenPorts []int `yaml:"https-port" short:"s" long:"https-port" description:"Listening ports for DNS-over-HTTPS"`

	// TLSListenPorts are the ports server listens on for DNS-over-TLS.
	TLSListenPorts []int `yaml:"tls-port" short:"t" long:"tls-port" description:"Listening ports for DNS-over-TLS"`

	// QUICListenPorts are the ports server listens on for DNS-over-QUIC.
	QUICListenPorts []int `yaml:"quic-port" short:"q" long:"quic-port" description:"Listening ports for DNS-over-QUIC"`

	// DNSCryptListenPorts are the ports server listens on for DNSCrypt.
	DNSCryptListenPorts []int `yaml:"dnscrypt-port" short:"y" long:"dnscrypt-port" description:"Listening ports for DNSCrypt"`

	// Upstreams is the list of DNS upstream servers.
	Upstreams []string `yaml:"upstream" short:"u" long:"upstream" description:"An upstream to be used (can be specified multiple times). You can also specify path to a file with the list of servers" optional:"false"`

	// BootstrapDNS is the list of bootstrap DNS upstream servers.
	BootstrapDNS []string `yaml:"bootstrap" short:"b" long:"bootstrap" description:"Bootstrap DNS for DoH and DoT, can be specified multiple times (default: use system-provided)"`

	// Fallbacks is the list of fallback DNS upstream servers.
	Fallbacks []string `yaml:"fallback" short:"f" long:"fallback" description:"Fallback resolvers to use when regular ones are unavailable, can be specified multiple times. You can also specify path to a file with the list of servers"`

	// PrivateRDNSUpstreams are upstreams to use for reverse DNS lookups of
	// private addresses, including the requests for authority records, such as
	// SOA and NS.
	PrivateRDNSUpstreams []string `yaml:"private-rdns-upstream" long:"private-rdns-upstream" description:"Private DNS upstreams to use for reverse DNS lookups of private addresses, can be specified multiple times"`

	// DNS64Prefix defines the DNS64 prefixes that dnsproxy should use when it
	// acts as a DNS64 server.  If not specified, dnsproxy uses the default
	// Well-Known Prefix.  This option can be specified multiple times.
	DNS64Prefix []string `yaml:"dns64-prefix" long:"dns64-prefix" description:"Prefix used to handle DNS64. If not specified, dnsproxy uses the 'Well-Known Prefix' 64:ff9b::.  Can be specified multiple times" required:"false"`

	// PrivateSubnets is the list of private subnets to determine private
	// addresses.
	PrivateSubnets []string `yaml:"private-subnets" long:"private-subnets" description:"Private subnets to use for reverse DNS lookups of private addresses" required:"false"`

	// BogusNXDomain transforms responses that contain at least one of the given
	// IP addresses into NXDOMAIN.
	//
	// TODO(a.garipov): Find a way to use [netutil.Prefix].  Currently, package
	// go-flags doesn't support text unmarshalers.
	BogusNXDomain []string `yaml:"bogus-nxdomain" long:"bogus-nxdomain" description:"Transform the responses containing at least a single IP that matches specified addresses and CIDRs into NXDOMAIN.  Can be specified multiple times."`

	// Timeout for outbound DNS queries to remote upstream servers in a
	// human-readable form.  Default is 10s.
	Timeout timeutil.Duration `yaml:"timeout" long:"timeout" description:"Timeout for outbound DNS queries to remote upstream servers in a human-readable form" default:"10s"`

	// CacheMinTTL is the minimum TTL value for caching DNS entries, in seconds.
	// It overrides the TTL value from the upstream server, if the one is less.
	CacheMinTTL uint32 `yaml:"cache-min-ttl" long:"cache-min-ttl" description:"Minimum TTL value for DNS entries, in seconds. Capped at 3600. Artificially extending TTLs should only be done with careful consideration."`

	// CacheMaxTTL is the maximum TTL value for caching DNS entries, in seconds.
	// It overrides the TTL value from the upstream server, if the one is
	// greater.
	CacheMaxTTL uint32 `yaml:"cache-max-ttl" long:"cache-max-ttl" description:"Maximum TTL value for DNS entries, in seconds."`

	// CacheSizeBytes is the cache size in bytes.  Default is 64k.
	CacheSizeBytes int `yaml:"cache-size" long:"cache-size" description:"Cache size (in bytes). Default: 64k"`

	// Ratelimit is the maximum number of requests per second.
	Ratelimit int `yaml:"ratelimit" short:"r" long:"ratelimit" description:"Ratelimit (requests per second)"`

	// RatelimitSubnetLenIPv4 is a subnet length for IPv4 addresses used for
	// rate limiting requests.
	RatelimitSubnetLenIPv4 int `yaml:"ratelimit-subnet-len-ipv4" long:"ratelimit-subnet-len-ipv4" description:"Ratelimit subnet length for IPv4." default:"24"`

	// RatelimitSubnetLenIPv6 is a subnet length for IPv6 addresses used for
	// rate limiting requests.
	RatelimitSubnetLenIPv6 int `yaml:"ratelimit-subnet-len-ipv6" long:"ratelimit-subnet-len-ipv6" description:"Ratelimit subnet length for IPv6." default:"56"`

	// UDPBufferSize is the size of the UDP buffer in bytes.  A value <= 0 will
	// use the system default.
	UDPBufferSize int `yaml:"udp-buf-size" long:"udp-buf-size" description:"Set the size of the UDP buffer in bytes. A value <= 0 will use the system default."`

	// MaxGoRoutines is the maximum number of goroutines.
	MaxGoRoutines uint `yaml:"max-go-routines" long:"max-go-routines" description:"Set the maximum number of go routines. A zero value will not not set a maximum."`

	// TLSMinVersion is the minimum allowed version of TLS.
	TLSMinVersion float32 `yaml:"tls-min-version" long:"tls-min-version" description:"Minimum TLS version, for example 1.0" optional:"yes"`

	// TLSMaxVersion is the maximum allowed version of TLS.
	TLSMaxVersion float32 `yaml:"tls-max-version" long:"tls-max-version" description:"Maximum TLS version, for example 1.3" optional:"yes"`

	// Pprof defines whether the pprof information needs to be exposed via
	// localhost:6060 or not.
	Pprof bool `yaml:"pprof" long:"pprof" description:"If present, exposes pprof information on localhost:6060." optional:"yes" optional-value:"true"`

	// Version, if true, prints the program version, and exits.
	Version bool `yaml:"version" long:"version" description:"Prints the program version"`

	// Verbose controls the verbosity of the output.
	Verbose bool `yaml:"verbose" short:"v" long:"verbose" description:"Verbose output (optional)" optional:"yes" optional-value:"true"`

	// Insecure disables upstream servers TLS certificate verification.
	Insecure bool `yaml:"insecure" long:"insecure" description:"Disable secure TLS certificate validation" optional:"yes" optional-value:"false"`

	// IPv6Disabled makes the server to respond with NODATA to all AAAA queries.
	IPv6Disabled bool `yaml:"ipv6-disabled" long:"ipv6-disabled" description:"If specified, all AAAA requests will be replied with NoError RCode and empty answer" optional:"yes" optional-value:"true"`

	// HTTP3 controls whether HTTP/3 is enabled for this instance of dnsproxy.
	// It enables HTTP/3 support for both the DoH upstreams and the DoH server.
	HTTP3 bool `yaml:"http3" long:"http3" description:"Enable HTTP/3 support" optional:"yes" optional-value:"false"`

	// CacheOptimistic, if set to true, enables the optimistic DNS cache. That
	// means that cached results will be served even if their cache TTL has
	// already expired.
	CacheOptimistic bool `yaml:"cache-optimistic" long:"cache-optimistic" description:"If specified, optimistic DNS cache is enabled" optional:"yes" optional-value:"true"`

	// Cache controls whether DNS responses are cached or not.
	Cache bool `yaml:"cache" long:"cache" description:"If specified, DNS cache is enabled" optional:"yes" optional-value:"true"`

	// RefuseAny makes the server to refuse requests of type ANY.
	RefuseAny bool `yaml:"refuse-any" long:"refuse-any" description:"If specified, refuse ANY requests" optional:"yes" optional-value:"true"`

	// EnableEDNSSubnet uses EDNS Client Subnet extension.
	EnableEDNSSubnet bool `yaml:"edns" long:"edns" description:"Use EDNS Client Subnet extension" optional:"yes" optional-value:"true"`

	// DNS64 defines whether DNS64 functionality is enabled or not.
	DNS64 bool `yaml:"dns64" long:"dns64" description:"If specified, dnsproxy will act as a DNS64 server" optional:"yes" optional-value:"true"`

	// UsePrivateRDNS makes the server to use private upstreams for reverse DNS
	// lookups of private addresses, including the requests for authority
	// records, such as SOA and NS.
	UsePrivateRDNS bool `yaml:"use-private-rdns" long:"use-private-rdns" description:"If specified, use private upstreams for reverse DNS lookups of private addresses" optional:"yes" optional-value:"true"`
}

// parseOptions returns options parsed from the command args or config file.
// If no options have been parsed returns a suitable exit code and an error.
func parseOptions() (opts *Options, exitCode int, err error) {
	opts = &Options{}

	// TODO(e.burkov, a.garipov):  Use flag package and remove the manual
	// options parsing.
	//
	// See https://github.com/AdguardTeam/dnsproxy/issues/182.
	for _, arg := range os.Args {
		if arg == argVersion {
			fmt.Printf("dnsproxy version: %s\n", version.Version())

			return nil, osutil.ExitCodeSuccess, nil
		} else if strings.HasPrefix(arg, argConfigPath) {
			confPath := strings.TrimPrefix(arg, argConfigPath)
			fmt.Printf("dnsproxy config path: %s\n", confPath)

			err = parseConfigFile(opts, confPath)
			if err != nil {
				return nil, osutil.ExitCodeFailure, fmt.Errorf(
					"parsing config file %s: %w",
					confPath,
					err,
				)
			}
		}
	}

	parser := goFlags.NewParser(opts, goFlags.Default)
	_, err = parser.Parse()
	if err != nil {
		if flagsErr, ok := err.(*goFlags.Error); ok && flagsErr.Type == goFlags.ErrHelp {
			return nil, osutil.ExitCodeSuccess, nil
		}

		return nil, osutil.ExitCodeArgumentError, nil
	}

	return opts, osutil.ExitCodeSuccess, nil
}

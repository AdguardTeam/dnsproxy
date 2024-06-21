// Package main is responsible for command-line interface of dnsproxy.
package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/http/pprof"
	"net/netip"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	proxynetutil "github.com/AdguardTeam/dnsproxy/internal/netutil"
	"github.com/AdguardTeam/dnsproxy/internal/version"
	"github.com/AdguardTeam/dnsproxy/proxy"
	"github.com/AdguardTeam/dnsproxy/upstream"
	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/log"
	"github.com/AdguardTeam/golibs/logutil/slogutil"
	"github.com/AdguardTeam/golibs/netutil"
	"github.com/AdguardTeam/golibs/osutil"
	"github.com/AdguardTeam/golibs/timeutil"
	"github.com/ameshkov/dnscrypt/v2"
	goFlags "github.com/jessevdk/go-flags"
	"github.com/miekg/dns"
	"gopkg.in/yaml.v3"
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

	// AllServers makes server to query all configured upstream servers in
	// parallel.
	AllServers bool `yaml:"all-servers" long:"all-servers" description:"If specified, parallel queries to all configured upstream servers are enabled" optional:"yes" optional-value:"true"`

	// FastestAddress controls whether the server should respond to A or AAAA
	// requests only with the fastest IP address detected by ICMP response time
	// or TCP connection time.
	FastestAddress bool `yaml:"fastest-addr" long:"fastest-addr" description:"Respond to A or AAAA requests only with the fastest IP address" optional:"yes" optional-value:"true"`

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

const (
	defaultLocalTimeout = 1 * time.Second

	argConfigPath = "--config-path="
	argVersion    = "--version"

	// statusArgumentError is returned when the program exits due to invalid
	// command-line argument or its value.
	//
	// TODO(a.garipov): Add to golibs.
	statusArgumentError = 2
)

// main is the entry point.
func main() {
	opts, exitCode, err := parseOptions()
	if err != nil {
		log.Fatalf("parsing options: %s", err)
	} else if opts == nil {
		os.Exit(exitCode)
	}

	// TODO(d.kolyshev): Remove after migration to slog.
	if opts.Verbose {
		log.SetLevel(log.DEBUG)
	}

	logOutput := os.Stdout
	if opts.LogOutput != "" {
		// #nosec G302 -- Trust the file path that is given in the
		// configuration.
		logOutput, err = os.OpenFile(opts.LogOutput, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o644)
		if err != nil {
			log.Fatalf("cannot create a log file: %s", err)
		}

		defer func() { _ = logOutput.Close() }()
		log.SetOutput(logOutput)
	}

	l := slogutil.New(&slogutil.Config{
		Output: logOutput,
		Format: slogutil.FormatAdGuardLegacy,
		// TODO(d.kolyshev): Consider making configurable.
		AddTimestamp: true,
		Verbose:      opts.Verbose,
	})

	ctx := context.Background()

	if opts.Pprof {
		runPprof(l)
	}

	err = runProxy(ctx, l, opts)
	if err != nil {
		l.ErrorContext(ctx, "running dnsproxy", slogutil.KeyError, err)

		// As defers are skipped in case of os.Exit, close logOutput manually.
		//
		// TODO(a.garipov): Consider making logger.Close method.
		if logOutput != os.Stdout {
			_ = logOutput.Close()
		}

		os.Exit(osutil.ExitCodeFailure)
	}
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

		return nil, statusArgumentError, nil
	}

	return opts, osutil.ExitCodeSuccess, nil
}

// parseConfigFile fills options with the settings from file read by the given
// path.
func parseConfigFile(options *Options, confPath string) (err error) {
	// #nosec G304 -- Trust the file path that is given in the args.
	b, err := os.ReadFile(confPath)
	if err != nil {
		return fmt.Errorf("reading file: %w", err)
	}

	err = yaml.Unmarshal(b, options)
	if err != nil {
		return fmt.Errorf("unmarshalling file: %w", err)
	}

	return nil
}

// runProxy starts and runs the proxy.  l must not be nil.
func runProxy(ctx context.Context, l *slog.Logger, options *Options) (err error) {
	var (
		buildVersion = version.Version()
		revision     = version.Revision()
		branch       = version.Branch()
		commitTime   = version.CommitTime()
	)

	l.InfoContext(
		ctx,
		"dnsproxy starting",
		"version", buildVersion,
		"revision", revision,
		"branch", branch,
		"commit_time", commitTime,
	)

	// Prepare the proxy server and its configuration.
	conf, err := createProxyConfig(ctx, l, options)
	if err != nil {
		return fmt.Errorf("configuring proxy: %w", err)
	}

	dnsProxy, err := proxy.New(conf)
	if err != nil {
		return fmt.Errorf("creating proxy: %w", err)
	}

	// Add extra handler if needed.
	if options.IPv6Disabled {
		ipv6Config := ipv6Configuration{
			logger:       l,
			ipv6Disabled: options.IPv6Disabled,
		}
		dnsProxy.RequestHandler = ipv6Config.handleDNSRequest
	}

	// Start the proxy server.
	err = dnsProxy.Start(ctx)
	if err != nil {
		return fmt.Errorf("starting dnsproxy: %w", err)
	}

	// TODO(e.burkov):  Use signal handler.
	signalChannel := make(chan os.Signal, 1)
	signal.Notify(signalChannel, syscall.SIGINT, syscall.SIGTERM)
	<-signalChannel

	// Stopping the proxy.
	err = dnsProxy.Shutdown(ctx)
	if err != nil {
		return fmt.Errorf("stopping dnsproxy: %w", err)
	}

	return nil
}

// runPprof runs pprof server on localhost:6060.
func runPprof(l *slog.Logger) {
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
		// TODO(d.kolyshev): Consider making configurable.
		pprofAddr := "localhost:6060"
		l.Info("starting pprof", "addr", pprofAddr)

		srv := &http.Server{
			Addr:        pprofAddr,
			ReadTimeout: 60 * time.Second,
			Handler:     mux,
		}

		err := srv.ListenAndServe()
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			l.Error("pprof failed to listen %v", "addr", pprofAddr, slogutil.KeyError, err)
		}
	}()
}

// createProxyConfig initializes [proxy.Config].  l must not be nil.
func createProxyConfig(
	ctx context.Context,
	l *slog.Logger,
	options *Options,
) (conf *proxy.Config, err error) {
	conf = &proxy.Config{
		Logger: l.With(slogutil.KeyPrefix, proxy.LogPrefix),

		RatelimitSubnetLenIPv4: options.RatelimitSubnetLenIPv4,
		RatelimitSubnetLenIPv6: options.RatelimitSubnetLenIPv6,

		Ratelimit:       options.Ratelimit,
		CacheEnabled:    options.Cache,
		CacheSizeBytes:  options.CacheSizeBytes,
		CacheMinTTL:     options.CacheMinTTL,
		CacheMaxTTL:     options.CacheMaxTTL,
		CacheOptimistic: options.CacheOptimistic,
		RefuseAny:       options.RefuseAny,
		HTTP3:           options.HTTP3,
		// TODO(e.burkov):  The following CIDRs are aimed to match any address.
		// This is not quite proper approach to be used by default so think
		// about configuring it.
		TrustedProxies: netutil.SliceSubnetSet{
			netip.MustParsePrefix("0.0.0.0/0"),
			netip.MustParsePrefix("::0/0"),
		},
		EnableEDNSClientSubnet: options.EnableEDNSSubnet,
		UDPBufferSize:          options.UDPBufferSize,
		HTTPSServerName:        options.HTTPSServerName,
		MaxGoroutines:          options.MaxGoRoutines,
		UsePrivateRDNS:         options.UsePrivateRDNS,
		PrivateSubnets:         netutil.SubnetSetFunc(netutil.IsLocallyServed),
	}

	if uiStr := options.HTTPSUserinfo; uiStr != "" {
		user, pass, ok := strings.Cut(uiStr, ":")
		if ok {
			conf.Userinfo = url.UserPassword(user, pass)
		} else {
			conf.Userinfo = url.User(user)
		}
	}

	options.initBogusNXDomain(ctx, l, conf)

	var errs []error
	errs = append(errs, options.initUpstreams(ctx, l, conf))
	errs = append(errs, options.initEDNS(ctx, l, conf))
	errs = append(errs, options.initTLSConfig(conf))
	errs = append(errs, options.initDNSCryptConfig(conf))
	errs = append(errs, options.initListenAddrs(conf))
	errs = append(errs, options.initSubnets(conf))

	return conf, errors.Join(errs...)
}

// isEmpty returns false if uc contains at least a single upstream.  uc must not
// be nil.
//
// TODO(e.burkov):  Think of a better way to validate the config.  Perhaps,
// return an error from [ParseUpstreamsConfig] if no upstreams were initialized.
func isEmpty(uc *proxy.UpstreamConfig) (ok bool) {
	return len(uc.Upstreams) == 0 &&
		len(uc.DomainReservedUpstreams) == 0 &&
		len(uc.SpecifiedDomainUpstreams) == 0
}

// initUpstreams inits upstream-related config fields.
//
// TODO(d.kolyshev): Join errors.
func (opts *Options) initUpstreams(
	ctx context.Context,
	l *slog.Logger,
	config *proxy.Config,
) (err error) {
	httpVersions := upstream.DefaultHTTPVersions
	if opts.HTTP3 {
		httpVersions = []upstream.HTTPVersion{
			upstream.HTTPVersion3,
			upstream.HTTPVersion2,
			upstream.HTTPVersion11,
		}
	}

	timeout := opts.Timeout.Duration
	bootOpts := &upstream.Options{
		HTTPVersions:       httpVersions,
		InsecureSkipVerify: opts.Insecure,
		Timeout:            timeout,
	}
	boot, err := initBootstrap(ctx, l, opts.BootstrapDNS, bootOpts)
	if err != nil {
		return fmt.Errorf("initializing bootstrap: %w", err)
	}

	upsOpts := &upstream.Options{
		Logger:             l,
		HTTPVersions:       httpVersions,
		InsecureSkipVerify: opts.Insecure,
		Bootstrap:          boot,
		Timeout:            timeout,
	}
	upstreams := loadServersList(opts.Upstreams)

	config.UpstreamConfig, err = proxy.ParseUpstreamsConfig(upstreams, upsOpts)
	if err != nil {
		return fmt.Errorf("parsing upstreams configuration: %w", err)
	}

	privateUpsOpts := &upstream.Options{
		Logger:       l,
		HTTPVersions: httpVersions,
		Bootstrap:    boot,
		Timeout:      min(defaultLocalTimeout, timeout),
	}
	privateUpstreams := loadServersList(opts.PrivateRDNSUpstreams)

	private, err := proxy.ParseUpstreamsConfig(privateUpstreams, privateUpsOpts)
	if err != nil {
		return fmt.Errorf("parsing private rdns upstreams configuration: %w", err)
	}

	if !isEmpty(private) {
		config.PrivateRDNSUpstreamConfig = private
	}

	fallbackUpstreams := loadServersList(opts.Fallbacks)
	fallbacks, err := proxy.ParseUpstreamsConfig(fallbackUpstreams, upsOpts)
	if err != nil {
		return fmt.Errorf("parsing fallback upstreams configuration: %w", err)
	}

	if !isEmpty(fallbacks) {
		config.Fallbacks = fallbacks
	}

	if opts.AllServers {
		config.UpstreamMode = proxy.UModeParallel
	} else if opts.FastestAddress {
		config.UpstreamMode = proxy.UModeFastestAddr
	} else {
		config.UpstreamMode = proxy.UModeLoadBalance
	}

	return nil
}

// initBootstrap initializes the [upstream.Resolver] for bootstrapping upstream
// servers.  It returns the default resolver if no bootstraps were specified.
// The returned resolver will also use system hosts files first.
func initBootstrap(
	ctx context.Context,
	l *slog.Logger,
	bootstraps []string,
	opts *upstream.Options,
) (r upstream.Resolver, err error) {
	var resolvers []upstream.Resolver

	for i, b := range bootstraps {
		var ur *upstream.UpstreamResolver
		ur, err = upstream.NewUpstreamResolver(b, opts)
		if err != nil {
			return nil, fmt.Errorf("creating bootstrap resolver at index %d: %w", i, err)
		}

		resolvers = append(resolvers, upstream.NewCachingResolver(ur))
	}

	switch len(resolvers) {
	case 0:
		etcHosts, hostsErr := upstream.NewDefaultHostsResolver(osutil.RootDirFS())
		if hostsErr != nil {
			l.ErrorContext(ctx, "creating default hosts resolver", slogutil.KeyError, hostsErr)

			return net.DefaultResolver, nil
		}

		return upstream.ConsequentResolver{etcHosts, net.DefaultResolver}, nil
	case 1:
		return resolvers[0], nil
	default:
		return upstream.ParallelResolver(resolvers), nil
	}
}

// initEDNS inits EDNS-related config fields.
func (opts *Options) initEDNS(
	ctx context.Context,
	l *slog.Logger,
	config *proxy.Config,
) (err error) {
	if opts.EDNSAddr == "" {
		return nil
	}

	if !opts.EnableEDNSSubnet {
		l.WarnContext(ctx, "--edns is required", "--edns-addr", opts.EDNSAddr)

		return nil
	}

	config.EDNSAddr, err = netutil.ParseIP(opts.EDNSAddr)
	if err != nil {
		return fmt.Errorf("parsing edns-addr: %w", err)
	}

	return nil
}

// initBogusNXDomain inits BogusNXDomain structure.
func (opts *Options) initBogusNXDomain(ctx context.Context, l *slog.Logger, config *proxy.Config) {
	if len(opts.BogusNXDomain) == 0 {
		return
	}

	for i, s := range opts.BogusNXDomain {
		p, err := proxynetutil.ParseSubnet(s)
		if err != nil {
			// TODO(a.garipov): Consider returning this err as a proper error.
			l.WarnContext(ctx, "parsing bogus nxdomain", "index", i, slogutil.KeyError, err)
		} else {
			config.BogusNXDomain = append(config.BogusNXDomain, p)
		}
	}
}

// initTLSConfig inits the TLS config.
func (opts *Options) initTLSConfig(config *proxy.Config) (err error) {
	if opts.TLSCertPath != "" && opts.TLSKeyPath != "" {
		var tlsConfig *tls.Config
		tlsConfig, err = newTLSConfig(opts)
		if err != nil {
			return fmt.Errorf("loading TLS config: %w", err)
		}

		config.TLSConfig = tlsConfig
	}

	return nil
}

// initDNSCryptConfig inits the DNSCrypt config.
func (opts *Options) initDNSCryptConfig(config *proxy.Config) (err error) {
	if opts.DNSCryptConfigPath == "" {
		return
	}

	b, err := os.ReadFile(opts.DNSCryptConfigPath)
	if err != nil {
		return fmt.Errorf("reading DNSCrypt config %q: %w", opts.DNSCryptConfigPath, err)
	}

	rc := &dnscrypt.ResolverConfig{}
	err = yaml.Unmarshal(b, rc)
	if err != nil {
		return fmt.Errorf("unmarshalling DNSCrypt config: %w", err)
	}

	cert, err := rc.CreateCert()
	if err != nil {
		return fmt.Errorf("creating DNSCrypt certificate: %w", err)
	}

	config.DNSCryptResolverCert = cert
	config.DNSCryptProviderName = rc.ProviderName

	return nil
}

// initListenAddrs sets up proxy configuration listen IP addresses.
func (opts *Options) initListenAddrs(config *proxy.Config) (err error) {
	addrs, err := parseListenAddrs(opts)
	if err != nil {
		return fmt.Errorf("parsing listen addresses: %w", err)
	}

	if len(opts.ListenPorts) == 0 {
		// If ListenPorts has not been parsed through config file nor command
		// line we set it to 53.
		opts.ListenPorts = []int{53}
	}

	for _, port := range opts.ListenPorts {
		for _, ip := range addrs {
			addrPort := netip.AddrPortFrom(ip, uint16(port))

			config.UDPListenAddr = append(config.UDPListenAddr, net.UDPAddrFromAddrPort(addrPort))
			config.TCPListenAddr = append(config.TCPListenAddr, net.TCPAddrFromAddrPort(addrPort))
		}
	}

	initTLSListenAddrs(config, opts, addrs)
	initDNSCryptListenAddrs(config, opts, addrs)

	return nil
}

// initTLSListenAddrs sets up proxy configuration TLS listen addresses.
func initTLSListenAddrs(config *proxy.Config, options *Options, addrs []netip.Addr) {
	if config.TLSConfig == nil {
		return
	}

	for _, ip := range addrs {
		for _, port := range options.TLSListenPorts {
			a := net.TCPAddrFromAddrPort(netip.AddrPortFrom(ip, uint16(port)))
			config.TLSListenAddr = append(config.TLSListenAddr, a)
		}

		for _, port := range options.HTTPSListenPorts {
			a := net.TCPAddrFromAddrPort(netip.AddrPortFrom(ip, uint16(port)))
			config.HTTPSListenAddr = append(config.HTTPSListenAddr, a)
		}

		for _, port := range options.QUICListenPorts {
			a := net.UDPAddrFromAddrPort(netip.AddrPortFrom(ip, uint16(port)))
			config.QUICListenAddr = append(config.QUICListenAddr, a)
		}
	}
}

// initDNSCryptListenAddrs sets up proxy configuration DNSCrypt listen
// addresses.
func initDNSCryptListenAddrs(config *proxy.Config, options *Options, addrs []netip.Addr) {
	if config.DNSCryptResolverCert == nil || config.DNSCryptProviderName == "" {
		return
	}

	for _, port := range options.DNSCryptListenPorts {
		p := uint16(port)

		for _, ip := range addrs {
			addrPort := netip.AddrPortFrom(ip, p)

			tcp := net.TCPAddrFromAddrPort(addrPort)
			config.DNSCryptTCPListenAddr = append(config.DNSCryptTCPListenAddr, tcp)

			udp := net.UDPAddrFromAddrPort(addrPort)
			config.DNSCryptUDPListenAddr = append(config.DNSCryptUDPListenAddr, udp)
		}
	}
}

// parseListenAddrs returns a slice of listen IP addresses from the given
// options.  In case no addresses are specified by options returns a slice with
// the IPv4 unspecified address "0.0.0.0".
func parseListenAddrs(options *Options) (addrs []netip.Addr, err error) {
	// TODO(d.kolyshev): Join errors.
	for i, a := range options.ListenAddrs {
		var ip netip.Addr
		ip, err = netip.ParseAddr(a)
		if err != nil {
			return addrs, fmt.Errorf("parsing listen address at index %d: %s", i, a)
		}

		addrs = append(addrs, ip)
	}

	if len(addrs) == 0 {
		// If ListenAddrs has not been parsed through config file nor command
		// line we set it to "0.0.0.0".
		//
		// TODO(a.garipov): Consider using localhost.
		addrs = append(addrs, netip.IPv4Unspecified())
	}

	return addrs, nil
}

// initSubnets sets the DNS64 configuration into conf.
//
// TODO(d.kolyshev): Join errors.
func (opts *Options) initSubnets(conf *proxy.Config) (err error) {
	if conf.UseDNS64 = opts.DNS64; conf.UseDNS64 {
		for i, p := range opts.DNS64Prefix {
			var pref netip.Prefix
			pref, err = netip.ParsePrefix(p)
			if err != nil {
				return fmt.Errorf("parsing dns64 prefix at index %d: %w", i, err)
			}

			conf.DNS64Prefs = append(conf.DNS64Prefs, pref)
		}
	}

	if !opts.UsePrivateRDNS {
		return nil
	}

	return opts.initPrivateSubnets(conf)
}

// initSubnets sets the private subnets configuration into conf.
func (opts *Options) initPrivateSubnets(conf *proxy.Config) (err error) {
	private := make([]netip.Prefix, 0, len(opts.PrivateSubnets))
	for i, p := range opts.PrivateSubnets {
		var pref netip.Prefix
		pref, err = netip.ParsePrefix(p)
		if err != nil {
			return fmt.Errorf("parsing private subnet at index %d: %w", i, err)
		}

		private = append(private, pref)
	}

	if len(private) > 0 {
		conf.PrivateSubnets = netutil.SliceSubnetSet(private)
	}

	return nil
}

// ipv6Configuration represents IPv6 configuration.
type ipv6Configuration struct {
	// logger is used for logging during requests handling.  It is never nil.
	logger *slog.Logger

	// ipv6Disabled set all AAAA requests to be replied with NoError RCode and
	// an empty answer.
	ipv6Disabled bool
}

// handleDNSRequest checks the IPv6 configuration for current session before
// resolving.
func (c *ipv6Configuration) handleDNSRequest(p *proxy.Proxy, ctx *proxy.DNSContext) (err error) {
	if !c.isIPv6Enabled(ctx, !c.ipv6Disabled) {
		return nil
	}

	return p.Resolve(ctx)
}

// retryNoError is the time for NoError SOA.
const retryNoError = 60

// isIPv6Enabled checks if AAAA requests should be enabled or not and sets
// NoError empty response to the given DNSContext if needed.
func (c *ipv6Configuration) isIPv6Enabled(ctx *proxy.DNSContext, ipv6Enabled bool) (enabled bool) {
	if !ipv6Enabled && ctx.Req.Question[0].Qtype == dns.TypeAAAA {
		c.logger.Debug(
			"ipv6 is disabled; replying with empty response",
			"req", ctx.Req.Question[0].Name,
		)

		ctx.Res = proxy.GenEmptyMessage(ctx.Req, dns.RcodeSuccess, retryNoError)

		return false
	}

	return true
}

// NewTLSConfig returns the TLS config that includes a certificate.  Use it for
// server TLS configuration or for a client certificate.  If caPath is empty,
// system CAs will be used.
func newTLSConfig(options *Options) (c *tls.Config, err error) {
	// Set default TLS min/max versions
	tlsMinVersion := tls.VersionTLS10
	tlsMaxVersion := tls.VersionTLS13

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
		return nil, fmt.Errorf("loading TLS cert: %s", err)
	}

	// #nosec G402 -- TLS MinVersion is configured by user.
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   uint16(tlsMinVersion),
		MaxVersion:   uint16(tlsMaxVersion),
	}, nil
}

// loadX509KeyPair reads and parses a public/private key pair from a pair of
// files.  The files must contain PEM encoded data.  The certificate file may
// contain intermediate certificates following the leaf certificate to form a
// certificate chain.  On successful return, Certificate.Leaf will be nil
// because the parsed form of the certificate is not retained.
func loadX509KeyPair(certFile, keyFile string) (crt tls.Certificate, err error) {
	// #nosec G304 -- Trust the file path that is given in the configuration.
	certPEMBlock, err := os.ReadFile(certFile)
	if err != nil {
		return tls.Certificate{}, err
	}

	// #nosec G304 -- Trust the file path that is given in the configuration.
	keyPEMBlock, err := os.ReadFile(keyFile)
	if err != nil {
		return tls.Certificate{}, err
	}

	return tls.X509KeyPair(certPEMBlock, keyPEMBlock)
}

// loadServersList loads a list of DNS servers from the specified list.  The
// thing is that the user may specify either a server address or the path to a
// file with a list of addresses.  This method takes care of it, it reads the
// file and loads servers from this file if needed.
func loadServersList(sources []string) []string {
	var servers []string

	for _, source := range sources {
		// #nosec G304 -- Trust the file path that is given in the
		// configuration.
		data, err := os.ReadFile(source)
		if err != nil {
			// Ignore errors, just consider it a server address and not a file.
			servers = append(servers, source)
		}

		lines := strings.Split(string(data), "\n")
		for _, line := range lines {
			line = strings.TrimSpace(line)

			// Ignore comments in the file.
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

package cmd

import (
	"context"
	"crypto/tls"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"net/url"
	"os"
	"strings"

	"github.com/AdguardTeam/dnsproxy/internal/dnsmsg"
	"github.com/AdguardTeam/dnsproxy/internal/handler"
	proxynetutil "github.com/AdguardTeam/dnsproxy/internal/netutil"
	"github.com/AdguardTeam/dnsproxy/proxy"
	"github.com/AdguardTeam/dnsproxy/upstream"
	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/logutil/slogutil"
	"github.com/AdguardTeam/golibs/netutil"
	"github.com/AdguardTeam/golibs/osutil"
	"github.com/ameshkov/dnscrypt/v2"
	"gopkg.in/yaml.v3"
)

// TODO(e.burkov):  Use a separate type for the YAML configuration file.

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

// createProxyConfig initializes [proxy.Config].  l must not be nil.
func createProxyConfig(
	ctx context.Context,
	l *slog.Logger,
	options *Options,
) (conf *proxy.Config, err error) {
	reqHdlr := handler.NewDefault(&handler.DefaultConfig{
		Logger: l.With(slogutil.KeyPrefix, "default_handler"),
		// TODO(e.burkov):  Use the configured message constructor.
		MessageConstructor: dnsmsg.DefaultMessageConstructor{},
		HaltIPv6:           options.IPv6Disabled,
	})

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
		RequestHandler:         reqHdlr.HandleRequest,
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
		Logger:             l,
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

	if opts.UpstreamMode != "" {
		err = config.UpstreamMode.UnmarshalText([]byte(opts.UpstreamMode))
		if err != nil {
			return fmt.Errorf("parsing upstream mode: %w", err)
		}

		return nil
	}

	config.UpstreamMode = proxy.UpstreamModeLoadBalance

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
		etcHosts, hostsErr := upstream.NewDefaultHostsResolver(osutil.RootDirFS(), l)
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

// parseListenAddrs returns a slice of listen IP addresses from the given
// options.  In case no addresses are specified by options returns a slice with
// the IPv4 unspecified address "0.0.0.0".
//
// TODO(d.kolyshev): Join errors.
func parseListenAddrs(addrStrs []string) (addrs []netip.Addr, err error) {
	for i, a := range addrStrs {
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

// initListenAddrs sets up proxy configuration listen IP addresses.
func (opts *Options) initListenAddrs(config *proxy.Config) (err error) {
	addrs, err := parseListenAddrs(opts.ListenAddrs)
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

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
	"time"

	"github.com/AdguardTeam/dnsproxy/internal/dnsmsg"
	"github.com/AdguardTeam/dnsproxy/internal/middleware"
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

// createProxyConfig initializes [proxy.Config].  l must not be nil.
func createProxyConfig(
	ctx context.Context,
	l *slog.Logger,
	conf *configuration,
) (proxyConf *proxy.Config, err error) {
	hostsFiles, err := conf.hostsFiles(ctx, l)
	if err != nil {
		// Don't wrap the error since it's informative enough as is.
		return nil, err
	}

	hosts, err := middleware.ReadHosts(ctx, l, hostsFiles)
	if err != nil {
		return nil, fmt.Errorf("reading hosts files: %w", err)
	}

	preMw := middleware.New(&middleware.Config{
		Logger: l.With(slogutil.KeyPrefix, "pre_handler_mw"),
		// TODO(e.burkov):  Use the configured message constructor.
		MessageConstructor: dnsmsg.DefaultMessageConstructor{},
		HaltIPv6:           conf.IPv6Disabled,
		HostsFiles:         hosts,
	})

	proxyConf = &proxy.Config{
		Logger: l.With(slogutil.KeyPrefix, proxy.LogPrefix),

		RatelimitSubnetLenIPv4: conf.RatelimitSubnetLenIPv4,
		RatelimitSubnetLenIPv6: conf.RatelimitSubnetLenIPv6,

		Ratelimit:                conf.Ratelimit,
		CacheEnabled:             conf.Cache,
		CacheSizeBytes:           conf.CacheSizeBytes,
		CacheMinTTL:              conf.CacheMinTTL,
		CacheMaxTTL:              conf.CacheMaxTTL,
		CacheOptimisticAnswerTTL: time.Duration(conf.OptimisticAnswerTTL),
		CacheOptimisticMaxAge:    time.Duration(conf.OptimisticMaxAge),
		CacheOptimistic:          conf.CacheOptimistic,
		RefuseAny:                conf.RefuseAny,
		HTTP3:                    conf.HTTP3,
		// TODO(e.burkov):  The following CIDRs are aimed to match any address.
		// This is not quite proper approach to be used by default so think
		// about configuring it.
		TrustedProxies: netutil.SliceSubnetSet{
			netip.MustParsePrefix("0.0.0.0/0"),
			netip.MustParsePrefix("::0/0"),
		},
		EnableEDNSClientSubnet: conf.EnableEDNSSubnet,
		UDPBufferSize:          conf.UDPBufferSize,
		HTTPSServerName:        conf.HTTPSServerName,
		MaxGoroutines:          conf.MaxGoRoutines,
		UsePrivateRDNS:         conf.UsePrivateRDNS,
		PrivateSubnets:         netutil.SubnetSetFunc(netutil.IsLocallyServed),
		RequestHandler:         preMw.Wrap(proxy.DefaultHandler{}),
		PendingRequests: &proxy.PendingRequestsConfig{
			Enabled: conf.PendingRequestsEnabled,
		},
	}

	if uiStr := conf.HTTPSUserinfo; uiStr != "" {
		user, pass, ok := strings.Cut(uiStr, ":")
		if ok {
			proxyConf.Userinfo = url.UserPassword(user, pass)
		} else {
			proxyConf.Userinfo = url.User(user)
		}
	}

	conf.initBogusNXDomain(ctx, l, proxyConf)

	var errs []error
	errs = append(errs, conf.initUpstreams(ctx, l, proxyConf))
	errs = append(errs, conf.initEDNS(ctx, l, proxyConf))
	errs = append(errs, conf.initTLSConfig(proxyConf))
	errs = append(errs, conf.initDNSCryptConfig(proxyConf))
	errs = append(errs, conf.initListenAddrs(proxyConf))
	errs = append(errs, conf.initSubnets(proxyConf))

	return proxyConf, errors.Join(errs...)
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

// defaultLocalTimeout is the default timeout for local operations.
const defaultLocalTimeout = 1 * time.Second

// initUpstreams inits upstream-related config fields.
//
// TODO(d.kolyshev): Join errors.
func (conf *configuration) initUpstreams(
	ctx context.Context,
	l *slog.Logger,
	config *proxy.Config,
) (err error) {
	httpVersions := upstream.DefaultHTTPVersions
	if conf.HTTP3 {
		httpVersions = []upstream.HTTPVersion{
			upstream.HTTPVersion3,
			upstream.HTTPVersion2,
			upstream.HTTPVersion11,
		}
	}

	timeout := time.Duration(conf.Timeout)
	bootOpts := &upstream.Options{
		Logger:             l,
		HTTPVersions:       httpVersions,
		InsecureSkipVerify: conf.Insecure,
		Timeout:            timeout,
	}
	boot, err := initBootstrap(ctx, l, conf.BootstrapDNS, bootOpts)
	if err != nil {
		return fmt.Errorf("initializing bootstrap: %w", err)
	}

	upsOpts := &upstream.Options{
		Logger:             l,
		HTTPVersions:       httpVersions,
		InsecureSkipVerify: conf.Insecure,
		Bootstrap:          boot,
		Timeout:            timeout,
	}
	upstreams := loadServersList(conf.Upstreams)

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
	privateUpstreams := loadServersList(conf.PrivateRDNSUpstreams)

	private, err := proxy.ParseUpstreamsConfig(privateUpstreams, privateUpsOpts)
	if err != nil {
		return fmt.Errorf("parsing private rdns upstreams configuration: %w", err)
	}

	if !isEmpty(private) {
		config.PrivateRDNSUpstreamConfig = private
	}

	fallbackUpstreams := loadServersList(conf.Fallbacks)
	fallbacks, err := proxy.ParseUpstreamsConfig(fallbackUpstreams, upsOpts)
	if err != nil {
		return fmt.Errorf("parsing fallback upstreams configuration: %w", err)
	}

	if !isEmpty(fallbacks) {
		config.Fallbacks = fallbacks
	}

	if conf.UpstreamMode != "" {
		err = config.UpstreamMode.UnmarshalText([]byte(conf.UpstreamMode))
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
		etcHosts, hostsErr := upstream.NewDefaultHostsResolver(ctx, osutil.RootDirFS(), l)
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
func (conf *configuration) initEDNS(
	ctx context.Context,
	l *slog.Logger,
	config *proxy.Config,
) (err error) {
	if conf.EDNSAddr == "" {
		return nil
	}

	if !conf.EnableEDNSSubnet {
		l.WarnContext(ctx, "--edns is required", "--edns-addr", conf.EDNSAddr)

		return nil
	}

	config.EDNSAddr, err = netutil.ParseIP(conf.EDNSAddr)
	if err != nil {
		return fmt.Errorf("parsing edns-addr: %w", err)
	}

	return nil
}

// initBogusNXDomain inits BogusNXDomain structure.
func (conf *configuration) initBogusNXDomain(
	ctx context.Context,
	l *slog.Logger,
	config *proxy.Config,
) {
	if len(conf.BogusNXDomain) == 0 {
		return
	}

	for i, s := range conf.BogusNXDomain {
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
func (conf *configuration) initTLSConfig(config *proxy.Config) (err error) {
	if conf.TLSCertPath != "" && conf.TLSKeyPath != "" {
		var tlsConfig *tls.Config
		tlsConfig, err = newTLSConfig(conf)
		if err != nil {
			return fmt.Errorf("loading TLS config: %w", err)
		}

		config.TLSConfig = tlsConfig
	}

	return nil
}

// initDNSCryptConfig inits the DNSCrypt config.
func (conf *configuration) initDNSCryptConfig(config *proxy.Config) (err error) {
	if conf.DNSCryptConfigPath == "" {
		return nil
	}

	b, err := os.ReadFile(conf.DNSCryptConfigPath)
	if err != nil {
		return fmt.Errorf("reading DNSCrypt config %q: %w", conf.DNSCryptConfigPath, err)
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
func (conf *configuration) initListenAddrs(config *proxy.Config) (err error) {
	addrs, err := parseListenAddrs(conf.ListenAddrs)
	if err != nil {
		return fmt.Errorf("parsing listen addresses: %w", err)
	}

	if len(conf.ListenPorts) == 0 {
		// If ListenPorts has not been parsed through config file nor command
		// line we set it to 53.
		conf.ListenPorts = []int{53}
	}

	for _, port := range conf.ListenPorts {
		if port == 0 {
			continue
		}
		for _, ip := range addrs {
			addrPort := netip.AddrPortFrom(ip, uint16(port))

			config.UDPListenAddr = append(config.UDPListenAddr, net.UDPAddrFromAddrPort(addrPort))
			config.TCPListenAddr = append(config.TCPListenAddr, net.TCPAddrFromAddrPort(addrPort))
		}
	}

	initTLSListenAddrs(config, conf, addrs)
	initDNSCryptListenAddrs(config, conf, addrs)

	return nil
}

// initTLSListenAddrs sets up proxy configuration TLS listen addresses.
func initTLSListenAddrs(proxyConf *proxy.Config, conf *configuration, addrs []netip.Addr) {
	if proxyConf.TLSConfig == nil {
		return
	}

	for _, ip := range addrs {
		for _, port := range conf.TLSListenPorts {
			a := net.TCPAddrFromAddrPort(netip.AddrPortFrom(ip, uint16(port)))
			proxyConf.TLSListenAddr = append(proxyConf.TLSListenAddr, a)
		}

		for _, port := range conf.HTTPSListenPorts {
			a := net.TCPAddrFromAddrPort(netip.AddrPortFrom(ip, uint16(port)))
			proxyConf.HTTPSListenAddr = append(proxyConf.HTTPSListenAddr, a)
		}

		for _, port := range conf.QUICListenPorts {
			a := net.UDPAddrFromAddrPort(netip.AddrPortFrom(ip, uint16(port)))
			proxyConf.QUICListenAddr = append(proxyConf.QUICListenAddr, a)
		}
	}
}

// initDNSCryptListenAddrs sets up proxy configuration DNSCrypt listen
// addresses.
func initDNSCryptListenAddrs(proxyConf *proxy.Config, conf *configuration, addrs []netip.Addr) {
	if proxyConf.DNSCryptResolverCert == nil || proxyConf.DNSCryptProviderName == "" {
		return
	}

	for _, port := range conf.DNSCryptListenPorts {
		p := uint16(port)

		for _, ip := range addrs {
			addrPort := netip.AddrPortFrom(ip, p)

			tcp := net.TCPAddrFromAddrPort(addrPort)
			proxyConf.DNSCryptTCPListenAddr = append(proxyConf.DNSCryptTCPListenAddr, tcp)

			udp := net.UDPAddrFromAddrPort(addrPort)
			proxyConf.DNSCryptUDPListenAddr = append(proxyConf.DNSCryptUDPListenAddr, udp)
		}
	}
}

// initSubnets sets the DNS64 configuration into conf.
//
// TODO(d.kolyshev): Join errors.
func (conf *configuration) initSubnets(proxyConf *proxy.Config) (err error) {
	if proxyConf.UseDNS64 = conf.DNS64; proxyConf.UseDNS64 {
		for i, p := range conf.DNS64Prefix {
			var pref netip.Prefix
			pref, err = netip.ParsePrefix(p)
			if err != nil {
				return fmt.Errorf("parsing dns64 prefix at index %d: %w", i, err)
			}

			proxyConf.DNS64Prefs = append(proxyConf.DNS64Prefs, pref)
		}
	}

	if !conf.UsePrivateRDNS {
		return nil
	}

	return conf.initPrivateSubnets(proxyConf)
}

// initSubnets sets the private subnets configuration into conf.
func (conf *configuration) initPrivateSubnets(proxyConf *proxy.Config) (err error) {
	private := make([]netip.Prefix, 0, len(conf.PrivateSubnets))
	for i, p := range conf.PrivateSubnets {
		var pref netip.Prefix
		pref, err = netip.ParsePrefix(p)
		if err != nil {
			return fmt.Errorf("parsing private subnet at index %d: %w", i, err)
		}

		private = append(private, pref)
	}

	if len(private) > 0 {
		proxyConf.PrivateSubnets = netutil.SliceSubnetSet(private)
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

// hostsFiles returns the list of hosts files to resolve from.  It's empty if
// resolving from hosts files is disabled.
func (conf *configuration) hostsFiles(
	ctx context.Context,
	l *slog.Logger,
) (paths []string, err error) {
	if !conf.HostsFileEnabled {
		l.DebugContext(ctx, "hosts files are disabled")

		return nil, nil
	}

	l.DebugContext(ctx, "hosts files are enabled")

	if len(conf.HostsFiles) > 0 {
		return conf.HostsFiles, nil
	}

	paths, err = proxynetutil.DefaultHostsPaths()
	if err != nil {
		return nil, fmt.Errorf("getting default hosts files: %w", err)
	}

	l.DebugContext(ctx, "hosts files are not specified, using default", "paths", paths)

	return paths, nil
}

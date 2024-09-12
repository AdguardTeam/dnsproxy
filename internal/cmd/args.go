package cmd

import (
	"flag"
	"fmt"
	"io"
	"os"
	"slices"
	"strings"

	"github.com/AdguardTeam/dnsproxy/internal/version"
	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/osutil"
	"github.com/AdguardTeam/golibs/timeutil"
)

// Indexes to help with the [commandLineOptions] initialization.
const (
	configPathIdx = iota
	logOutputIdx
	tlsCertPathIdx
	tlsKeyPathIdx
	httpsServerNameIdx
	httpsUserinfoIdx
	dnsCryptConfigPathIdx
	ednsAddrIdx
	upstreamModeIdx
	listenAddrsIdx
	listenPortsIdx
	httpsListenPortsIdx
	tlsListenPortsIdx
	quicListenPortsIdx
	dnsCryptListenPortsIdx
	upstreamsIdx
	bootstrapDNSIdx
	fallbacksIdx
	privateRDNSUpstreamsIdx
	dns64PrefixIdx
	privateSubnetsIdx
	bogusNXDomainIdx
	hostsFilesIdx
	timeoutIdx
	cacheMinTTLIdx
	cacheMaxTTLIdx
	cacheSizeBytesIdx
	ratelimitIdx
	ratelimitSubnetLenIPv4Idx
	ratelimitSubnetLenIPv6Idx
	udpBufferSizeIdx
	maxGoRoutinesIdx
	tlsMinVersionIdx
	tlsMaxVersionIdx
	helpIdx
	hostsFileEnabledIdx
	pprofIdx
	versionIdx
	verboseIdx
	insecureIdx
	ipv6DisabledIdx
	http3Idx
	cacheOptimisticIdx
	cacheIdx
	refuseAnyIdx
	enableEDNSSubnetIdx
	dns64Idx
	usePrivateRDNSIdx
)

// commandLineOption contains information about a command-line option: its long
// and, if there is one, short forms, the value type, and the description.
type commandLineOption struct {
	description string
	long        string
	short       string
	valueType   string
}

// commandLineOptions are all command-line options currently supported by the
// binary.
var commandLineOptions = []*commandLineOption{
	configPathIdx: {
		description: "YAML configuration file. Minimal working configuration in config.yaml.dist." +
			" Options passed through command line will override the ones from this file.",
		long:      "config-path",
		short:     "",
		valueType: "path",
	},
	logOutputIdx: {
		description: `Path to the log file.`,
		long:        "output",
		short:       "o",
		valueType:   "path",
	},
	tlsCertPathIdx: {
		description: "Path to a file with the certificate chain.",
		long:        "tls-crt",
		short:       "c",
		valueType:   "path",
	},
	tlsKeyPathIdx: {
		description: "Path to a file with the private key.",
		long:        "tls-key",
		short:       "k",
		valueType:   "path",
	},
	httpsServerNameIdx: {
		description: "Set the Server header for the responses from the HTTPS server.",
		long:        "https-server-name",
		short:       "",
		valueType:   "name",
	},
	httpsUserinfoIdx: {
		description: "If set, all DoH queries are required to have this basic authentication " +
			"information.",
		long:      "https-userinfo",
		short:     "",
		valueType: "name",
	},
	dnsCryptConfigPathIdx: {
		description: "Path to a file with DNSCrypt configuration. You can generate one using " +
			"https://github.com/ameshkov/dnscrypt.",
		long:      "dnscrypt-config",
		short:     "g",
		valueType: "path",
	},
	ednsAddrIdx: {
		description: "Send EDNS Client Address.",
		long:        "edns-addr",
		short:       "",
		valueType:   "address",
	},
	upstreamModeIdx: {
		description: "Defines the upstreams logic mode, possible values: load_balance, parallel, " +
			"fastest_addr (default: load_balance).",
		long:      "upstream-mode",
		short:     "",
		valueType: "mode",
	},
	listenAddrsIdx: {
		description: "Listening addresses.",
		long:        "listen",
		short:       "l",
		valueType:   "address",
	},
	listenPortsIdx: {
		description: "Listening ports. Zero value disables TCP and UDP listeners.",
		long:        "port",
		short:       "p",
		valueType:   "port",
	},
	httpsListenPortsIdx: {
		description: "Listening ports for DNS-over-HTTPS.",
		long:        "https-port",
		short:       "s",
		valueType:   "port",
	},
	tlsListenPortsIdx: {
		description: "Listening ports for DNS-over-TLS.",
		long:        "tls-port",
		short:       "t",
		valueType:   "port",
	},
	quicListenPortsIdx: {
		description: "Listening ports for DNS-over-QUIC.",
		long:        "quic-port",
		short:       "q",
		valueType:   "port",
	},
	dnsCryptListenPortsIdx: {
		description: "Listening ports for DNSCrypt.",
		long:        "dnscrypt-port",
		short:       "y",
		valueType:   "port",
	},
	upstreamsIdx: {
		description: "An upstream to be used (can be specified multiple times). You can also " +
			"specify path to a file with the list of servers.",
		long:      "upstream",
		short:     "u",
		valueType: "",
	},
	bootstrapDNSIdx: {
		description: "Bootstrap DNS for DoH and DoT, can be specified multiple times (default: " +
			"use system-provided).",
		long:      "bootstrap",
		short:     "b",
		valueType: "",
	},
	fallbacksIdx: {
		description: "Fallback resolvers to use when regular ones are unavailable, can be " +
			"specified multiple times. You can also specify path to a file with the list of servers.",
		long:      "fallback",
		short:     "f",
		valueType: "",
	},
	privateRDNSUpstreamsIdx: {
		description: "Private DNS upstreams to use for reverse DNS lookups of private addresses, " +
			"can be specified multiple times.",
		long:      "private-rdns-upstream",
		short:     "",
		valueType: "",
	},
	dns64PrefixIdx: {
		description: "Prefix used to handle DNS64. If not specified, dnsproxy uses the " +
			"'Well-Known Prefix' 64:ff9b::.  Can be specified multiple times.",
		long:      "dns64-prefix",
		short:     "",
		valueType: "subnet",
	},
	privateSubnetsIdx: {
		description: "Private subnets to use for reverse DNS lookups of private addresses.",
		long:        "private-subnets",
		short:       "",
		valueType:   "subnet",
	},
	bogusNXDomainIdx: {
		description: "Transform the responses containing at least a single IP that matches " +
			"specified addresses and CIDRs into NXDOMAIN.  Can be specified multiple times.",
		long:      "bogus-nxdomain",
		short:     "",
		valueType: "subnet",
	},
	hostsFilesIdx: {
		description: "List of paths to the hosts files relative to the root, can be specified " +
			"multiple times.",
		long:      "hosts-files",
		short:     "",
		valueType: "path",
	},
	timeoutIdx: {
		description: "Timeout for outbound DNS queries to remote upstream servers in a " +
			"human-readable form",
		long:      "timeout",
		short:     "",
		valueType: "duration",
	},
	cacheMinTTLIdx: {
		description: "Minimum TTL value for DNS entries, in seconds. Capped at 3600. " +
			"Artificially extending TTLs should only be done with careful consideration.",
		long:      "cache-min-ttl",
		short:     "",
		valueType: "uint32",
	},
	cacheMaxTTLIdx: {
		description: "Maximum TTL value for DNS entries, in seconds.",
		long:        "cache-max-ttl",
		short:       "",
		valueType:   "uint32",
	},
	cacheSizeBytesIdx: {
		description: "Cache size (in bytes). Default: 64k.",
		long:        "cache-size",
		short:       "",
		valueType:   "int",
	},
	ratelimitIdx: {
		description: "Ratelimit (requests per second).",
		long:        "ratelimit",
		short:       "r",
		valueType:   "int",
	},
	ratelimitSubnetLenIPv4Idx: {
		description: "Ratelimit subnet length for IPv4.",
		long:        "ratelimit-subnet-len-ipv4",
		short:       "",
		valueType:   "int",
	},
	ratelimitSubnetLenIPv6Idx: {
		description: "Ratelimit subnet length for IPv6.",
		long:        "ratelimit-subnet-len-ipv6",
		short:       "",
		valueType:   "int",
	},
	udpBufferSizeIdx: {
		description: "Set the size of the UDP buffer in bytes. A value <= 0 will use the system " +
			"default.",
		long:      "udp-buf-size",
		short:     "",
		valueType: "int",
	},
	maxGoRoutinesIdx: {
		description: "Set the maximum number of go routines. A zero value will not not set a " +
			"maximum.",
		long:      "max-go-routines",
		short:     "",
		valueType: "uint",
	},
	tlsMinVersionIdx: {
		description: "Minimum TLS version, for example 1.0.",
		long:        "tls-min-version",
		short:       "",
		valueType:   "version",
	},
	tlsMaxVersionIdx: {
		description: "Maximum TLS version, for example 1.3.",
		long:        "tls-max-version",
		short:       "",
		valueType:   "version",
	},
	helpIdx: {
		description: "Print this help message and quit.",
		long:        "help",
		short:       "h",
		valueType:   "",
	},
	hostsFileEnabledIdx: {
		description: "If specified, use hosts files for resolving.",
		long:        "hosts-file-enabled",
		short:       "",
		valueType:   "",
	},
	pprofIdx: {
		description: "If present, exposes pprof information on localhost:6060.",
		long:        "pprof",
		short:       "",
		valueType:   "",
	},
	versionIdx: {
		description: "Prints the program version.",
		long:        "version",
		short:       "",
		valueType:   "",
	},
	verboseIdx: {
		description: "Verbose output.",
		long:        "verbose",
		short:       "v",
		valueType:   "",
	},
	insecureIdx: {
		description: "Disable secure TLS certificate validation.",
		long:        "insecure",
		short:       "",
		valueType:   "",
	},
	ipv6DisabledIdx: {
		description: "If specified, all AAAA requests will be replied with NoError RCode and " +
			"empty answer.",
		long:      "ipv6-disabled",
		short:     "",
		valueType: "",
	},
	http3Idx: {
		description: "Enable HTTP/3 support.",
		long:        "http3",
		short:       "",
		valueType:   "",
	},
	cacheOptimisticIdx: {
		description: "If specified, optimistic DNS cache is enabled.",
		long:        "cache-optimistic",
		short:       "",
		valueType:   "",
	},
	cacheIdx: {
		description: "If specified, DNS cache is enabled.",
		long:        "cache",
		short:       "",
		valueType:   "",
	},
	refuseAnyIdx: {
		description: "If specified, refuses ANY requests.",
		long:        "refuse-any",
		short:       "",
		valueType:   "",
	},
	enableEDNSSubnetIdx: {
		description: "Use EDNS Client Subnet extension.",
		long:        "edns",
		short:       "",
		valueType:   "",
	},
	dns64Idx: {
		description: "If specified, dnsproxy will act as a DNS64 server.",
		long:        "dns64",
		short:       "",
		valueType:   "",
	},
	usePrivateRDNSIdx: {
		description: "If specified, use private upstreams for reverse DNS lookups of private " +
			"addresses.",
		long:      "use-private-rdns",
		short:     "",
		valueType: "",
	},
}

// parseCmdLineOptions parses the command-line options.  conf must not be nil.
func parseCmdLineOptions(conf *configuration) (err error) {
	cmdName, args := os.Args[0], os.Args[1:]

	flags := flag.NewFlagSet(cmdName, flag.ContinueOnError)
	for i, fieldPtr := range []any{
		configPathIdx:             &conf.ConfigPath,
		logOutputIdx:              &conf.LogOutput,
		tlsCertPathIdx:            &conf.TLSCertPath,
		tlsKeyPathIdx:             &conf.TLSKeyPath,
		httpsServerNameIdx:        &conf.HTTPSServerName,
		httpsUserinfoIdx:          &conf.HTTPSUserinfo,
		dnsCryptConfigPathIdx:     &conf.DNSCryptConfigPath,
		ednsAddrIdx:               &conf.EDNSAddr,
		upstreamModeIdx:           &conf.UpstreamMode,
		listenAddrsIdx:            &conf.ListenAddrs,
		listenPortsIdx:            &conf.ListenPorts,
		httpsListenPortsIdx:       &conf.HTTPSListenPorts,
		tlsListenPortsIdx:         &conf.TLSListenPorts,
		quicListenPortsIdx:        &conf.QUICListenPorts,
		dnsCryptListenPortsIdx:    &conf.DNSCryptListenPorts,
		upstreamsIdx:              &conf.Upstreams,
		bootstrapDNSIdx:           &conf.BootstrapDNS,
		fallbacksIdx:              &conf.Fallbacks,
		privateRDNSUpstreamsIdx:   &conf.PrivateRDNSUpstreams,
		dns64PrefixIdx:            &conf.DNS64Prefix,
		privateSubnetsIdx:         &conf.PrivateSubnets,
		bogusNXDomainIdx:          &conf.BogusNXDomain,
		hostsFilesIdx:             &conf.HostsFiles,
		timeoutIdx:                &conf.Timeout,
		cacheMinTTLIdx:            &conf.CacheMinTTL,
		cacheMaxTTLIdx:            &conf.CacheMaxTTL,
		cacheSizeBytesIdx:         &conf.CacheSizeBytes,
		ratelimitIdx:              &conf.Ratelimit,
		ratelimitSubnetLenIPv4Idx: &conf.RatelimitSubnetLenIPv4,
		ratelimitSubnetLenIPv6Idx: &conf.RatelimitSubnetLenIPv6,
		udpBufferSizeIdx:          &conf.UDPBufferSize,
		maxGoRoutinesIdx:          &conf.MaxGoRoutines,
		tlsMinVersionIdx:          &conf.TLSMinVersion,
		tlsMaxVersionIdx:          &conf.TLSMaxVersion,
		helpIdx:                   &conf.help,
		hostsFileEnabledIdx:       &conf.HostsFileEnabled,
		pprofIdx:                  &conf.Pprof,
		versionIdx:                &conf.Version,
		verboseIdx:                &conf.Verbose,
		insecureIdx:               &conf.Insecure,
		ipv6DisabledIdx:           &conf.IPv6Disabled,
		http3Idx:                  &conf.HTTP3,
		cacheOptimisticIdx:        &conf.CacheOptimistic,
		cacheIdx:                  &conf.Cache,
		refuseAnyIdx:              &conf.RefuseAny,
		enableEDNSSubnetIdx:       &conf.EnableEDNSSubnet,
		dns64Idx:                  &conf.DNS64,
		usePrivateRDNSIdx:         &conf.UsePrivateRDNS,
	} {
		addOption(flags, fieldPtr, commandLineOptions[i])
	}

	flags.Usage = func() { usage(cmdName, os.Stderr) }

	err = flags.Parse(args)
	if err != nil {
		// Don't wrap the error, because it's informative enough as is.
		return err
	}

	return nil
}

// defineFlag defines a flag with specified setFlag function.  o must not be
// nil.
func defineFlag[T any](
	fieldPtr *T,
	o *commandLineOption,
	setFlag func(p *T, name string, value T, usage string),
) {
	setFlag(fieldPtr, o.long, *fieldPtr, o.description)
	if o.short != "" {
		setFlag(fieldPtr, o.short, *fieldPtr, o.description)
	}
}

// defineFlagVar defines a flag with the specified [flag.Value] value.  o must
// not be nil.
func defineFlagVar(flags *flag.FlagSet, value flag.Value, o *commandLineOption) {
	flags.Var(value, o.long, o.description)
	if o.short != "" {
		flags.Var(value, o.short, o.description)
	}
}

// defineTimeutilDurationFlag defines a flag with for the specified
// [*timeutil.Duration] pointer and command line option.  o must not be nil.
func defineTimeutilDurationFlag(
	flags *flag.FlagSet,
	fieldPtr *timeutil.Duration,
	o *commandLineOption,
) {
	flags.TextVar(fieldPtr, o.long, *fieldPtr, o.description)
	if o.short != "" {
		flags.TextVar(fieldPtr, o.short, *fieldPtr, o.description)
	}
}

// addOption adds the command-line option described by o to flags using fieldPtr
// as the pointer to the value.
func addOption(flags *flag.FlagSet, fieldPtr any, o *commandLineOption) {
	switch fieldPtr := fieldPtr.(type) {
	case *string:
		defineFlag(fieldPtr, o, flags.StringVar)
	case *bool:
		defineFlag(fieldPtr, o, flags.BoolVar)
	case *int:
		defineFlag(fieldPtr, o, flags.IntVar)
	case *uint:
		defineFlag(fieldPtr, o, flags.UintVar)
	case *uint32:
		defineFlagVar(flags, (*uint32Value)(fieldPtr), o)
	case *float32:
		defineFlagVar(flags, (*float32Value)(fieldPtr), o)
	case *[]int:
		defineFlagVar(flags, newIntSliceValue(fieldPtr), o)
	case *[]string:
		defineFlagVar(flags, newStringSliceValue(fieldPtr), o)
	case *timeutil.Duration:
		defineTimeutilDurationFlag(flags, fieldPtr, o)
	default:
		panic(fmt.Errorf("unexpected field pointer type %T: %w", fieldPtr, errors.ErrBadEnumValue))
	}
}

// usage prints a usage message similar to the one printed by package flag but
// taking long vs. short versions into account as well as using more informative
// value hints.
func usage(cmdName string, output io.Writer) {
	options := slices.Clone(commandLineOptions)
	slices.SortStableFunc(options, func(a, b *commandLineOption) (res int) {
		return strings.Compare(a.long, b.long)
	})

	b := &strings.Builder{}
	_, _ = fmt.Fprintf(b, "Usage of %s:\n", cmdName)

	for _, o := range options {
		writeUsageLine(b, o)

		// Use four spaces before the tab to trigger good alignment for both 4-
		// and 8-space tab stops.
		_, _ = fmt.Fprintf(b, "    \t%s\n", o.description)
	}

	_, _ = io.WriteString(output, b.String())
}

// writeUsageLine writes the usage line for the provided command-line option.
func writeUsageLine(b *strings.Builder, o *commandLineOption) {
	if o.short == "" {
		if o.valueType == "" {
			_, _ = fmt.Fprintf(b, "  --%s\n", o.long)
		} else {
			_, _ = fmt.Fprintf(b, "  --%s=%s\n", o.long, o.valueType)
		}

		return
	}

	if o.valueType == "" {
		_, _ = fmt.Fprintf(b, "  --%s/-%s\n", o.long, o.short)
	} else {
		_, _ = fmt.Fprintf(b, "  --%[1]s=%[3]s/-%[2]s %[3]s\n", o.long, o.short, o.valueType)
	}
}

// processCmdLineOptions decides if dnsproxy should exit depending on the
// results of command-line option parsing.
func processCmdLineOptions(conf *configuration, parseErr error) (exitCode int, needExit bool) {
	if parseErr != nil {
		// Assume that usage has already been printed.
		return osutil.ExitCodeArgumentError, true
	}

	if conf.help {
		usage(os.Args[0], os.Stdout)

		return osutil.ExitCodeSuccess, true
	}

	if conf.Version {
		fmt.Printf("dnsproxy version %s\n", version.Version())

		return osutil.ExitCodeSuccess, true
	}

	return osutil.ExitCodeSuccess, false
}

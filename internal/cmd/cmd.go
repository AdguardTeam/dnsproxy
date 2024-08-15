// Package cmd is the dnsproxy CLI entry point.
package cmd

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/pprof"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/AdguardTeam/dnsproxy/internal/version"
	"github.com/AdguardTeam/dnsproxy/proxy"
	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/logutil/slogutil"
	"github.com/AdguardTeam/golibs/osutil"
	"github.com/miekg/dns"
)

// Main is the entrypoint of dnsproxy CLI.  Main may accept arguments, such as
// embedded assets and command-line arguments.
func Main() {
	opts, exitCode, err := parseOptions()
	if err != nil {
		_, _ = fmt.Fprintln(os.Stderr, err)
	}

	if opts == nil {
		os.Exit(exitCode)
	}

	logOutput := os.Stdout
	if opts.LogOutput != "" {
		// #nosec G302 -- Trust the file path that is given in the
		// configuration.
		logOutput, err = os.OpenFile(opts.LogOutput, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o644)
		if err != nil {
			_, _ = fmt.Fprintln(os.Stderr, fmt.Errorf("cannot create a log file: %s", err))

			os.Exit(osutil.ExitCodeArgumentError)
		}

		defer func() { _ = logOutput.Close() }()
	}

	l := slogutil.New(&slogutil.Config{
		Output: logOutput,
		Format: slogutil.FormatDefault,
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

// runProxy starts and runs the proxy.  l must not be nil.
//
// TODO(e.burkov):  Move into separate dnssvc package.
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

	// TODO(e.burkov):  Use [service.SignalHandler].
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
//
// TODO(e.burkov):  Use [httputil.RoutePprof].
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

// ipv6Configuration represents IPv6 configuration.
//
// TODO(e.burkov):  Refactor and move to separate handler package.
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

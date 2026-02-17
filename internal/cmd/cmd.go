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
)

// Main is the entrypoint of dnsproxy CLI.  Main may accept arguments, such as
// embedded assets and command-line arguments.
func Main() {
	conf, exitCode, err := parseConfig()
	if err != nil {
		_, _ = fmt.Fprintln(os.Stderr, fmt.Errorf("parsing options: %w", err))
	}

	if conf == nil {
		os.Exit(exitCode)
	}

	logOutput := os.Stdout
	if conf.LogOutput != "" {
		// #nosec G302 -- Trust the file path that is given in the
		// configuration.
		logOutput, err = os.OpenFile(conf.LogOutput, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o644)
		if err != nil {
			_, _ = fmt.Fprintln(os.Stderr, fmt.Errorf("cannot create a log file: %s", err))

			os.Exit(osutil.ExitCodeArgumentError)
		}

		defer func() { _ = logOutput.Close() }()
	}

	lvl := slog.LevelInfo
	if conf.Verbose {
		lvl = slog.LevelDebug
	}

	l := slogutil.New(&slogutil.Config{
		Output: logOutput,
		Format: slogutil.FormatDefault,
		Level:  lvl,
		// TODO(d.kolyshev): Consider making configurable.
		AddTimestamp: true,
	})

	ctx := context.Background()

	if conf.Pprof {
		runPprof(ctx, l)
	}

	err = runProxy(ctx, l, conf)
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
func runProxy(ctx context.Context, l *slog.Logger, conf *configuration) (err error) {
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
	proxyConf, err := createProxyConfig(ctx, l, conf)
	if err != nil {
		return fmt.Errorf("configuring proxy: %w", err)
	}

	dnsProxy, err := proxy.New(proxyConf)
	if err != nil {
		return fmt.Errorf("creating proxy: %w", err)
	}

	// Start the proxy server.
	err = dnsProxy.Start(ctx)
	if err != nil {
		return fmt.Errorf("starting dnsproxy: %w", err)
	}

	if conf.APIPort > 0 {
		runAPI(ctx, l, conf.APIPort, dnsProxy)
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
// TODO(e.burkov):  Add debugsvc.
func runPprof(ctx context.Context, l *slog.Logger) {
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
		const pprofAddr = "localhost:6060"
		l.InfoContext(ctx, "starting pprof", "addr", pprofAddr)

		srv := &http.Server{
			Addr:        pprofAddr,
			ReadTimeout: 60 * time.Second,
			Handler:     mux,
		}

		err := srv.ListenAndServe()
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			l.ErrorContext(ctx, "pprof failed to listen", "addr", pprofAddr, slogutil.KeyError, err)
		}
	}()
}

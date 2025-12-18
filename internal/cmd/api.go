package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/AdguardTeam/dnsproxy/proxy"
	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/logutil/slogutil"
)

// runAPI starts the HTTP API server.
func runAPI(ctx context.Context, l *slog.Logger, port int, p *proxy.Proxy) {
	mux := http.NewServeMux()
	mux.HandleFunc("/prefetch/stats", handlePrefetchStats(p))

	addr := fmt.Sprintf(":%d", port)
	l.InfoContext(ctx, "starting api server", "addr", addr)

	srv := &http.Server{
		Addr:        addr,
		ReadTimeout: 60 * time.Second,
		Handler:     mux,
	}

	go func() {
		err := srv.ListenAndServe()
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			l.ErrorContext(ctx, "api server failed to listen", "addr", addr, slogutil.KeyError, err)
		}
	}()

	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		if err := srv.Shutdown(shutdownCtx); err != nil {
			l.ErrorContext(ctx, "api server shutdown failed", slogutil.KeyError, err)
		}
	}()
}

// handlePrefetchStats returns a handler that serves prefetch statistics.
func handlePrefetchStats(p *proxy.Proxy) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		stats := p.GetPrefetchStats()
		if stats == nil {
			// Prefetching not enabled or not ready
			http.Error(w, "prefetching not enabled", http.StatusNotFound)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(stats); err != nil {
			http.Error(w, "failed to encode stats", http.StatusInternalServerError)
		}
	}
}

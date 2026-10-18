package main

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"time"

	"f5-redactor/internal/server"
)

// shutdownTimeout is how long running requests get to finish after
// shutdown starts. It stays below the Kubernetes default grace period
// (30s) minus the shutdown delay, so the process exits before it is killed.
const shutdownTimeout = 20 * time.Second

// runServer serves srv on ln until ctx is cancelled (SIGTERM), then shuts
// down gracefully:
//
//  1. /readyz starts failing, so Kubernetes takes the pod out of the
//     Service and sends no new requests;
//  2. after delay (time for that change to reach every load balancer), the
//     listener closes;
//  3. requests that are still streaming get up to shutdownTimeout to finish.
func runServer(ctx context.Context, ln net.Listener, srv *server.Server, logger *slog.Logger, delay time.Duration) error {
	httpSrv := &http.Server{
		Handler: srv.Handler(),
		// Protects against clients that open connections and send headers
		// very slowly. There is no ReadTimeout or WriteTimeout on purpose:
		// a /redact stream can legitimately run for a long time.
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       2 * time.Minute,
		ErrorLog:          slog.NewLogLogger(logger.Handler(), slog.LevelWarn),
	}

	errc := make(chan error, 1)
	go func() { errc <- httpSrv.Serve(ln) }()
	logger.Info("listening", "addr", ln.Addr().String())

	select {
	case err := <-errc:
		return err
	case <-ctx.Done():
	}

	logger.Info("shutting down", "delay", delay.String())
	srv.SetReady(false)
	time.Sleep(delay)

	shutdownCtx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
	defer cancel()
	if err := httpSrv.Shutdown(shutdownCtx); err != nil {
		return err
	}
	if err := <-errc; err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	logger.Info("stopped")
	return nil
}

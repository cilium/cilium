package httpserver

import (
	"context"
	"net"
	"net/http"
	"time"
)

// New returns a new server with sane defaults.
func New(ctx context.Context, handler http.Handler) *http.Server {
	return &http.Server{
		BaseContext:       func(_ net.Listener) context.Context { return ctx },
		Handler:           handler,
		MaxHeaderBytes:    1 << 20,
		IdleTimeout:       90 * time.Second, // matches http.DefaultTransport keep-alive timeout
		ReadHeaderTimeout: 32 * time.Second,
	}
}

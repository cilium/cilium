// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package api

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"runtime/debug"
	"syscall"

	"github.com/cloudflare/cfssl/log"

	"github.com/cilium/cilium/pkg/logging/logfields"
)

// APIPanicHandler recovers from API panics and logs encountered panics
type APIPanicHandler struct {
	Logger *slog.Logger
	Next   http.Handler
}

// ServeHTTP implements the http.Handler interface.
// It recovers from panics of all next handlers and logs them
func (h *APIPanicHandler) ServeHTTP(wr http.ResponseWriter, req *http.Request) {
	defer func() {
		if r := recover(); r != nil {
			scopedLog := h.Logger.With(
				slog.Any("url", req.URL),
				slog.String("method", req.Method),
				slog.String("client", req.RemoteAddr),
			)

			if err, ok := r.(error); ok && errors.Is(err, syscall.EPIPE) {
				scopedLog.Debug("Failed to write API response: client connection closed",
					slog.Any(logfields.Error, err),
				)
				return
			}

			scopedLog.Warn("Cilium API handler panicked",
				slog.Any("panic_message", r),
			)
			if scopedLog.Enabled(context.Background(), slog.LevelDebug) {
				os.Stdout.Write(debug.Stack())
			}
			wr.WriteHeader(http.StatusInternalServerError)
			if _, err := wr.Write([]byte("Internal error occurred, check Cilium logs for details.")); err != nil {
				log.Debug("Failed to write API response",
					slog.Any(logfields.Error, err),
				)
			}
		}
	}()
	h.Next.ServeHTTP(wr, req)
}

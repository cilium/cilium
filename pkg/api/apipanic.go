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
				logfields.URL, req.URL,
				logfields.Method, req.Method,
				logfields.Client, req.RemoteAddr,
			)

			if err, ok := r.(error); ok && errors.Is(err, syscall.EPIPE) {
				scopedLog.Debug("Failed to write API response: client connection closed",
					logfields.Error, err,
				)
				return
			}

			scopedLog.Warn("Cilium API handler panicked",
				logfields.PanicMessage, r,
			)
			if scopedLog.Enabled(context.Background(), slog.LevelDebug) {
				os.Stdout.Write(debug.Stack())
			}
			wr.WriteHeader(http.StatusInternalServerError)
			if _, err := wr.Write([]byte("Internal error occurred, check Cilium logs for details.")); err != nil {
				scopedLog.Debug("Failed to write API response",
					logfields.Error, err,
				)
			}
		}
	}()
	h.Next.ServeHTTP(wr, req)
}

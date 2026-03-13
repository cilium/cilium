// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package logging

import (
	"context"
	"errors"
	"log/slog"
)

// NewMultiSlogHandler creates a slog.Handler that supports multiple
// underlying handlers, such as to output text and json.
func NewMultiSlogHandler(handler slog.Handler) *multiSlogHandler {
	return &multiSlogHandler{
		handlers: []slog.Handler{handler},
	}
}

type multiSlogHandler struct {
	handlers []slog.Handler
}

func (i *multiSlogHandler) Enabled(ctx context.Context, level slog.Level) bool {
	for _, h := range i.handlers {
		if h.Enabled(ctx, level) {
			return true
		}
	}
	return false
}

func (i *multiSlogHandler) Handle(ctx context.Context, record slog.Record) error {
	var errs error
	for _, h := range i.handlers {
		// MultiSlogHandler will process all records that have higher level than the
		// minimum level across all registered handlers.
		// Only call individual handlers if they enable the provided record level.
		if h.Enabled(ctx, record.Level) {
			err := h.Handle(ctx, record)
			if err != nil {
				errs = errors.Join(errs, err)
			}
		}
	}
	return errs
}

func (i *multiSlogHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	newHandlers := make([]slog.Handler, 0, len(i.handlers))
	for _, h := range i.handlers {
		newHandlers = append(newHandlers, h.WithAttrs(attrs))
	}
	return &multiSlogHandler{
		handlers: newHandlers,
	}
}

func (i *multiSlogHandler) WithGroup(name string) slog.Handler {
	newHandlers := make([]slog.Handler, 0, len(i.handlers))
	for _, h := range i.handlers {
		newHandlers = append(newHandlers, h.WithGroup(name))
	}
	return &multiSlogHandler{
		handlers: newHandlers,
	}
}

func (i *multiSlogHandler) AddHandlers(handlers ...slog.Handler) *multiSlogHandler {
	return &multiSlogHandler{
		handlers: append(i.handlers, handlers...),
	}
}

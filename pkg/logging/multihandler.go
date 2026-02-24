// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package logging

import (
	"context"
	"errors"
	"log/slog"

	"github.com/cilium/cilium/pkg/lock"
)

// NewMultiSlogHandler creates a slog.Handler that supports multiple
// underlying handlers, such as to output text and json.
func NewMultiSlogHandler(handler slog.Handler) *multiSlogHandler {
	return &multiSlogHandler{
		mu:       lock.RWMutex{},
		handlers: []slog.Handler{handler},
	}
}

type multiSlogHandler struct {
	mu       lock.RWMutex
	handlers []slog.Handler
}

func (i *multiSlogHandler) Enabled(ctx context.Context, level slog.Level) bool {
	i.mu.RLock()
	defer i.mu.RUnlock()
	for _, h := range i.handlers {
		if h.Enabled(ctx, level) {
			return true
		}
	}
	return false
}

func (i *multiSlogHandler) Handle(ctx context.Context, record slog.Record) error {
	i.mu.RLock()
	defer i.mu.RUnlock()
	var errs error
	for _, h := range i.handlers {
		err := h.Handle(ctx, record)
		if err != nil {
			errs = errors.Join(errs, err)
		}
	}
	return errs
}

func (i *multiSlogHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	i.mu.RLock()
	defer i.mu.RUnlock()
	newHandlers := make([]slog.Handler, 0, len(i.handlers))
	for _, h := range i.handlers {
		newHandlers = append(newHandlers, h.WithAttrs(attrs))
	}
	return &multiSlogHandler{
		handlers: newHandlers,
	}
}

func (i *multiSlogHandler) WithGroup(name string) slog.Handler {
	i.mu.RLock()
	defer i.mu.RUnlock()
	newHandlers := make([]slog.Handler, 0, len(i.handlers))
	for _, h := range i.handlers {
		newHandlers = append(newHandlers, h.WithGroup(name))
	}
	return &multiSlogHandler{
		handlers: newHandlers,
	}
}

func (i *multiSlogHandler) AddHandlers(handlers ...slog.Handler) {
	i.mu.Lock()
	defer i.mu.Unlock()
	i.handlers = append(i.handlers, handlers...)
}

func (i *multiSlogHandler) SetHandler(handler slog.Handler) {
	i.mu.Lock()
	defer i.mu.Unlock()
	i.handlers = []slog.Handler{handler}
}

// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package logging

import (
	"context"
	"log/slog"

	"github.com/cilium/cilium/pkg/lock"
)

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
		return h.Enabled(ctx, level)
	}
	return false
}

func (i *multiSlogHandler) Handle(ctx context.Context, record slog.Record) error {
	i.mu.RLock()
	defer i.mu.RUnlock()
	for _, h := range i.handlers {
		err := h.Handle(ctx, record)
		if err != nil {
			return err
		}
	}
	return nil
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

func (i *multiSlogHandler) AddHooks(handlers ...slog.Handler) {
	i.mu.Lock()
	defer i.mu.Unlock()
	for _, h := range handlers {
		i.handlers = append(i.handlers, h)
	}
}

func (i *multiSlogHandler) SetHandler(handler slog.Handler) {
	i.mu.Lock()
	defer i.mu.Unlock()
	i.handlers = []slog.Handler{handler}
}

// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package logging

import (
	"context"
	"log/slog"
	"os"
	"strings"
	lock "sync"
	"time"

	"github.com/cilium/cilium/pkg/logging/logfields"
)

// logrErrorKey is the key used by the logr library for the error parameter.
const logrErrorKey = "err"

// SlogNopHandler discards all logs.
var SlogNopHandler slog.Handler = nopHandler{}

type nopHandler struct{}

func (nopHandler) Enabled(context.Context, slog.Level) bool  { return false }
func (nopHandler) Handle(context.Context, slog.Record) error { return nil }
func (n nopHandler) WithAttrs([]slog.Attr) slog.Handler      { return n }
func (n nopHandler) WithGroup(string) slog.Handler           { return n }

var slogHandlerOpts = &slog.HandlerOptions{
	AddSource:   false,
	Level:       slogLeveler,
	ReplaceAttr: replaceAttrFn,
}

var slogLeveler = func() *slog.LevelVar {
	var levelVar slog.LevelVar
	levelVar.Set(slog.LevelInfo)
	return &levelVar
}()

func newMultiSlogHandler(handler slog.Handler) *multiSlogHandler {
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

var defaultMultiSlogHandler = newMultiSlogHandler(slog.NewTextHandler(
	os.Stderr,
	slogHandlerOpts,
))

// Default slog logger. Will be overwritten once initializeSlog is called.
var DefaultSlogLogger = slog.New(defaultMultiSlogHandler)

// Approximates the logrus output via slog for job groups during the transition
// phase.
func initializeSlog(logOpts LogOptions, useStdout bool) {
	opts := *slogHandlerOpts
	opts.Level = logOpts.GetLogLevel()

	logFormat := logOpts.GetLogFormat()
	switch logFormat {
	case LogFormatJSON, LogFormatText:
		opts.ReplaceAttr = replaceAttrFnWithoutTimestamp
	case LogFormatJSONTimestamp, LogFormatTextTimestamp:
		opts.ReplaceAttr = replaceAttrFn
	}

	writer := os.Stderr
	if useStdout {
		writer = os.Stdout
	}

	switch logFormat {
	case LogFormatJSON, LogFormatJSONTimestamp:
		defaultMultiSlogHandler.SetHandler(slog.NewJSONHandler(
			writer,
			&opts,
		))
	case LogFormatText, LogFormatTextTimestamp:
		defaultMultiSlogHandler.SetHandler(slog.NewTextHandler(
			writer,
			&opts,
		))
	}
}

func ReplaceAttrFn(groups []string, a slog.Attr) slog.Attr {
	return replaceAttrFn(groups, a)
}

func replaceAttrFn(groups []string, a slog.Attr) slog.Attr {
	switch a.Key {
	case slog.TimeKey:
		// Adjust to timestamp format that logrus uses; except that we can't
		// force slog to quote the value like logrus does...
		return slog.String(slog.TimeKey, a.Value.Time().Format(time.RFC3339Nano))
	case slog.LevelKey:
		// Lower-case the log level
		return slog.Attr{
			Key:   a.Key,
			Value: slog.StringValue(strings.ToLower(a.Value.String())),
		}
	case logrErrorKey:
		// Uniform the attribute identifying the error
		return slog.Attr{
			Key:   logfields.Error,
			Value: a.Value,
		}
	}
	return a
}

func replaceAttrFnWithoutTimestamp(groups []string, a slog.Attr) slog.Attr {
	switch a.Key {
	case slog.TimeKey:
		// Drop timestamps
		return slog.Attr{}
	default:
		return replaceAttrFn(groups, a)
	}
}

type FieldLogger interface {
	Handler() slog.Handler
	With(args ...any) *slog.Logger
	WithGroup(name string) *slog.Logger
	Enabled(ctx context.Context, level slog.Level) bool
	Log(ctx context.Context, level slog.Level, msg string, args ...any)
	LogAttrs(ctx context.Context, level slog.Level, msg string, attrs ...slog.Attr)
	Debug(msg string, args ...any)
	DebugContext(ctx context.Context, msg string, args ...any)
	Info(msg string, args ...any)
	InfoContext(ctx context.Context, msg string, args ...any)
	Warn(msg string, args ...any)
	WarnContext(ctx context.Context, msg string, args ...any)
	Error(msg string, args ...any)
	ErrorContext(ctx context.Context, msg string, args ...any)
}

func Fatal(logger FieldLogger, msg string, args ...any) {
	logger.Error(msg, args...)
	os.Exit(-1)
}

func Panic(logger FieldLogger, msg string, args ...any) {
	logger.Error(msg, args...)
	panic(msg)
}

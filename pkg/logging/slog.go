// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package logging

import (
	"context"
	"log/slog"
	"os"
	"strings"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/cilium/cilium/pkg/logging/logfields"
)

// logrErrorKey is the key used by the logr library for the error parameter.
const logrErrorKey = "err"

var slogHandlerOpts = &slog.HandlerOptions{
	AddSource:   false,
	Level:       slog.LevelInfo,
	ReplaceAttr: ReplaceAttrFnWithoutTimestamp,
}

// Default slog logger. Will be overwritten once initializeSlog is called.
var DefaultSlogLogger *slog.Logger = slog.New(slog.NewTextHandler(
	os.Stderr,
	slogHandlerOpts,
))

func slogLevel(l logrus.Level) slog.Level {
	switch l {
	case logrus.DebugLevel, logrus.TraceLevel:
		return slog.LevelDebug
	case logrus.InfoLevel:
		return slog.LevelInfo
	case logrus.WarnLevel:
		return slog.LevelWarn
	case logrus.ErrorLevel, logrus.PanicLevel, logrus.FatalLevel:
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}

// Approximates the logrus output via slog for job groups during the transition
// phase.
func initializeSlog(logOpts LogOptions, loggers []string) {
	opts := *slogHandlerOpts
	opts.Level = slogLevel(logOpts.GetLogLevel())
	if opts.Level == slog.LevelDebug {
		opts.AddSource = true
	}

	logFormat := logOpts.GetLogFormat()
	switch logFormat {
	case LogFormatJSON, LogFormatText:
		opts.ReplaceAttr = ReplaceAttrFnWithoutTimestamp
	case LogFormatJSONTimestamp, LogFormatTextTimestamp:
		opts.ReplaceAttr = replaceAttrFn
	}

	writer := os.Stderr
	switch logOpts[WriterOpt] {
	case StdErrOpt:
	default:
		if len(loggers) == 0 {
			writer = os.Stdout
		}
	}

	switch logFormat {
	case LogFormatJSON, LogFormatJSONTimestamp:
		DefaultSlogLogger = slog.New(slog.NewJSONHandler(
			writer,
			&opts,
		))
	case LogFormatText, LogFormatTextTimestamp:
		DefaultSlogLogger = slog.New(slog.NewTextHandler(
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
		return slog.String(slog.TimeKey, a.Value.Time().Format(time.RFC3339))
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

func ReplaceAttrFnWithoutTimestamp(groups []string, a slog.Attr) slog.Attr {
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

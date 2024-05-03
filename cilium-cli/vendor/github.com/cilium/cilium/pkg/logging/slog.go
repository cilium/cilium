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
)

// SlogNopHandler discards all logs.
var SlogNopHandler slog.Handler = nopHandler{}

type nopHandler struct{}

func (nopHandler) Enabled(context.Context, slog.Level) bool  { return false }
func (nopHandler) Handle(context.Context, slog.Record) error { return nil }
func (n nopHandler) WithAttrs([]slog.Attr) slog.Handler      { return n }
func (n nopHandler) WithGroup(string) slog.Handler           { return n }

var slogHandlerOpts = &slog.HandlerOptions{
	AddSource:   false,
	Level:       slog.LevelInfo,
	ReplaceAttr: replaceLevelAndDropTime,
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
func initializeSlog(logOpts LogOptions, useStdout bool) {
	opts := *slogHandlerOpts
	opts.Level = slogLevel(logOpts.GetLogLevel())

	logFormat := logOpts.GetLogFormat()
	switch logFormat {
	case LogFormatJSON, LogFormatText:
		opts.ReplaceAttr = replaceLevelAndDropTime
	case LogFormatJSONTimestamp, LogFormatTextTimestamp:
		opts.ReplaceAttr = replaceLevel
	}

	writer := os.Stderr
	if useStdout {
		writer = os.Stdout
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

func replaceLevel(groups []string, a slog.Attr) slog.Attr {
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
	}
	return a
}

func replaceLevelAndDropTime(groups []string, a slog.Attr) slog.Attr {
	switch a.Key {
	case slog.TimeKey:
		// Drop timestamps
		return slog.Attr{}
	case slog.LevelKey:
		// Lower-case the log level
		return slog.Attr{
			Key:   a.Key,
			Value: slog.StringValue(strings.ToLower(a.Value.String())),
		}
	}
	return a
}

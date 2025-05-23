// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build !windows

package logging

import (
	"context"
	"fmt"
	"log/slog"
	"log/syslog"
	"strings"
	"time"
)

// SyslogHook to send logs via syslog.
type SyslogHook struct {
	Writer        *syslog.Writer
	SyslogNetwork string
	SyslogRaddr   string
	handler       slog.Handler
}

func (hook *SyslogHook) Enabled(ctx context.Context, level slog.Level) bool {
	return hook.handler.Enabled(ctx, level)
}

func (hook *SyslogHook) Handle(ctx context.Context, r slog.Record) error {
	timestamp := r.Time.Format(time.RFC3339)

	var logStr strings.Builder
	logStr.WriteString(fmt.Sprintf("[%s] [%s] %s", timestamp, r.Level.String(), r.Message))

	r.Attrs(func(a slog.Attr) bool {
		logStr.WriteString(fmt.Sprintf(" %s=%v", a.Key, a.Value))
		return true
	})

	str := logStr.String()
	switch r.Level {
	case LevelPanic:
		return hook.Writer.Crit(str)
	case LevelFatal:
		return hook.Writer.Crit(str)
	case slog.LevelError:
		return hook.Writer.Err(str)
	case slog.LevelWarn:
		return hook.Writer.Warning(str)
	case slog.LevelInfo:
		return hook.Writer.Info(str)
	case slog.LevelDebug:
		return hook.Writer.Debug(str)
	default:
		return hook.Writer.Info(str)
	}
}

func (hook *SyslogHook) WithAttrs(attrs []slog.Attr) slog.Handler {
	return hook.handler.WithAttrs(attrs)
}

func (hook *SyslogHook) WithGroup(name string) slog.Handler {
	return hook.handler.WithGroup(name)
}

func NewSyslogHook(network, raddr string, priority syslog.Priority, tag string, slogLevel slog.Level) (*SyslogHook, error) {
	w, err := syslog.Dial(network, raddr, priority, tag)
	if err != nil {
		return nil, err
	}
	return &SyslogHook{
		Writer:        w,
		SyslogNetwork: network,
		SyslogRaddr:   raddr,
		handler: slog.NewTextHandler(w, &slog.HandlerOptions{
			AddSource: false,
			Level:     slogLevel,
		}),
	}, nil
}

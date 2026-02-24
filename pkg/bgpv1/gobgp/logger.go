// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package gobgp

import (
	"log/slog"

	gobgpLog "github.com/osrg/gobgp/v3/pkg/log"

	"github.com/cilium/cilium/pkg/bgpv1/types"
	"github.com/cilium/cilium/pkg/logging"
)

// implement github.com/osrg/gobgp/v3/pkg/log/Logger interface
type ServerLogger struct {
	l         *slog.Logger
	asn       uint32
	component string
	subsys    string
}

type LogParams struct {
	AS        uint32
	Component string
	SubSys    string
}

func NewServerLogger(l *slog.Logger, params LogParams) *ServerLogger {
	return &ServerLogger{
		l:         l,
		asn:       params.AS,
		component: params.Component,
		subsys:    params.SubSys,
	}
}

func (l *ServerLogger) Panic(msg string, fields gobgpLog.Fields) {
	logAttrs := make([]any, 0, len(fields)+3)
	for k, v := range fields {
		logAttrs = append(
			logAttrs,
			k, v,
		)
	}
	logAttrs = append(
		logAttrs,
		types.LocalASNLogField, l.asn,
		types.ComponentLogField, l.component,
		types.SubsysLogField, l.subsys,
	)
	logging.Panic(l.l, msg, logAttrs...)
}

func (l *ServerLogger) Fatal(msg string, fields gobgpLog.Fields) {
	logAttrs := make([]any, 0, len(fields)+3)
	for k, v := range fields {
		logAttrs = append(
			logAttrs,
			k, v,
		)
	}
	logAttrs = append(
		logAttrs,
		types.LocalASNLogField, l.asn,
		types.ComponentLogField, l.component,
		types.SubsysLogField, l.subsys,
	)
	logging.Fatal(l.l, msg, logAttrs...)
}

func (l *ServerLogger) Error(msg string, fields gobgpLog.Fields) {
	logAttrs := make([]any, 0, len(fields)+3)
	for k, v := range fields {
		logAttrs = append(
			logAttrs,
			k, v,
		)
	}
	logAttrs = append(
		logAttrs,
		types.LocalASNLogField, l.asn,
		types.ComponentLogField, l.component,
		types.SubsysLogField, l.subsys,
	)
	l.l.Error(msg, logAttrs...)
}

func (l *ServerLogger) Warn(msg string, fields gobgpLog.Fields) {
	logAttrs := make([]any, 0, len(fields)+3)
	for k, v := range fields {
		logAttrs = append(
			logAttrs,
			k, v,
		)
	}
	logAttrs = append(
		logAttrs,
		types.LocalASNLogField, l.asn,
		types.ComponentLogField, l.component,
		types.SubsysLogField, l.subsys,
	)
	l.l.Warn(msg, logAttrs...)
}

func (l *ServerLogger) Info(msg string, fields gobgpLog.Fields) {
	logAttrs := make([]any, 0, len(fields)+3)
	for k, v := range fields {
		logAttrs = append(
			logAttrs,
			k, v,
		)
	}
	logAttrs = append(
		logAttrs,
		types.LocalASNLogField, l.asn,
		types.ComponentLogField, l.component,
		types.SubsysLogField, l.subsys,
	)
	l.l.Info(msg, logAttrs...)
}

func (l *ServerLogger) Debug(msg string, fields gobgpLog.Fields) {
	logAttrs := make([]any, 0, len(fields)+3)
	for k, v := range fields {
		logAttrs = append(
			logAttrs,
			k, v,
		)
	}
	logAttrs = append(
		logAttrs,
		types.LocalASNLogField, l.asn,
		types.ComponentLogField, l.component,
		types.SubsysLogField, l.subsys,
	)
	l.l.Debug(msg, logAttrs...)
}

func (l *ServerLogger) SetLevel(gobgpLog.LogLevel) {
}

func (l *ServerLogger) GetLevel() gobgpLog.LogLevel {
	switch logging.GetSlogLevel(l.l) {
	case slog.LevelDebug:
		return gobgpLog.DebugLevel
	case slog.LevelInfo:
		return gobgpLog.InfoLevel
	case slog.LevelWarn:
		return gobgpLog.WarnLevel
	case slog.LevelError:
		return gobgpLog.ErrorLevel
	case logging.LevelPanic:
		return gobgpLog.PanicLevel
	case logging.LevelFatal:
		return gobgpLog.FatalLevel
	default:
		return gobgpLog.InfoLevel
	}
}

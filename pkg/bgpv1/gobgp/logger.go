// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package gobgp

import (
	gobgpLog "github.com/osrg/gobgp/v3/pkg/log"

	"github.com/sirupsen/logrus"
)

// implement github.com/osrg/gobgp/v3/pkg/log/Logger interface
type ServerLogger struct {
	l         *logrus.Logger
	asn       uint32
	component string
	subsys    string
}

type LogParams struct {
	AS        uint32
	Component string
	SubSys    string
}

func NewServerLogger(l *logrus.Logger, params LogParams) *ServerLogger {
	return &ServerLogger{
		l:         l,
		asn:       params.AS,
		component: params.Component,
		subsys:    params.SubSys,
	}
}

func (l *ServerLogger) Panic(msg string, fields gobgpLog.Fields) {
	fields["asn"] = l.asn
	fields["component"] = l.component
	fields["subsys"] = l.subsys
	l.l.WithFields(logrus.Fields(fields)).Panic(msg)
}

func (l *ServerLogger) Fatal(msg string, fields gobgpLog.Fields) {
	fields["asn"] = l.asn
	fields["component"] = l.component
	fields["subsys"] = l.subsys
	l.l.WithFields(logrus.Fields(fields)).Fatal(msg)
}

func (l *ServerLogger) Error(msg string, fields gobgpLog.Fields) {
	fields["asn"] = l.asn
	fields["component"] = l.component
	fields["subsys"] = l.subsys
	l.l.WithFields(logrus.Fields(fields)).Error(msg)
}

func (l *ServerLogger) Warn(msg string, fields gobgpLog.Fields) {
	fields["asn"] = l.asn
	fields["component"] = l.component
	fields["subsys"] = l.subsys
	l.l.WithFields(logrus.Fields(fields)).Warn(msg)
}

func (l *ServerLogger) Info(msg string, fields gobgpLog.Fields) {
	fields["asn"] = l.asn
	fields["component"] = l.component
	fields["subsys"] = l.subsys
	l.l.WithFields(logrus.Fields(fields)).Info(msg)
}

func (l *ServerLogger) Debug(msg string, fields gobgpLog.Fields) {
	fields["asn"] = l.asn
	fields["component"] = l.component
	fields["subsys"] = l.subsys
	l.l.WithFields(logrus.Fields(fields)).Debug(msg)
}

func (l *ServerLogger) SetLevel(level gobgpLog.LogLevel) {
	l.l.SetLevel(logrus.Level(level))
}

func (l *ServerLogger) GetLevel() gobgpLog.LogLevel {
	return gobgpLog.LogLevel(l.l.GetLevel())
}

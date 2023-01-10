// Copyright (C) 2021 Nippon Telegraph and Telephone Corporation.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//    http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
// implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package log

import (
	"github.com/sirupsen/logrus"
)

type LogLevel uint32

const (
	PanicLevel LogLevel = iota
	FatalLevel
	ErrorLevel
	WarnLevel
	InfoLevel
	DebugLevel
	TraceLevel
)

type Fields map[string]interface{}

type Logger interface {
	Panic(msg string, fields Fields)
	Fatal(msg string, fields Fields)
	Error(msg string, fields Fields)
	Warn(msg string, fields Fields)
	Info(msg string, fields Fields)
	Debug(msg string, fields Fields)
	SetLevel(level LogLevel)
	GetLevel() LogLevel
}

type DefaultLogger struct {
	logger *logrus.Logger
}

func (l *DefaultLogger) Panic(msg string, fields Fields) {
	l.logger.WithFields(logrus.Fields(fields)).Panic(msg)
}

func (l *DefaultLogger) Fatal(msg string, fields Fields) {
	l.logger.WithFields(logrus.Fields(fields)).Fatal(msg)
}

func (l *DefaultLogger) Error(msg string, fields Fields) {
	l.logger.WithFields(logrus.Fields(fields)).Error(msg)
}

func (l *DefaultLogger) Warn(msg string, fields Fields) {
	l.logger.WithFields(logrus.Fields(fields)).Warn(msg)
}

func (l *DefaultLogger) Info(msg string, fields Fields) {
	l.logger.WithFields(logrus.Fields(fields)).Info(msg)
}

func (l *DefaultLogger) Debug(msg string, fields Fields) {
	l.logger.WithFields(logrus.Fields(fields)).Debug(msg)
}

func (l *DefaultLogger) SetLevel(level LogLevel) {
	l.logger.SetLevel(logrus.Level(level))
}

func (l *DefaultLogger) GetLevel() LogLevel {
	return LogLevel(l.logger.GetLevel())
}

func NewDefaultLogger() *DefaultLogger {
	return &DefaultLogger{
		logger: logrus.New(),
	}
}

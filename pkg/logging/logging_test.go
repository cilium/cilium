// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package logging

import (
	"reflect"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
)

func TestGetLogLevel(t *testing.T) {
	opts := LogOptions{}

	// case doesn't matter with log options
	opts[LevelOpt] = "DeBuG"
	require.Equal(t, logrus.DebugLevel, opts.GetLogLevel())

	opts[LevelOpt] = "Invalid"
	require.Equal(t, DefaultLogLevel, opts.GetLogLevel())
}

func TestGetLogFormat(t *testing.T) {
	opts := LogOptions{}

	// case doesn't matter with log options
	opts[FormatOpt] = "JsOn"
	require.Equal(t, LogFormatJSON, opts.GetLogFormat())

	opts[FormatOpt] = "Invalid"
	require.Equal(t, DefaultLogFormatTimestamp, opts.GetLogFormat())

	opts[FormatOpt] = "JSON-TS"
	require.Equal(t, LogFormatJSONTimestamp, opts.GetLogFormat())
}

func TestSetLogLevel(t *testing.T) {
	oldLevel := DefaultLogger.GetLevel()
	defer DefaultLogger.SetLevel(oldLevel)

	SetLogLevel(logrus.TraceLevel)
	require.Equal(t, logrus.TraceLevel, DefaultLogger.GetLevel())
}

func TestSetDefaultLogLevel(t *testing.T) {
	oldLevel := DefaultLogger.GetLevel()
	defer DefaultLogger.SetLevel(oldLevel)

	SetDefaultLogLevel()
	require.Equal(t, DefaultLogLevel, DefaultLogger.GetLevel())
}

func TestSetLogFormat(t *testing.T) {
	oldFormatter := DefaultLogger.Formatter
	defer DefaultLogger.SetFormatter(oldFormatter)

	SetLogFormat(LogFormatJSON)
	require.Equal(t, "*logrus.JSONFormatter", reflect.TypeOf(DefaultLogger.Formatter).String())

	SetLogFormat(LogFormatJSONTimestamp)
	require.Equal(t, "*logrus.JSONFormatter", reflect.TypeOf(DefaultLogger.Formatter).String())
	require.False(t, DefaultLogger.Formatter.(*logrus.JSONFormatter).DisableTimestamp)
	require.Equal(t, time.RFC3339Nano, DefaultLogger.Formatter.(*logrus.JSONFormatter).TimestampFormat)
}

func TestSetDefaultLogFormat(t *testing.T) {
	oldFormatter := DefaultLogger.Formatter
	defer DefaultLogger.SetFormatter(oldFormatter)

	SetDefaultLogFormat()
	require.Equal(t, "*logrus.TextFormatter", reflect.TypeOf(DefaultLogger.Formatter).String())
}

func TestSetupLogging(t *testing.T) {
	oldLevel := DefaultLogger.GetLevel()
	defer DefaultLogger.SetLevel(oldLevel)

	// Validates that we configure the DefaultLogger correctly
	logOpts := LogOptions{
		"format": "json",
		"level":  "error",
	}

	SetupLogging([]string{}, logOpts, "", false)
	require.Equal(t, logrus.ErrorLevel, DefaultLogger.GetLevel())
	require.Equal(t, "*logrus.JSONFormatter", reflect.TypeOf(DefaultLogger.Formatter).String())

	// Validate that the 'debug' flag/arg overrides the logOptions
	SetupLogging([]string{}, logOpts, "", true)
	require.Equal(t, logrus.DebugLevel, DefaultLogger.GetLevel())
}

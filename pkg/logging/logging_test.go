// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package logging

import (
	"bytes"
	"flag"
	"reflect"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"k8s.io/klog/v2"
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
	require.Equal(t, LogFormatJSON, opts.GetLogFormat()) //nolint: testifylint

	opts[FormatOpt] = "Invalid"
	require.Equal(t, DefaultLogFormatTimestamp, opts.GetLogFormat())

	opts[FormatOpt] = "JSON-TS"
	require.Equal(t, LogFormatJSONTimestamp, opts.GetLogFormat()) //nolint: testifylint
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

func TestSetupLogging2(t *testing.T) {
	out := &bytes.Buffer{}
	logger := initializeDefaultLogger()
	logger.SetOutput(out)
	log := logger.WithField("subsys", "logging-test")
	overrides := []logLevelOverride{
		{
			matcher:     regexp.MustCompile("^please override (this|foo)!$"),
			targetLevel: logrus.InfoLevel,
		},
	}
	errWriter, err := severityOverrideWriter(logrus.ErrorLevel, log, overrides)
	assert.NoError(t, err)

	klogFlags := flag.NewFlagSet("cilium", flag.ExitOnError)
	klog.InitFlags(klogFlags)
	klogFlags.Set("logtostderr", "false")
	klogFlags.Set("skip_headers", "true")
	klogFlags.Set("one_output", "true")

	klog.SetOutputBySeverity("ERROR", errWriter)
	klog.SetOutputBySeverity("INFO", log.WriterLevel(logrus.InfoLevel))
	klog.Error("please do not override this!")
	klog.Error("please override this!")
	klog.Error("please override foo!")
	klog.Error("final log")
	klog.Flush()
	var lines []string
	assert.EventuallyWithT(t, func(collect *assert.CollectT) {
		logout := strings.Trim(out.String(), "\n")
		lines = strings.Split(logout, "\n")
		assert.Len(collect, lines, 4)
	}, time.Second, time.Millisecond*50)
	for _, line := range lines {
		if strings.Contains(line, "please override this!") || strings.Contains(line, "please override foo!") {
			assert.Contains(t, line, "level=info")
		} else {
			assert.Contains(t, line, "level=error")
		}
	}

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

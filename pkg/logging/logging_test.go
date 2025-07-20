// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package logging

import (
	"bytes"
	"flag"
	"log/slog"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"k8s.io/klog/v2"

	"github.com/cilium/cilium/pkg/logging/logfields"
)

func TestGetLogLevel(t *testing.T) {
	opts := LogOptions{}

	// case doesn't matter with log options
	opts[LevelOpt] = "DeBuG"
	require.Equal(t, slog.LevelDebug, opts.GetLogLevel())

	opts[LevelOpt] = "Invalid"
	require.Equal(t, DefaultLogLevel, opts.GetLogLevel())
}

func TestGetLogFormat(t *testing.T) {
	opts := LogOptions{}

	// case doesn't matter with log options
	opts[FormatOpt] = "JsOn"
	require.Equal(t, LogFormatJSON, opts.GetLogFormat()) // nolint: testifylint

	opts[FormatOpt] = "Invalid"
	require.Equal(t, DefaultLogFormatTimestamp, opts.GetLogFormat())

	opts[FormatOpt] = "JSON-TS"
	require.Equal(t, LogFormatJSONTimestamp, opts.GetLogFormat()) // nolint: testifylint
}

func TestSetLogLevel(t *testing.T) {
	oldLevel := GetSlogLevel(DefaultSlogLogger)
	defer SetLogLevel(oldLevel)

	SetLogLevel(slog.LevelDebug)
	require.Equal(t, slog.LevelDebug, GetSlogLevel(DefaultSlogLogger))
}

func TestSetDefaultLogLevel(t *testing.T) {
	oldLevel := GetSlogLevel(DefaultSlogLogger)
	defer SetLogLevel(oldLevel)

	SetDefaultLogLevel()
	require.Equal(t, DefaultLogLevel, GetSlogLevel(DefaultSlogLogger))
}

func TestSetupLogging2(t *testing.T) {
	var out bytes.Buffer
	logger := slog.New(
		slog.NewTextHandler(&out,
			&slog.HandlerOptions{
				ReplaceAttr: ReplaceAttrFnWithoutTimestamp,
			},
		),
	)
	log := logger.With(logfields.LogSubsys, "logging-test")
	overrides := []logLevelOverride{
		{
			matcher:     regexp.MustCompile("^please override (this|foo)!$"),
			targetLevel: slog.LevelInfo,
		},
	}
	errWriter, err := severityOverrideWriter(slog.LevelError, log, overrides)
	assert.NoError(t, err)

	klogFlags := flag.NewFlagSet("cilium", flag.ExitOnError)
	klog.InitFlags(klogFlags)
	klogFlags.Set("logtostderr", "false")
	klogFlags.Set("skip_headers", "true")
	klogFlags.Set("one_output", "true")

	klog.SetOutputBySeverity("ERROR", errWriter)
	klog.SetOutputBySeverity("INFO", &out)
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
	oldLevel := GetSlogLevel(DefaultSlogLogger)
	defer SetLogLevel(oldLevel)

	// Validates that we configure the DefaultSlogLogger correctly
	logOpts := LogOptions{
		"format": "json",
		"level":  "error",
	}

	err := SetupLogging([]string{}, logOpts, "", false)
	assert.NoError(t, err)
	require.Equal(t, slog.LevelError, GetSlogLevel(DefaultSlogLogger))

	// Validate that the 'debug' flag/arg overrides the logOptions
	err = SetupLogging([]string{}, logOpts, "", true)
	assert.NoError(t, err)
	require.Equal(t, slog.LevelDebug, GetSlogLevel(DefaultSlogLogger))
}

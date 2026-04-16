// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package logging

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log/slog"
	"regexp"
	"strings"
	"testing"

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

func TestKlogBridgeLevelOverrides(t *testing.T) {
	var out bytes.Buffer
	logger := slog.New(
		slog.NewJSONHandler(&out,
			&slog.HandlerOptions{
				ReplaceAttr: ReplaceAttrFnWithoutTimestamp,
			},
		),
	)
	log := logger.With(logfields.LogSubsys, "klog")

	overrides := []logLevelOverride{
		{
			matcher:     regexp.MustCompile("^please override (this|foo)!$"),
			targetLevel: slog.LevelInfo,
		},
	}
	handler := &klogOverrideHandler{
		inner:     log.Handler(),
		overrides: overrides,
	}
	klog.SetSlogLogger(slog.New(handler))

	klog.ErrorS(nil, "please do not override this!")
	klog.ErrorS(nil, "please override this!")
	klog.ErrorS(nil, "please override foo!")
	klog.ErrorS(fmt.Errorf("something failed"), "final log", "key", "value")
	klog.Flush()

	logout := strings.Trim(out.String(), "\n")
	lines := strings.Split(logout, "\n")
	require.Len(t, lines, 4)

	for _, line := range lines {
		var entry map[string]any
		require.NoError(t, json.Unmarshal([]byte(line), &entry))

		msg, _ := entry["msg"].(string)
		level, _ := entry["level"].(string)

		// Verify subsys is propagated
		assert.Equal(t, "klog", entry[logfields.LogSubsys])

		switch {
		case msg == "please override this!" || msg == "please override foo!":
			assert.Equal(t, "info", level, "overridden messages should be info, got line: %s", line)
		case msg == "please do not override this!":
			assert.Equal(t, "error", level, "non-overridden error should stay error, got line: %s", line)
		case msg == "final log":
			assert.Equal(t, "error", level, "non-overridden error should stay error, got line: %s", line)
			assert.Equal(t, "value", entry["key"], "structured key-value pairs should be preserved")
			assert.Equal(t, "something failed", entry[logfields.Error], "error should be preserved as a structured field")
		}
	}
}

func TestKlogBridgeStructuredFields(t *testing.T) {
	var out bytes.Buffer
	logger := slog.New(
		slog.NewJSONHandler(&out,
			&slog.HandlerOptions{
				ReplaceAttr: ReplaceAttrFnWithoutTimestamp,
			},
		),
	)

	log := logger.With(logfields.LogSubsys, "klog")
	handler := &klogOverrideHandler{
		inner:     log.Handler(),
		overrides: nil,
	}
	klog.SetSlogLogger(slog.New(handler))

	klog.InfoS("test message", "pod", "my-pod", "namespace", "default")
	klog.Flush()

	logout := strings.Trim(out.String(), "\n")
	var entry map[string]any
	require.NoError(t, json.Unmarshal([]byte(logout), &entry))

	assert.Equal(t, "test message", entry["msg"])
	assert.Equal(t, "my-pod", entry["pod"])
	assert.Equal(t, "default", entry["namespace"])
	assert.Equal(t, "klog", entry[logfields.LogSubsys])
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

// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package dnsproxy

import (
	"context"
	"log/slog"
	"runtime"
	"slices"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

const requestLoggerTestIdentity = identity.NumericIdentity(1234)

type requestLoggerTestRecord struct {
	message string
	attrs   map[string]any
	pc      uintptr
}

type requestLoggerTestState struct {
	records       []requestLoggerTestRecord
	withAttrCalls [][]slog.Attr
}

func (s *requestLoggerTestState) find(t *testing.T, message string) requestLoggerTestRecord {
	t.Helper()
	for _, record := range s.records {
		if record.message == message {
			return record
		}
	}
	t.Fatalf("log message %q not found in %#v", message, s.records)
	return requestLoggerTestRecord{}
}

type requestLoggerTestHandler struct {
	state        *requestLoggerTestState
	attrs        []slog.Attr
	minLevel     slog.Level
	debugAttrKey string
}

func (h *requestLoggerTestHandler) Enabled(_ context.Context, level slog.Level) bool {
	if level >= h.minLevel {
		return true
	}
	return level == slog.LevelDebug && slices.ContainsFunc(h.attrs, func(attr slog.Attr) bool {
		return attr.Key == h.debugAttrKey
	})
}

func (h *requestLoggerTestHandler) Handle(_ context.Context, record slog.Record) error {
	attrs := make(map[string]any, len(h.attrs)+record.NumAttrs())
	addAttr := func(attr slog.Attr) bool {
		attr.Value = attr.Value.Resolve()
		attrs[attr.Key] = attr.Value.Any()
		return true
	}
	for _, attr := range h.attrs {
		addAttr(attr)
	}
	record.Attrs(addAttr)

	h.state.records = append(h.state.records, requestLoggerTestRecord{
		message: record.Message,
		attrs:   attrs,
		pc:      record.PC,
	})
	return nil
}

func (h *requestLoggerTestHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	h.state.withAttrCalls = append(h.state.withAttrCalls, slices.Clone(attrs))
	next := *h
	next.attrs = append(slices.Clone(h.attrs), attrs...)
	return &next
}

func (h *requestLoggerTestHandler) WithGroup(string) slog.Handler { return h }

func newRequestLoggerTestLogger(minLevel slog.Level, debugAttrKey string) (*slog.Logger, *requestLoggerTestState) {
	state := &requestLoggerTestState{}
	logger := slog.New(&requestLoggerTestHandler{
		state:        state,
		minLevel:     minLevel,
		debugAttrKey: debugAttrKey,
	}).With(logfields.LogSubsys, "dnsproxy")
	return logger, state
}

func TestDNSRequestLoggerDefersDisabledDebugScope(t *testing.T) {
	logger, state := newRequestLoggerTestLogger(slog.LevelInfo, "")
	baseWithAttrs := len(state.withAttrCalls)

	requestLog := newDNSRequestLogger(logger, "10.0.0.10:12345", 42, true)
	requestLog.withName("denied.example.")
	requestLog.withEndpoint("111", requestLoggerTestIdentity)

	require.Nil(t, requestLog.debugLogger())
	require.Len(t, state.withAttrCalls, baseWithAttrs)
	require.Empty(t, state.records)

	requestLog.logger().Error("late-error")
	require.Equal(t, [][]slog.Attr{
		{
			slog.Any(logfields.IPAddr, "10.0.0.10:12345"),
			slog.Any(logfields.DNSRequestID, uint16(42)),
		},
		{slog.Any(logfields.DNSName, "denied.example.")},
		{
			slog.Any(logfields.EndpointID, "111"),
			slog.Any(logfields.Identity, requestLoggerTestIdentity),
		},
	}, state.withAttrCalls[baseWithAttrs:])

	record := state.find(t, "late-error")
	require.Equal(t, "dnsproxy", record.attrs[logfields.LogSubsys])
	require.Equal(t, "10.0.0.10:12345", record.attrs[logfields.IPAddr])
	require.Equal(t, uint64(42), record.attrs[logfields.DNSRequestID])
	require.Equal(t, "denied.example.", record.attrs[logfields.DNSName])
	require.Equal(t, "111", record.attrs[logfields.EndpointID])
	require.Equal(t, requestLoggerTestIdentity, record.attrs[logfields.Identity])
}

func TestDNSRequestLoggerPreservesScopeBoundaries(t *testing.T) {
	logger, state := newRequestLoggerTestLogger(slog.LevelDebug, "")
	baseWithAttrs := len(state.withAttrCalls)

	requestLog := newDNSRequestLogger(logger, "10.0.0.10:12345", 42, true)
	requestLog.withName("denied.example.")
	require.Len(t, state.withAttrCalls, baseWithAttrs)

	requestLog.debugLogger().Debug("name-scoped")
	require.Equal(t, [][]slog.Attr{
		{
			slog.Any(logfields.IPAddr, "10.0.0.10:12345"),
			slog.Any(logfields.DNSRequestID, uint16(42)),
		},
		{slog.Any(logfields.DNSName, "denied.example.")},
	}, state.withAttrCalls[baseWithAttrs:])

	requestLog.withEndpoint("111", requestLoggerTestIdentity)
	require.Equal(t, []slog.Attr{
		slog.Any(logfields.EndpointID, "111"),
		slog.Any(logfields.Identity, requestLoggerTestIdentity),
	}, state.withAttrCalls[baseWithAttrs+2])

	requestLog.logger().Error("endpoint-scoped")
	require.Len(t, state.withAttrCalls, baseWithAttrs+3, "the materialized logger must be reused")
	record := state.find(t, "endpoint-scoped")
	require.Equal(t, "111", record.attrs[logfields.EndpointID])
	require.Equal(t, requestLoggerTestIdentity, record.attrs[logfields.Identity])
	require.Contains(t, runtime.FuncForPC(record.pc).Name(), "TestDNSRequestLoggerPreservesScopeBoundaries")
}

func TestDNSRequestLoggerKeepsEagerFallback(t *testing.T) {
	logger, state := newRequestLoggerTestLogger(slog.LevelInfo, logfields.DNSName)
	baseWithAttrs := len(state.withAttrCalls)

	requestLog := newDNSRequestLogger(logger, "10.0.0.10:12345", 42, false)
	require.Len(t, state.withAttrCalls, baseWithAttrs+1)

	requestLog.withName("denied.example.")
	require.Len(t, state.withAttrCalls, baseWithAttrs+2)

	requestLog.debugLogger().Debug("attribute-enabled")
	record := state.find(t, "attribute-enabled")
	require.Equal(t, "denied.example.", record.attrs[logfields.DNSName])
}

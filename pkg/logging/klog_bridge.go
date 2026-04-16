// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package logging

import (
	"context"
	"log/slog"
	"regexp"

	"k8s.io/klog/v2"

	"github.com/cilium/cilium/pkg/logging/logfields"
)

var klogOverrides = []logLevelOverride{
	{
		// TODO: We can drop this once bumped to new client-go version which has this at info level:
		// https://github.com/kubernetes/client-go/commit/ea7a7e7cf9697850f17631f79ef4ef45b95c449e.
		matcher:     regexp.MustCompile("Failed to update.*falling back to slow path"),
		targetLevel: slog.LevelInfo,
	},
}

type logLevelOverride struct {
	matcher     *regexp.Regexp
	targetLevel slog.Level
}

// klogOverrideHandler is an slog.Handler that adds a "subsys" attribute and
// applies log level overrides based on regex patterns matching the log message.
// It wraps an underlying slog.Handler and delegates all actual output to it.
type klogOverrideHandler struct {
	inner     slog.Handler
	overrides []logLevelOverride
}

func (h *klogOverrideHandler) Enabled(ctx context.Context, level slog.Level) bool {
	// Always return true for levels at or above the minimum override target,
	// because a message at a higher level might get overridden down to a lower
	// level that the inner handler still accepts. In practice the inner handler
	// does the final filtering so this is safe.
	return h.inner.Enabled(ctx, level)
}

func (h *klogOverrideHandler) Handle(ctx context.Context, record slog.Record) error {
	for _, override := range h.overrides {
		if override.matcher.MatchString(record.Message) {
			record.Level = override.targetLevel
			break
		}
	}
	return h.inner.Handle(ctx, record)
}

func (h *klogOverrideHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return &klogOverrideHandler{
		inner:     h.inner.WithAttrs(attrs),
		overrides: h.overrides,
	}
}

func (h *klogOverrideHandler) WithGroup(name string) slog.Handler {
	return &klogOverrideHandler{
		inner:     h.inner.WithGroup(name),
		overrides: h.overrides,
	}
}

func initializeKLog(logger *slog.Logger) {
	log := logger.With(logfields.LogSubsys, "klog")
	handler := &klogOverrideHandler{
		inner:     log.Handler(),
		overrides: klogOverrides,
	}
	klog.SetSlogLogger(slog.New(handler))
}

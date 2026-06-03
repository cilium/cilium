// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package logging

import (
	"context"
	"log/slog"
	"regexp"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/klog/v2"

	"github.com/cilium/cilium/pkg/logging/logfields"
)

var klogOverrides = []logLevelOverride{
	{
		// A lease conflict during leader election is benign and self-recovers on
		// the next renew. It happens when operators briefly co-lead during a
		// rolling upgrade. Downgrade only the conflict so genuine lease update
		// failures still surface at error. See GH-45426.
		matcher:      regexp.MustCompile("Failed to update lease"),
		errPredicate: apierrors.IsConflict,
		targetLevel:  slog.LevelInfo,
	},
}

type logLevelOverride struct {
	matcher *regexp.Regexp
	// errPredicate, when set, must also match the record's "err" attribute for
	// the override to apply.
	errPredicate func(error) bool
	targetLevel  slog.Level
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
		if !override.matcher.MatchString(record.Message) {
			continue
		}
		if override.errPredicate != nil && !override.errPredicate(recordErr(record)) {
			continue
		}
		record.Level = override.targetLevel
		break
	}
	return h.inner.Handle(ctx, record)
}

// recordErr returns the error stored under the "err" attribute by logr's slog
// bridge for klog Error() calls, or nil if absent.
func recordErr(record slog.Record) error {
	var err error
	record.Attrs(func(a slog.Attr) bool {
		if a.Key != "err" {
			return true
		}
		err, _ = a.Value.Any().(error)
		return false
	})
	return err
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

// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package controllerruntime

import (
	"bytes"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"testing"

	"github.com/go-logr/logr"
	"github.com/stretchr/testify/assert"
	corev1 "k8s.io/api/core/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"

	"github.com/cilium/cilium/pkg/logging/logfields"
)

func newForbiddenError(cause metav1.CauseType) error {
	return &k8serrors.StatusError{ErrStatus: metav1.Status{
		Message: "forbidden error",
		Status:  metav1.StatusFailure,
		Code:    http.StatusForbidden,
		Reason:  metav1.StatusReasonForbidden,
		Details: &metav1.StatusDetails{
			Causes: []metav1.StatusCause{{Type: cause}},
		},
	}}
}

func TestLogSink(t *testing.T) {
	var buf bytes.Buffer
	logger := newLogrFromSlog(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{
		ReplaceAttr: func(groups []string, a slog.Attr) slog.Attr {
			switch a.Key {
			case "time":
				return slog.Attr{}
			case "err":
				return slog.Attr{Key: logfields.Error, Value: a.Value}
			}

			return a
		},
	})))

	tests := []struct {
		logger   logr.Logger
		msg      string
		err      error
		expected string
	}{
		{
			logger:   logger,
			err:      errors.New("foo"),
			msg:      "Reconciler error",
			expected: "level=ERROR msg=\"Reconciler error\" error=foo bar=baz",
		},
		{
			logger:   logger.WithName("name").WithValues("qux", "fred"),
			err:      errors.New("foo"),
			msg:      "Reconciler error",
			expected: "level=ERROR msg=\"Reconciler error\" qux=fred logger=name error=foo bar=baz",
		},
		{
			logger:   logger,
			err:      k8serrors.NewAlreadyExists(schema.GroupResource{Resource: "pod"}, "test"),
			msg:      "Reconciler error",
			expected: "level=INFO msg=\"Reconciler error\" bar=baz error=\"pod \\\"test\\\" already exists\"",
		},
		{
			logger:   logger.WithName("name").WithValues("qux", "fred"),
			msg:      "Reconciler error",
			err:      k8serrors.NewAlreadyExists(schema.GroupResource{Resource: "pod"}, "test"),
			expected: "level=INFO msg=\"Reconciler error\" qux=fred logger=name bar=baz error=\"pod \\\"test\\\" already exists\"",
		},
		{
			logger:   logger.WithName("name").WithValues("qux", "fred"),
			msg:      "Reconciler error",
			err:      fmt.Errorf("foo: %w", k8serrors.NewAlreadyExists(schema.GroupResource{Resource: "pod"}, "test")),
			expected: "level=INFO msg=\"Reconciler error\" qux=fred logger=name bar=baz error=\"foo: pod \\\"test\\\" already exists\"",
		},
		{
			logger:   logger.WithName("name").WithValues("qux", "fred"),
			msg:      "Reconciler error",
			err:      k8serrors.NewNotFound(schema.GroupResource{Resource: "pod"}, "test"),
			expected: "level=INFO msg=\"Reconciler error\" qux=fred logger=name bar=baz error=\"pod \\\"test\\\" not found\"",
		},
		{
			logger:   logger.WithName("name").WithValues("qux", "fred"),
			msg:      "Reconciler error",
			err:      k8serrors.NewConflict(schema.GroupResource{Resource: "pod"}, "test", errors.New("foo")),
			expected: "level=INFO msg=\"Reconciler error\" qux=fred logger=name bar=baz error=\"Operation cannot be fulfilled on pod \\\"test\\\": foo\"",
		},
		{
			logger:   logger.WithName("name").WithValues("qux", "fred"),
			msg:      "Reconciler error",
			err:      newForbiddenError(corev1.NamespaceTerminatingCause),
			expected: "level=INFO msg=\"Reconciler error\" qux=fred logger=name bar=baz error=\"forbidden error\"",
		},
		{
			logger:   logger.WithName("name").WithValues("qux", "fred"),
			msg:      "Reconciler error",
			err:      newForbiddenError(metav1.CauseTypeFieldValueDuplicate),
			expected: "level=ERROR msg=\"Reconciler error\" qux=fred logger=name error=\"forbidden error\" bar=baz",
		},
		{
			logger:   logger.WithName("name").WithValues("qux", "fred"),
			msg:      "Something else",
			err:      k8serrors.NewConflict(schema.GroupResource{Resource: "pod"}, "test", errors.New("foo")),
			expected: "level=ERROR msg=\"Something else\" qux=fred logger=name error=\"Operation cannot be fulfilled on pod \\\"test\\\": foo\" bar=baz",
		},
	}

	for _, tt := range tests {
		buf.Reset()
		tt.logger.Error(tt.err, tt.msg, "bar", "baz")
		assert.Equal(t, tt.expected, strings.TrimSuffix(buf.String(), "\n"))
	}
}

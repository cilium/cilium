// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package controllerruntime

import (
	"bytes"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/go-logr/logr"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	corev1 "k8s.io/api/core/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
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
	lgr := logrus.New()
	lgr.SetOutput(&buf)
	lgr.SetFormatter(&logrus.TextFormatter{DisableTimestamp: true})

	logger := newLogrFromLogrus(lgr)

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
			expected: "level=error msg=\"Reconciler error\" bar=baz error=foo",
		},
		{
			logger:   logger.WithName("name").WithValues("qux", "fred"),
			err:      errors.New("foo"),
			msg:      "Reconciler error",
			expected: "level=error msg=\"Reconciler error\" bar=baz error=foo logger=name qux=fred",
		},
		{
			logger:   logger,
			err:      k8serrors.NewAlreadyExists(schema.GroupResource{Resource: "pod"}, "test"),
			msg:      "Reconciler error",
			expected: "level=info msg=\"Reconciler error\" bar=baz error=\"pod \\\"test\\\" already exists\"",
		},
		{
			logger:   logger.WithName("name").WithValues("qux", "fred"),
			msg:      "Reconciler error",
			err:      k8serrors.NewAlreadyExists(schema.GroupResource{Resource: "pod"}, "test"),
			expected: "level=info msg=\"Reconciler error\" bar=baz error=\"pod \\\"test\\\" already exists\" logger=name qux=fred",
		},
		{
			logger:   logger.WithName("name").WithValues("qux", "fred"),
			msg:      "Reconciler error",
			err:      fmt.Errorf("foo: %w", k8serrors.NewAlreadyExists(schema.GroupResource{Resource: "pod"}, "test")),
			expected: "level=info msg=\"Reconciler error\" bar=baz error=\"foo: pod \\\"test\\\" already exists\" logger=name qux=fred",
		},
		{
			logger:   logger.WithName("name").WithValues("qux", "fred"),
			msg:      "Reconciler error",
			err:      k8serrors.NewNotFound(schema.GroupResource{Resource: "pod"}, "test"),
			expected: "level=info msg=\"Reconciler error\" bar=baz error=\"pod \\\"test\\\" not found\" logger=name qux=fred",
		},
		{
			logger:   logger.WithName("name").WithValues("qux", "fred"),
			msg:      "Reconciler error",
			err:      k8serrors.NewConflict(schema.GroupResource{Resource: "pod"}, "test", errors.New("foo")),
			expected: "level=info msg=\"Reconciler error\" bar=baz error=\"Operation cannot be fulfilled on pod \\\"test\\\": foo\" logger=name qux=fred",
		},
		{
			logger:   logger.WithName("name").WithValues("qux", "fred"),
			msg:      "Reconciler error",
			err:      newForbiddenError(corev1.NamespaceTerminatingCause),
			expected: "level=info msg=\"Reconciler error\" bar=baz error=\"forbidden error\" logger=name qux=fred",
		},
		{
			logger:   logger.WithName("name").WithValues("qux", "fred"),
			msg:      "Reconciler error",
			err:      newForbiddenError(metav1.CauseTypeFieldValueDuplicate),
			expected: "level=error msg=\"Reconciler error\" bar=baz error=\"forbidden error\" logger=name qux=fred",
		},
		{
			logger:   logger.WithName("name").WithValues("qux", "fred"),
			msg:      "Something else",
			err:      k8serrors.NewConflict(schema.GroupResource{Resource: "pod"}, "test", errors.New("foo")),
			expected: "level=error msg=\"Something else\" bar=baz error=\"Operation cannot be fulfilled on pod \\\"test\\\": foo\" logger=name qux=fred",
		},
	}

	for _, tt := range tests {
		buf.Reset()
		tt.logger.Error(tt.err, tt.msg, "bar", "baz")
		assert.Equal(t, tt.expected, strings.TrimSuffix(buf.String(), "\n"))
	}
}

// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package tests

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/cilium/cilium/cilium-cli/connectivity/check"
	"github.com/cilium/cilium/cilium-cli/utils/features"
)

func TestRetryConditionCurlOptions(t *testing.T) {
	params := check.Parameters{Retry: 3, RetryDelay: 3 * time.Second}
	ep := check.HTTPEndpoint("ep", "http://192.0.2.1:80/public")
	pod := check.Pod{Pod: &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Labels: map[string]string{"kind": "client"}}}}

	newRC := func(opts ...RetryOption) *retryCondition {
		rc := &retryCondition{}
		for _, o := range opts {
			o(rc)
		}
		return rc
	}

	retryOpts := []string{"--retry", "3", "--retry-all-errors", "--retry-delay", "3"}

	// A drop is expected: no retry flags regardless of the retry condition,
	// because curl always waits between retries and retrying a request meant to
	// fail only adds retry delay.
	assert.Empty(t, newRC(WithRetryAll()).CurlOptions(ep, features.IPFamilyV4, pod, params, false),
		"WithRetryAll must not emit retry options when a drop is expected")
	assert.Empty(t, newRC(WithRetryDestPort(80)).CurlOptions(ep, features.IPFamilyV4, pod, params, false),
		"scoped condition must not emit retry options when a drop is expected")

	// Success expected + WithRetryAll: emit the retry flags.
	assert.Equal(t, retryOpts, newRC(WithRetryAll()).CurlOptions(ep, features.IPFamilyV4, pod, params, true))

	// Retry disabled globally: never emit, even when success is expected.
	assert.Empty(t, newRC(WithRetryAll()).CurlOptions(ep, features.IPFamilyV4, pod,
		check.Parameters{Retry: 0}, true))

	// Success expected but no retry condition set: nothing to emit.
	assert.Empty(t, newRC().CurlOptions(ep, features.IPFamilyV4, pod, params, true))

	// Matching dest-port condition + success: emit.
	assert.Equal(t, retryOpts, newRC(WithRetryDestPort(80)).CurlOptions(ep, features.IPFamilyV4, pod, params, true))

	// Non-matching dest-port condition: no retry even on success.
	assert.Empty(t, newRC(WithRetryDestPort(8080)).CurlOptions(ep, features.IPFamilyV4, pod, params, true))
}

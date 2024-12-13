// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package k8s

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestK8sErrorLogTimeout(t *testing.T) {
	errstr := "I am an error string"

	// ensure k8sErrMsg is empty for tests that use it
	k8sErrMsgMU.Lock()
	k8sErrMsg = map[string]time.Time{}
	k8sErrMsgMU.Unlock()

	// Returns true because it's the first time we see this message
	startTime := time.Now()
	require.True(t, k8sErrorUpdateCheckUnmuteTime(errstr, startTime))

	// Returns false because <= k8sErrLogTimeout time has passed
	noLogTime := startTime.Add(k8sErrLogTimeout)
	require.False(t, k8sErrorUpdateCheckUnmuteTime(errstr, noLogTime))

	// Returns true because k8sErrLogTimeout has passed
	shouldLogTime := startTime.Add(k8sErrLogTimeout).Add(time.Nanosecond)
	require.True(t, k8sErrorUpdateCheckUnmuteTime(errstr, shouldLogTime))
}

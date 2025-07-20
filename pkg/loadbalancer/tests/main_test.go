// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package tests

import (
	"testing"

	"go.uber.org/goleak"
)

func TestMain(m *testing.M) {
	goleak.VerifyTestMain(m,
		// The metrics "status" collector tries to connect to the agent and leaves these
		// around. We should refactor pkg/metrics to split it into "plain registry"
		// and the agent specifics.
		goleak.IgnoreTopFunction("net/http.(*persistConn).writeLoop"),
		goleak.IgnoreTopFunction("internal/poll.runtime_pollWait"),

		// Unfortunately we don't have a way for waiting for the DelayingWorkQueue's background goroutine
		// to exit (used by pkg/k8s/resource), so we'll just need to ignore it.
		goleak.IgnoreTopFunction("k8s.io/client-go/util/workqueue.(*delayingType[...]).waitingLoop"),
	)
}

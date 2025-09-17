// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package testutils

import (
	"slices"
	"testing"

	//nolint:gomodguard
	"go.uber.org/goleak"
)

func defaultGoleakOptions() []goleak.Option {
	return []goleak.Option{
		// The metrics "status" collector tries to connect to the agent and leaves these
		// around. We should refactor pkg/metrics to split it into "plain registry"
		// and the agent specifics.
		goleak.IgnoreTopFunction("net/http.(*persistConn).writeLoop"),
		goleak.IgnoreTopFunction("internal/poll.runtime_pollWait"),

		// Unfortunately we don't have a way for waiting for the workqueue's background goroutine
		// to exit (used by pkg/k8s/resource), so we'll just need to ignore it.
		goleak.IgnoreTopFunction("k8s.io/client-go/util/workqueue.(*Typed[...]).updateUnfinishedWorkLoop"),
		goleak.IgnoreTopFunction("k8s.io/client-go/util/workqueue.(*delayingType[...]).waitingLoop"),
	}
}

// GoleakVerifyTestMain calls [goleak.VerifyTestMain] with our known list of
// leaky functions to ignore. To use this:
//
//	func TestMain(m *testing.M) {
//	  testutils.GoleakVerifyTestMain(m)
//	}
func GoleakVerifyTestMain(m *testing.M, options ...goleak.Option) {
	goleak.VerifyTestMain(
		m,
		slices.Concat(defaultGoleakOptions(), options)...)
}

// GoleakVerifyNone calls [goleak.VerifyNone] with our known list of leaky
// functions to ignore.
func GoleakVerifyNone(t *testing.T, options ...goleak.Option) {
	goleak.VerifyNone(
		t,
		slices.Concat(defaultGoleakOptions(), options)...)
}

// Aliases for the goleak options as we're forbidding the go.uber.org/goleak
// import.
var (
	GoleakIgnoreTopFunction = goleak.IgnoreTopFunction
	GoleakIgnoreAnyFunction = goleak.IgnoreAnyFunction
	GoleakIgnoreCurrent     = goleak.IgnoreCurrent
	GoleakCleanup           = goleak.Cleanup
)

type GoleakOption = goleak.Option

/*
Copyright 2023 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package http //nolint:revive

import (
	"fmt"
	"regexp"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	clientset "k8s.io/client-go/kubernetes"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"sigs.k8s.io/gateway-api/conformance/utils/config"
	"sigs.k8s.io/gateway-api/conformance/utils/kubernetes"
	"sigs.k8s.io/gateway-api/conformance/utils/tlog"
)

func GetMirrorLogRegexp(path string) *regexp.Regexp {
	return regexp.MustCompile(fmt.Sprintf("Echoing back request made to %s to client", regexp.QuoteMeta(path)))
}

func ExpectMirroredRequest(t *testing.T, client client.Client, clientset clientset.Interface, mirrorPods []MirroredBackend, path string, timeoutConfig config.TimeoutConfig) func() {
	for i, mirrorPod := range mirrorPods {
		if mirrorPod.Name == "" {
			tlog.Fatalf(t, "Mirrored BackendRef[%d].Name wasn't provided in the testcase, this test should only check http request mirror.", i)
		}
	}

	mirrorLogRegexp := GetMirrorLogRegexp(path)

	var done sync.WaitGroup
	var started sync.WaitGroup
	started.Add(len(mirrorPods))
	results := make(chan bool, len(mirrorPods))

	// Start the log window before the requests were sent, not at "now". The
	// caller already dispatched the mirrored requests, and on a high-latency
	// (e.g. edge-routed) data plane the mirror is logged in-cluster slightly
	// before the primary response returns to the client, so it can land in an
	// earlier second than time.Now() and be excluded by the SinceTime filter,
	// which has 1-second granularity. MaxTimeToConsistency bounds how long the
	// caller's send loop could have run, and the match regexp is keyed on the
	// unique request path, so widening the window cannot match an unrelated
	// test's mirror.
	assertionStart := time.Now().Add(-timeoutConfig.MaxTimeToConsistency)

	for _, mirrorPod := range mirrorPods {
		done.Go(func() {
			var startedOnce sync.Once

			success := assert.Eventually(t, func() bool {
				tlog.Log(t, "Searching for the mirrored request log")
				tlog.Logf(t, `Reading "%s/%s" logs`, mirrorPod.Namespace, mirrorPod.Name)
				logs, err := kubernetes.DumpEchoLogs(t.Context(), mirrorPod.Namespace, mirrorPod.Name, client, clientset, assertionStart)
				if err != nil {
					tlog.Logf(t, `Couldn't read "%s/%s" logs: %v`, mirrorPod.Namespace, mirrorPod.Name, err)
					return false
				}

				// Report as started after we have successfully dumped the logs for
				// the first time.
				startedOnce.Do(started.Done)

				return slices.ContainsFunc(logs, mirrorLogRegexp.MatchString)
			}, timeoutConfig.RequestTimeout, time.Second, `Couldn't find mirrored request in "%s/%s" logs`, mirrorPod.Namespace, mirrorPod.Name)

			// signal done even if all log dumps failed above.
			startedOnce.Do(started.Done)
			results <- success
		})
	}

	// Wait until each watcher has either dumped logs at least once or timed out.
	started.Wait()

	// caller should eventually call the returned function to wait for the goroutines to be done
	// and to log if successful
	return func() {
		done.Wait()
		close(results)

		successes := 0
		for result := range results {
			if result {
				successes++
			}
		}
		if successes == len(mirrorPods) {
			tlog.Log(t, "Found mirrored request log in all desired backends")
		}
	}
}

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

func ExpectMirroredRequest(t *testing.T, client client.Client, clientset clientset.Interface, mirrorPods []MirroredBackend, path string, timeoutConfig config.TimeoutConfig) func() {
	for i, mirrorPod := range mirrorPods {
		if mirrorPod.Name == "" {
			tlog.Fatalf(t, "Mirrored BackendRef[%d].Name wasn't provided in the testcase, this test should only check http request mirror.", i)
		}
	}

	mirrorLogRegexp := regexp.MustCompile(fmt.Sprintf("Echoing back request made to %s to client", regexp.QuoteMeta(path)))

	var done sync.WaitGroup
	done.Add(len(mirrorPods))
	var started sync.WaitGroup
	started.Add(len(mirrorPods))
	results := make(chan bool, len(mirrorPods))

	// Apply one second safety margin for small clock skew between the nodes.
	assertionStart := time.Now().Add(-time.Second)

	for _, mirrorPod := range mirrorPods {
		go func(mirrorPod MirroredBackend) {
			var startedOnce sync.Once

			defer done.Done()

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

				for _, log := range logs {
					if mirrorLogRegexp.MatchString(log) {
						return true
					}
				}
				return false
			}, timeoutConfig.RequestTimeout, time.Second, `Couldn't find mirrored request in "%s/%s" logs`, mirrorPod.Namespace, mirrorPod.Name)

			// signal done even if all log dumps failed above.
			startedOnce.Do(started.Done)
			results <- success
		}(mirrorPod)
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

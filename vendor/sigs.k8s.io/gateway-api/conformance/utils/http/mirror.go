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

package http

import (
	"fmt"
	"regexp"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	clientset "k8s.io/client-go/kubernetes"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"sigs.k8s.io/gateway-api/conformance/utils/kubernetes"
	"sigs.k8s.io/gateway-api/conformance/utils/tlog"
)

func ExpectMirroredRequest(t *testing.T, client client.Client, clientset clientset.Interface, mirrorPods []MirroredBackend, path string) {
	for i, mirrorPod := range mirrorPods {
		if mirrorPod.Name == "" {
			tlog.Fatalf(t, "Mirrored BackendRef[%d].Name wasn't provided in the testcase, this test should only check http request mirror.", i)
		}
	}

	var wg sync.WaitGroup
	wg.Add(len(mirrorPods))

	for _, mirrorPod := range mirrorPods {
		go func(mirrorPod MirroredBackend) {
			defer wg.Done()

			require.Eventually(t, func() bool {
				mirrorLogRegexp := regexp.MustCompile(fmt.Sprintf("Echoing back request made to \\%s to client", path))

				tlog.Log(t, "Searching for the mirrored request log")
				tlog.Logf(t, `Reading "%s/%s" logs`, mirrorPod.Namespace, mirrorPod.Name)
				logs, err := kubernetes.DumpEchoLogs(mirrorPod.Namespace, mirrorPod.Name, client, clientset, time.Now())
				if err != nil {
					tlog.Logf(t, `Couldn't read "%s/%s" logs: %v`, mirrorPod.Namespace, mirrorPod.Name, err)
					return false
				}

				for _, log := range logs {
					if mirrorLogRegexp.MatchString(log) {
						return true
					}
				}
				return false
			}, 60*time.Second, time.Millisecond*100, fmt.Sprintf(`Couldn't find mirrored request in "%s/%s" logs`, mirrorPod.Namespace, mirrorPod.Name))
		}(mirrorPod)
	}

	wg.Wait()

	tlog.Log(t, "Found mirrored request log in all desired backends")
}

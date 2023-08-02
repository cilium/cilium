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
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	clientset "k8s.io/client-go/kubernetes"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"sigs.k8s.io/gateway-api/conformance/utils/kubernetes"
)

func ExpectMirroredRequest(t *testing.T, client client.Client, clientset *clientset.Clientset, ns, mirrorPod, path string) {
	if mirrorPod == "" {
		t.Fatalf("MirroredTo wasn't provided in the testcase, this test should only check http request mirror.")
	}

	require.Eventually(t, func() bool {
		var mirrored bool
		mirrorLogRegexp := regexp.MustCompile(fmt.Sprintf("Echoing back request made to \\%s to client", path))

		t.Log("Searching for the mirrored request log")
		t.Logf("Reading \"%s/%s\" logs", ns, mirrorPod)
		logs, err := kubernetes.DumpEchoLogs(ns, mirrorPod, client, clientset)
		if err != nil {
			t.Logf("could not read \"%s/%s\" logs: %v", ns, mirrorPod, err)
			return false
		}

		for _, log := range logs {
			if mirrorLogRegexp.MatchString(string(log)) {
				mirrored = true
				break
			}
		}
		return mirrored

	}, 60*time.Second, time.Second, "Mirrored request log wasn't found")

	t.Log("Mirrored request log found")
}

// Copyright 2017 Authors of Cilium
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package k8sTest

import (
	"fmt"
	"path"
	"strings"
	"sync"
	"time"

	"github.com/cilium/cilium/test/helpers"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	log "github.com/sirupsen/logrus"
)

var _ = Describe("NightlyK8sEpsMeasurement", func() {

	var kubectl *helpers.Kubectl
	var logger *log.Entry
	var initialized bool
	initialize := func() {
		if initialized == true {
			return
		}
		logger = log.WithFields(log.Fields{"testName": "K8sServiceTest"})
		logger.Info("Starting")

		kubectl = helpers.CreateKubectl(helpers.K8s1VMName, logger)
		path := fmt.Sprintf("%s/cilium_ds.yaml", kubectl.ManifestsPath())
		kubectl.Apply(path)
		_, err := kubectl.WaitforPods(helpers.KubeSystemNamespace, "-l k8s-app=cilium", 600)
		Expect(err).Should(BeNil())
		initialized = true
	}

	BeforeEach(func() {
		initialize()
	})

	AfterEach(func() {
		if CurrentGinkgoTestDescription().Failed {
			ciliumPod, _ := kubectl.GetCiliumPodOnNode(helpers.KubeSystemNamespace, "k8s1")
			kubectl.CiliumReport("kube-system", ciliumPod, []string{
				"cilium service list",
				"cilium endpoint list"})
		}
	})

	endpointCount := 10
	manifestPath := "tmp.yaml"

	Measure(fmt.Sprintf("%d endpoint creation", endpointCount), func(b Benchmarker) {
		_, lastServer, err := helpers.GenerateManifestForEndpoints(endpointCount, manifestPath)
		Expect(err).Should(BeNil())

		vagrantManifestPath := path.Join(helpers.BasePath, manifestPath)

		res := kubectl.Apply(vagrantManifestPath)
		res.ExpectSuccess(res.GetDebugMessage())
		defer kubectl.Delete(vagrantManifestPath)

		waitForPodsTime := b.Time("Wait for pods", func() {
			pods, err := kubectl.WaitforPods(helpers.DefaultNamespace, "-l zgroup=testapp", 300)
			Expect(pods).Should(BeTrue())
			Expect(err).Should(BeNil())
		})
		log.WithFields(log.Fields{"pod creation time": waitForPodsTime}).Info("")

		ciliumPod, err := kubectl.GetCiliumPodOnNode(helpers.KubeSystemNamespace, helpers.K8s1)
		Expect(err).Should(BeNil())

		ciliumPod2, err := kubectl.GetCiliumPodOnNode(helpers.KubeSystemNamespace, helpers.K8s2)
		Expect(err).Should(BeNil())

		pods := []string{ciliumPod, ciliumPod2}

		runtime := b.Time("Endpoint creation", func() {

			Eventually(func() bool {
				count := 0
				for _, pod := range pods {
					output := kubectl.CiliumExec(pod, "cilium endpoint list").Output().String()
					count += strings.Count(output, "ready")
				}

				return count >= endpointCount

			}, 300*time.Second, 3*time.Second).Should(BeTrue())
		})
		log.WithFields(log.Fields{"endpoint creation time": runtime}).Info("")

		var wg sync.WaitGroup

		for serverIndex := 0; serverIndex <= lastServer; serverIndex++ {
			for clientIndex := lastServer + 1; clientIndex < endpointCount; clientIndex++ {
				wg.Add(1)
				//TODO: run these functions with go after figuring out why they fail while run in parallel
				func(to, from int) {
					defer wg.Done()
					defer GinkgoRecover()

					result := kubectl.TestConnectivityPodService(fmt.Sprintf("app%d", from), fmt.Sprintf("app%d-service", to))
					result.ExpectSuccess(result.GetDebugMessage())
				}(serverIndex, clientIndex)
			}
		}
		wg.Wait()
	}, 1)
})

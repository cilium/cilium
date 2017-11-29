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

	ciliumPath := fmt.Sprintf("%s/cilium_ds.yaml", kubectl.ManifestsPath())

	initialize := func() {
		if initialized == true {
			return
		}
		logger = log.WithFields(log.Fields{"testName": "NightlyK8sEpsMeasurement"})
		logger.Info("Starting")

		kubectl = helpers.CreateKubectl(helpers.K8s1VMName, logger)
		kubectl.Apply(ciliumPath)
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

	endpointCount := 20
	manifestPath := "tmp.yaml"
	vagrantManifestPath := path.Join(helpers.BasePath, manifestPath)
	var lastServer int

	Measure(fmt.Sprintf("%d endpoint creation", endpointCount), func(b Benchmarker) {
		var err error
		_, lastServer, err = helpers.GenerateManifestForEndpoints(endpointCount, manifestPath)
		Expect(err).Should(BeNil())

		res := kubectl.Apply(vagrantManifestPath)
		res.ExpectSuccess(res.GetDebugMessage())

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

	}, 1)

	It("Should be able to connect from client pods to services while cilium pod is being restarted", func() {
		defer kubectl.Delete(vagrantManifestPath)

		connectivityTestsFinished := make(chan struct{})

		// Run connectivity tests
		go func() {
			concurrency := 5
			sem := make(chan struct{}, concurrency)

			for serverIndex := 0; serverIndex <= lastServer; serverIndex++ {
				for clientIndex := lastServer + 1; clientIndex < endpointCount; clientIndex++ {
					sem <- struct{}{}
					go func(to, from int) {
						defer func() { <-sem }()
						defer GinkgoRecover()

						result := kubectl.TestConnectivityPodService(fmt.Sprintf("app%d", from), fmt.Sprintf("app%d-service", to))
						result.ExpectSuccess(result.GetDebugMessage())

					}(serverIndex, clientIndex)
				}
			}
			// fill the channel to make sure there are no goroutines left
			for i := 0; i < cap(sem); i++ {
				sem <- struct{}{}
			}
			log.Info("Connectivity checks finished")
			connectivityTestsFinished <- struct{}{}
		}()

		// Randomly redeploy cilium agent
	Redeploy:
		for {
			select {
			case <-connectivityTestsFinished:
				break Redeploy
			default:
				res := kubectl.Delete(ciliumPath)
				res.ExpectSuccess(res.GetDebugMessage())

				res = kubectl.Apply(ciliumPath)
				res.ExpectSuccess(res.GetDebugMessage())

				_, err := kubectl.WaitforPods(helpers.KubeSystemNamespace, "-l k8s-app=cilium", 600)
				Expect(err).Should(BeNil())
			}
		}
	})
})

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
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path"
	"sync"
	"time"

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/test/helpers"
	"github.com/cilium/cilium/test/helpers/policygen"

	"github.com/Jeffail/gabs"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/sirupsen/logrus"
)

var (
	configMap       = "ConfigMap"
	endpointTimeout = (60 * time.Second)
)

var _ = Describe("NightlyEpsMeasurement", func() {

	var kubectl *helpers.Kubectl
	var logger *logrus.Entry
	var once sync.Once
	var ciliumPath string

	initialize := func() {
		logger = log.WithFields(logrus.Fields{"testName": "NightlyK8sEpsMeasurement"})
		logger.Info("Starting")

		kubectl = helpers.CreateKubectl(helpers.K8s1VMName(), logger)

		ciliumPath = kubectl.ManifestGet("cilium_ds.yaml")
		kubectl.Apply(ciliumPath)

		_, err := kubectl.WaitforPods(helpers.KubeSystemNamespace, "-l k8s-app=cilium", 600)
		Expect(err).Should(BeNil())

		err = kubectl.WaitKubeDNS()
		Expect(err).Should(BeNil())
	}

	BeforeEach(func() {
		once.Do(initialize)
	})

	AfterEach(func() {
		if CurrentGinkgoTestDescription().Failed {
			ciliumPod, _ := kubectl.GetCiliumPodOnNode(helpers.KubeSystemNamespace, helpers.K8s1)
			kubectl.CiliumReport(helpers.KubeSystemNamespace, ciliumPod, []string{
				"cilium service list",
				"cilium endpoint list"})
		}
	})

	endpointCount := 20
	manifestPath := "tmp.yaml"
	vagrantManifestPath := path.Join(helpers.BasePath, manifestPath)
	var lastServer int

	Measure(fmt.Sprintf("%d endpoint creation", endpointCount), func(b Benchmarker) {
		endpointsTimeout := endpointTimeout * time.Duration(endpointCount)
		desiredState := string(models.EndpointStateReady)
		var err error
		_, lastServer, err = helpers.GenerateManifestForEndpoints(endpointCount, manifestPath)
		Expect(err).Should(BeNil())

		res := kubectl.Apply(vagrantManifestPath)
		res.ExpectSuccess(res.GetDebugMessage())

		waitForPodsTime := b.Time("Wait for pods", func() {
			pods, err := kubectl.WaitforPods(helpers.DefaultNamespace, "-l zgroup=testapp", endpointsTimeout)
			Expect(err).Should(BeNil(),
				"Cannot retrieve %d pods in %d seconds", endpointCount, endpointsTimeout)
			Expect(pods).Should(BeTrue())
		})

		log.WithFields(logrus.Fields{"pod creation time": waitForPodsTime}).Info("")

		ciliumPods, err := kubectl.GetCiliumPods(helpers.KubeSystemNamespace)
		Expect(err).To(BeNil(), "Cannot retrieve cilium pods")

		runtime := b.Time("Endpoint creation", func() {
			Eventually(func() bool {
				count := 0
				for _, pod := range ciliumPods {
					status := kubectl.CiliumEndpointsStatus(pod)
					result := map[string]int{}
					for _, state := range status {
						result[state]++
					}
					count += result[desiredState]
					logger.WithFields(logrus.Fields{
						"status": result,
						"pod":    pod,
					}).Info("Cilium endpoint status")
				}
				return count >= endpointCount
			}, endpointsTimeout, 3*time.Second).Should(BeTrue())
		})
		log.WithFields(logrus.Fields{"endpoint creation time": runtime}).Info("")
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

	Context("Nightly Policies", func() {
		numPods := 20
		bunchPods := 5
		podsCreated := 0

		AfterEach(func() {
			kubectl.Exec(fmt.Sprintf(
				"%s delete --all pods,svc,cnp -n %s", helpers.KubectlCmd, helpers.DefaultNamespace))
		})

		Measure(fmt.Sprintf("Applying policies to %d pods in a group of %d", numPods, bunchPods), func(b Benchmarker) {
			testDef := func() {
				logger.Errorf("Creating %d new pods, total created are %d", numPods, podsCreated)
				testSpecGroup := policygen.TestSpecsGroup{}
				for i := 0; i < bunchPods; i++ {
					testSpec := policygen.GetBasicTestSpec()
					testSpecGroup = append(testSpecGroup, &testSpec)
				}

				By("Creating endpoints")

				endpoints := b.Time("Runtime", func() {
					testSpecGroup.CreateAndApplyManifests(kubectl)
				})
				b.RecordValue("Endpoint Creation in seconds", endpoints.Seconds())
				By("Apply Policies")

				policy := b.Time("policy", func() {
					testSpecGroup.CreateAndApplyCNP(kubectl)
				})
				b.RecordValue("Policy Creation in seconds", policy.Seconds())

				By("Connectivity Test")
				conn := b.Time("connTest", func() {
					testSpecGroup.ConnectivityTest()
				})

				b.RecordValue("Connectivity test in seconds", conn.Seconds())
			}

			for podsCreated < numPods {
				testDef()
				podsCreated = podsCreated + bunchPods
			}
		}, 1)
	})
})

var _ = Describe("NightlyExamples", func() {

	var kubectl *helpers.Kubectl
	var logger *logrus.Entry
	var once sync.Once
	var ciliumPath string
	var demoPath string
	var l3Policy string
	var appService = "app1-service"

	initialize := func() {
		logger = log.WithFields(logrus.Fields{"testName": "NightlyK8sEpsMeasurement"})
		logger.Info("Starting")

		kubectl = helpers.CreateKubectl(helpers.K8s1VMName(), logger)
		kubectl.Delete(ciliumPath)

		demoPath = kubectl.ManifestGet("demo.yaml")
		l3Policy = kubectl.ManifestGet("l3_l4_policy.yaml")
	}

	BeforeEach(func() {
		once.Do(initialize)
	})

	AfterEach(func() {
		kubectl.Delete(demoPath)
		kubectl.Delete(l3Policy)
	})

	// getAppPods return a map where the key is the Application name and the
	// value is the pod name
	getAppPods := func() map[string]string {
		appPods := make(map[string]string)
		apps := []string{helpers.App1, helpers.App2, helpers.App3}
		for _, v := range apps {
			res, err := kubectl.GetPodNames(helpers.DefaultNamespace, fmt.Sprintf("id=%s", v))
			Expect(err).Should(BeNil())
			appPods[v] = res[0]
			logger.Infof("PolicyRulesTest: pod=%q assigned to %q", res[0], v)
		}
		return appPods
	}

	It("Check Kubernetes Example is working correctly", func() {
		var path = "../examples/kubernetes/cilium.yaml"
		var result bytes.Buffer
		newCiliumDSName := fmt.Sprintf("cilium_ds_%s.json", helpers.MakeUID())

		objects, err := helpers.DecodeYAMLOrJSON(path)
		Expect(err).To(BeNil())

		for _, object := range objects {
			data, err := json.Marshal(object)
			Expect(err).To(BeNil())

			jsonObj, err := gabs.ParseJSON(data)
			Expect(err).To(BeNil())

			value, _ := jsonObj.Path("kind").Data().(string)
			if value == configMap {
				jsonObj.SetP("---\nendpoints:\n- http://k8s1:9732\n", "data.etcd-config")
				jsonObj.SetP("true", "data.debug")
			}

			result.WriteString(jsonObj.String())
		}

		fp, err := os.Create(newCiliumDSName)
		defer fp.Close()
		Expect(err).To(BeNil())

		fmt.Fprint(fp, result.String())

		kubectl.Apply(helpers.GetFilePath(newCiliumDSName)).ExpectSuccess()
		defer kubectl.Delete(helpers.GetFilePath(newCiliumDSName))
		status, err := kubectl.WaitforPods(helpers.KubeSystemNamespace, "-l k8s-app=cilium", 300)
		Expect(status).Should(BeTrue())
		Expect(err).Should(BeNil())

		kubectl.Apply(demoPath).ExpectSuccess()
		_, err = kubectl.WaitforPods(helpers.DefaultNamespace, "-l zgroup=testapp", 300)
		Expect(err).Should(BeNil())

		_, err = kubectl.CiliumPolicyAction(helpers.KubeSystemNamespace, l3Policy, helpers.KubectlApply, 300)
		Expect(err).Should(BeNil())

		appPods := getAppPods()

		clusterIP, _, err := kubectl.GetServiceHostPort(helpers.DefaultNamespace, appService)
		Expect(err).Should(BeNil())

		_, err = kubectl.ExecPodCmd(
			helpers.DefaultNamespace, appPods[helpers.App2],
			helpers.CurlFail(fmt.Sprintf("http://%s/public", clusterIP)))
		Expect(err).Should(BeNil())

		_, err = kubectl.ExecPodCmd(
			helpers.DefaultNamespace, appPods[helpers.App3],
			helpers.CurlFail(fmt.Sprintf("http://%s/public", clusterIP)))
		Expect(err).Should(HaveOccurred())
	})
})

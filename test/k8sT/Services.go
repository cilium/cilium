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
	"net"
	"strings"

	"github.com/asaskevich/govalidator"
	"github.com/cilium/cilium/test/helpers"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/sirupsen/logrus"
	"k8s.io/api/core/v1"
)

var _ = Describe("K8sServicesTest", func() {

	var kubectl *helpers.Kubectl
	var logger *logrus.Entry
	var initialized bool
	var serviceName string = "app1-service"
	initialize := func() {
		if initialized == true {
			return
		}
		logger = log.WithFields(logrus.Fields{"testName": "K8sServiceTest"})
		logger.Info("Starting")

		kubectl = helpers.CreateKubectl(helpers.K8s1VMName(), logger)
		path := kubectl.ManifestGet("cilium_ds.yaml")
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
			ciliumPod, _ := kubectl.GetCiliumPodOnNode("kube-system", "k8s1")
			kubectl.CiliumReport("kube-system", ciliumPod, []string{
				"cilium service list",
				"cilium endpoint list",
				"cilium policy get"})
		}
	})

	testHTTPRequest := func(url string) {
		output, err := kubectl.GetPods(helpers.DefaultNamespace, "-l zgroup=testDSClient").Filter("{.items[*].metadata.name}")
		ExpectWithOffset(1, err).Should(BeNil())
		pods := strings.Split(output.String(), " ")
		// A DS with client is running in each node. So we try from each node
		// that can connect to the service.  To make sure that the cross-node
		// service connectivity is correct we tried 10 times, so balance in the
		// two nodes
		for _, pod := range pods {
			for i := 1; i <= 10; i++ {
				_, err := kubectl.ExecPodCmd(helpers.DefaultNamespace, pod, fmt.Sprintf("curl --connect-timeout 5 %s", url))
				ExpectWithOffset(1, err).Should(BeNil(), "Pod '%s' can not connect to service '%s'", pod, url)
			}
		}
	}

	waitPodsDs := func() {
		groups := []string{"zgroup=testDS", "zgroup=testDSClient"}
		for _, pod := range groups {
			pods, err := kubectl.WaitforPods(helpers.DefaultNamespace, fmt.Sprintf("-l %s", pod), 300)
			ExpectWithOffset(1, pods).Should(BeTrue())
			ExpectWithOffset(1, err).Should(BeNil())
		}
	}

	It("Check Service", func() {
		demoDSPath := kubectl.ManifestGet("demo.yaml")
		kubectl.Apply(demoDSPath)
		defer kubectl.Delete(demoDSPath)

		pods, err := kubectl.WaitforPods(helpers.DefaultNamespace, "-l zgroup=testapp", 300)
		Expect(pods).Should(BeTrue())
		Expect(err).Should(BeNil())

		svcIP, err := kubectl.Get(
			helpers.DefaultNamespace, fmt.Sprintf("service %s", serviceName)).Filter("{.spec.clusterIP}")
		Expect(err).Should(BeNil())
		Expect(govalidator.IsIP(svcIP.String())).Should(BeTrue())

		status := kubectl.Exec(fmt.Sprintf("curl http://%s/", svcIP))
		status.ExpectSuccess()

		ciliumPod, err := kubectl.GetCiliumPodOnNode(helpers.KubeSystemNamespace, helpers.K8s1)
		Expect(err).Should(BeNil())

		service := kubectl.CiliumExec(ciliumPod, "cilium service list")
		Expect(service.Output()).Should(ContainSubstring(svcIP.String()))
		service.ExpectSuccess()

	}, 300)

	It("Check Service with cross-node", func() {
		demoDSPath := kubectl.ManifestGet("demo_ds.yaml")
		kubectl.Apply(demoDSPath)
		defer kubectl.Delete(demoDSPath)

		waitPodsDs()

		svcIP, err := kubectl.Get(
			helpers.DefaultNamespace, "service testds-service").Filter("{.spec.clusterIP}")
		Expect(err).Should(BeNil())
		log.Debugf("svcIP: %s", svcIP.String())
		Expect(govalidator.IsIP(svcIP.String())).Should(BeTrue())

		url := fmt.Sprintf("http://%s/", svcIP)
		testHTTPRequest(url)
	})

	//TODO: Check service with IPV6

	It("Check NodePort", func() {
		demoDSPath := kubectl.ManifestGet("demo_ds.yaml")
		kubectl.Apply(demoDSPath)
		defer kubectl.Delete(demoDSPath)

		waitPodsDs()

		var data v1.Service
		err := kubectl.Get("default", "service test-nodeport").Unmarshal(&data)
		Expect(err).Should(BeNil(), "Can not retrieve service")
		url := fmt.Sprintf("http://%s",
			net.JoinHostPort(data.Spec.ClusterIP, fmt.Sprintf("%d", data.Spec.Ports[0].Port)))
		testHTTPRequest(url)
	})

	It("CNP Specs Test", func() {

		// Various constants used in this test
		wgetCommand := "%s exec -t %s wget -- --tries=2 --connect-timeout 10 %s"

		version := "version"
		v1 := "v1"
		v2 := "v2"

		productPage := "productpage"
		reviews := "reviews"
		ratings := "ratings"
		details := "details"
		app := "app"
		bookinfo := "bookinfo"
		health := "health"

		apiPort := "9080"

		podNameFilter := "{.items[*].metadata.name}"

		// shouldConnect asserts that srcPod can connect to dst.
		shouldConnect := func(srcPod, dst string) {
			By(fmt.Sprintf("Checking that %s can connect to %s", srcPod, dst))
			res := kubectl.Exec(fmt.Sprintf(wgetCommand, helpers.KubectlCmd, srcPod, dst))
			res.ExpectSuccess()
		}

		// shouldNotConnect asserts that srcPod cannot connect to dst.
		shouldNotConnect := func(srcPod, dst string) {
			By(fmt.Sprintf("Checking that %s cannot connect to %s", srcPod, dst))
			res := kubectl.Exec(fmt.Sprintf(wgetCommand, helpers.KubectlCmd, srcPod, dst))
			res.ExpectFail()
		}

		// formatLabelArgument formats the provided key-value pairs as labels for use in
		// querying Kubernetes.
		formatLabelArgument := func(firstKey, firstValue string, nextLabels ...string) string {
			baseString := fmt.Sprintf("-l %s=%s", firstKey, firstValue)
			if nextLabels == nil {
				return baseString
			} else if len(nextLabels)%2 != 0 {
				panic("must provide even number of arguments for label key-value pairings")
			} else {
				for i := 0; i < len(nextLabels); i += 2 {
					baseString = fmt.Sprintf("%s,%s=%s", baseString, nextLabels[i], nextLabels[i+1])
				}
			}
			return baseString
		}

		// formatAPI is a helper function which formats a URI to access.
		formatAPI := func(service, port, resource string) string {
			if resource != "" {
				return fmt.Sprintf("%s:%s/%s", service, port, resource)
			}

			return fmt.Sprintf("%s:%s", service, port)
		}

		ciliumPodK8s1, err := kubectl.GetCiliumPodOnNode(helpers.KubeSystemNamespace, helpers.K8s1)
		Expect(err).Should(BeNil())

		ciliumPodK8s2, err := kubectl.GetCiliumPodOnNode(helpers.KubeSystemNamespace, helpers.K8s2)
		Expect(err).Should(BeNil())

		bookInfoPath := kubectl.ManifestGet(bookinfo)
		res := kubectl.Create(bookInfoPath)
		defer kubectl.Delete(bookInfoPath)
		res.ExpectSuccess()

		pods, err := kubectl.WaitforPods(helpers.DefaultNamespace, formatLabelArgument(version, v1), helpers.HelperTimeout)
		Expect(pods).Should(BeTrue())
		Expect(err).Should(BeNil())

		pods, err = kubectl.WaitforPods(helpers.DefaultNamespace, formatLabelArgument(version, v2), helpers.HelperTimeout)
		Expect(pods).Should(BeTrue())
		Expect(err).Should(BeNil())

		reviewsPodV1, err := kubectl.GetPods(helpers.DefaultNamespace, formatLabelArgument(app, reviews, version, v1)).Filter(podNameFilter)
		Expect(err).Should(BeNil())

		productpagePodV1, err := kubectl.GetPods(helpers.DefaultNamespace, formatLabelArgument(app, productPage, version, v1)).Filter(podNameFilter)
		Expect(err).Should(BeNil())

		areEndpointsReady := kubectl.CiliumEndpointWait(ciliumPodK8s1)
		Expect(areEndpointsReady).Should(BeTrue())

		pods, err = kubectl.WaitForServiceEndpoints(helpers.DefaultNamespace, "", details, apiPort, helpers.HelperTimeout)
		Expect(pods).Should(BeTrue())
		Expect(err).Should(BeNil())

		pods, err = kubectl.WaitForServiceEndpoints(helpers.DefaultNamespace, "", ratings, apiPort, helpers.HelperTimeout)
		Expect(pods).Should(BeTrue())
		Expect(err).Should(BeNil())

		pods, err = kubectl.WaitForServiceEndpoints(helpers.DefaultNamespace, "", reviews, apiPort, helpers.HelperTimeout)
		Expect(pods).Should(BeTrue())
		Expect(err).Should(BeNil())

		pods, err = kubectl.WaitForServiceEndpoints(helpers.DefaultNamespace, "", productPage, apiPort, helpers.HelperTimeout)
		Expect(pods).Should(BeTrue())
		Expect(err).Should(BeNil())

		By("Before policy import; all pods should be able to connect")
		shouldConnect(reviewsPodV1.String(), formatAPI(ratings, apiPort, health))
		shouldConnect(reviewsPodV1.String(), formatAPI(ratings, apiPort, ""))

		shouldConnect(productpagePodV1.String(), formatAPI(details, apiPort, health))
		shouldConnect(productpagePodV1.String(), formatAPI(details, apiPort, ""))
		shouldConnect(productpagePodV1.String(), formatAPI(ratings, apiPort, health))
		shouldConnect(productpagePodV1.String(), formatAPI(ratings, apiPort, ""))

		var policyPath string
		var policyCmd string

		if helpers.GetCurrentK8SEnv() != "1.6" {
			policyPath = fmt.Sprintf("%s/policies/cnp.yaml", bookInfoPath)
			policyCmd = "cilium policy get io.cilium.k8s-policy-name=multi-rules"

		} else {
			policyPath = fmt.Sprintf("%s/policies/cnp-deprecated.yaml", bookInfoPath)
			policyCmd = "cilium policy get io.cilium.k8s-policy-name=multi-rules-deprecated"
		}
		By("Importing policy")
		res = kubectl.Create(policyPath)
		defer func() {
			By("Checking that all policies were deleted in Cilium")
			output, err := kubectl.ExecPodCmd(helpers.KubeSystemNamespace, ciliumPodK8s1, policyCmd)
			Expect(err).Should(Not(BeNil()), "policies should be deleted from Cilium: policies found: %s", output)
		}()
		defer kubectl.Delete(policyPath)

		res.ExpectSuccess()

		By("Waiting for endpoints on k8s1 to be in ready state")
		areEndpointsReady = kubectl.CiliumEndpointWait(ciliumPodK8s1)
		Expect(areEndpointsReady).Should(BeTrue())

		By("Waiting for endpoints on k8s2 to be in ready state")
		areEndpointsReady = kubectl.CiliumEndpointWait(ciliumPodK8s2)
		Expect(areEndpointsReady).Should(BeTrue())

		By("Checking that policies were correctly imported into Cilium")
		_, err = kubectl.ExecPodCmd(helpers.KubeSystemNamespace, ciliumPodK8s1, policyCmd)
		Expect(err).Should(BeNil())

		By("After policy import")
		shouldConnect(reviewsPodV1.String(), formatAPI(ratings, apiPort, health))
		shouldNotConnect(reviewsPodV1.String(), formatAPI(ratings, apiPort, ""))

		shouldConnect(productpagePodV1.String(), formatAPI(details, apiPort, health))
		shouldConnect(productpagePodV1.String(), formatAPI(details, apiPort, ""))

		shouldNotConnect(productpagePodV1.String(), formatAPI(ratings, apiPort, health))
		shouldNotConnect(productpagePodV1.String(), formatAPI(ratings, apiPort, ""))
	})
})

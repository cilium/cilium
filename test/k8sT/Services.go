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
	log "github.com/sirupsen/logrus"
	"k8s.io/api/core/v1"
)

var _ = Describe("K8sServicesTest", func() {

	var kubectl *helpers.Kubectl
	var logger *log.Entry
	var initialized bool
	var serviceName string = "app1-service"
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
			ciliumPod, _ := kubectl.GetCiliumPodOnNode("kube-system", "k8s1")
			kubectl.CiliumReport("kube-system", ciliumPod, []string{
				"cilium service list",
				"cilium endpoint list"})
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
				_, err := kubectl.Exec(helpers.DefaultNamespace, pod, fmt.Sprintf("curl --connect-timeout 5 %s", url))
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
		demoDSPath := fmt.Sprintf("%s/demo.yaml", kubectl.ManifestsPath())
		kubectl.Apply(demoDSPath)
		defer kubectl.Delete(demoDSPath)

		pods, err := kubectl.WaitforPods(helpers.DefaultNamespace, "-l zgroup=testapp", 300)
		Expect(pods).Should(BeTrue())
		Expect(err).Should(BeNil())

		svcIP, err := kubectl.Get(
			helpers.DefaultNamespace, fmt.Sprintf("service %s", serviceName)).Filter("{.spec.clusterIP}")
		Expect(err).Should(BeNil())
		Expect(govalidator.IsIP(svcIP.String())).Should(BeTrue())

		status := kubectl.Node.Exec(fmt.Sprintf("curl http://%s/", svcIP))
		status.ExpectSuccess()

		ciliumPod, err := kubectl.GetCiliumPodOnNode(helpers.KubeSystemNamespace, helpers.K8s1)
		Expect(err).Should(BeNil())

		service := kubectl.CiliumExec(ciliumPod, "cilium service list")
		Expect(service.Output()).Should(ContainSubstring(svcIP.String()))
		service.ExpectSuccess()

	}, 300)

	It("Check Service with cross-node", func() {
		demoDSPath := fmt.Sprintf("%s/demo_ds.yaml", kubectl.ManifestsPath())
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
		demoDSPath := fmt.Sprintf("%s/demo_ds.yaml", kubectl.ManifestsPath())
		kubectl.Apply(demoDSPath)
		defer kubectl.Delete(demoDSPath)

		waitPodsDs()

		var data v1.Service
		err := kubectl.Get("default", "service test-nodeport").UnMarshal(&data)
		Expect(err).Should(BeNil(), "Can not retrieve service")
		url := fmt.Sprintf("http://%s",
			net.JoinHostPort(data.Spec.ClusterIP, fmt.Sprintf("%d", data.Spec.Ports[0].Port)))
		testHTTPRequest(url)
	})
})

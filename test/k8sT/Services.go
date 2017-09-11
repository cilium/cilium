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

	"github.com/asaskevich/govalidator"
	"github.com/cilium/cilium/test/helpers"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	log "github.com/sirupsen/logrus"
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

		kubectl = helpers.CreateKubectl("k8s1", logger)
		path := fmt.Sprintf("%s/cilium_ds.yaml", kubectl.ManifestsPath())
		kubectl.Apply(path)
		_, err := kubectl.WaitforPods("kube-system", "-l k8s-app=cilium", 600)
		Expect(err).Should(BeNil())
		initialized = true
	}

	BeforeEach(func() {
		initialize()
	})

	It("Check Service", func() {
		demoDSPath := fmt.Sprintf("%s/demo.yaml", kubectl.ManifestsPath())
		kubectl.Apply(demoDSPath)
		pods, err := kubectl.WaitforPods("default", "-l zgroup=testapp", 300)
		Expect(pods).Should(BeTrue())
		Expect(err).Should(BeNil())

		svcIP, err := kubectl.Get(
			"default", fmt.Sprintf("service %s", serviceName)).Filter("{.spec.clusterIP}")
		Expect(err).Should(BeNil())
		Expect(govalidator.IsIP(svcIP.String())).Should(BeTrue())

		status := kubectl.Node.Exec(fmt.Sprintf("curl http://%s/", svcIP))
		Expect(status.WasSuccessful()).Should(BeTrue())

		ciliumPod, err := kubectl.GetCiliumPodOnNode("kube-system", "k8s1")
		Expect(err).Should(BeNil())

		service := kubectl.CiliumExec(ciliumPod, "cilium service list")
		Expect(service.Output()).Should(ContainSubstring(svcIP.String()))
		Expect(service.WasSuccessful()).Should(BeTrue())

		kubectl.Delete(demoDSPath)
	}, 300)

	//TODO: Check service with IPV6
	//TODO: Check the service with cross-node
	//TODO: NodePort? It is ready?

})

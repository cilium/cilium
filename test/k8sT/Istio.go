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

	. "github.com/cilium/cilium/test/ginkgo-ext"
	"github.com/cilium/cilium/test/helpers"

	. "github.com/onsi/gomega"
	"github.com/sirupsen/logrus"
)

var _ = Describe("K8sValidatedIstioTest", func() {

	var (
		kubectl          *helpers.Kubectl
		logger           *logrus.Entry
		microscopeErr    error
		microscopeCancel func() error
		ciliumPodK8s1    string
		ciliumFilter     string = "-l k8s-app=cilium"
		ciliumPath       string = helpers.ManifestGet("cilium_ds_istio.yaml")
		istioManifest    string = helpers.ManifestGet("istio-auth.yaml")
		istioNS          string = "istio-system"
		istioFilter      string = "-l zgroup=istio"
		istioVersion     string = "release-0.8-20180521-15-16"
		istioURL         string = fmt.Sprintf("https://storage.googleapis.com/istio-prerelease/daily-build/%[1]s/istio-%[1]s-linux.tar.gz", istioVersion)
		istioConfigMap   string = helpers.ManifestGet("istio-kube-inject-template.yaml")
		istioInitPolicy  string = helpers.ManifestGet("istio-sidecar-init-policy.yaml")
		demoPath         string = helpers.ManifestGet("demo_big.yaml")
		container        string = "app-frontend"
	)

	BeforeAll(func() {
		logger = log.WithFields(logrus.Fields{"testName": "K8sValidatedIstioTest"})
		logger.Info("Starting")

		kubectl = helpers.CreateKubectl(helpers.K8s1VMName(), logger)
		kubectl.Apply(ciliumPath)

		_ = kubectl.Exec(fmt.Sprintf(
			"%s -n %s delete pods %s",
			helpers.KubectlCmd, helpers.KubeSystemNamespace, ciliumFilter))

		err := kubectl.WaitforPods(helpers.KubeSystemNamespace, ciliumFilter, 600)
		Expect(err).Should(BeNil())

		err = kubectl.WaitKubeDNS()
		Expect(err).Should(BeNil(), "DNS is not ready after timeout")

		_, err = kubectl.CiliumPolicyAction(
			helpers.KubeSystemNamespace, istioInitPolicy,
			helpers.KubectlApply, 300)
		Expect(err).Should(BeNil(), "Cannot apply init policy")

		ciliumPodK8s1, err = kubectl.GetCiliumPodOnNode(helpers.KubeSystemNamespace, helpers.K8s1)
		Expect(err).Should(BeNil(), "Cannot get cilium pod on k8s1")

		// Installing Istio
		res := kubectl.Exec(fmt.Sprintf("cd /tmp/; curl -L %s | tar xz ", istioURL))
		res.ExpectSuccess("Cannot download istio: %s", res.CombineOutput())

		res = kubectl.ExecWithSudo(fmt.Sprintf("mv -f /tmp/istio-%s /usr/local/istio", istioVersion))
		res.ExpectSuccess("Cannot mv Istio source folder ")

		res = kubectl.ExecWithSudo("ln -sf /usr/local/istio/bin/* /usr/local/bin/")
		res.ExpectSuccess("cannot copy Istio binaries")

		kubectl.Apply(istioManifest)

		err = kubectl.WaitforPods(istioNS, istioFilter, 600)
		Expect(err).Should(BeNil(), "Istio cannot be installed correctly")
	})

	kubeInject := func(fileName string, command string) *helpers.CmdRes {
		cmd := fmt.Sprintf("istioctl kube-inject --injectConfigFile %s -f %s | %s %s -f -",
			istioConfigMap,
			fileName,
			helpers.KubectlCmd,
			command)
		return kubectl.Exec(cmd)
	}

	AfterAll(func() {
		kubectl.Delete(ciliumPath)
		kubectl.Delete(istioManifest)
		kubectl.ExecWithSudo("rm -rf /ust/local/istio")
	})

	AfterFailed(func() {
		kubectl.CiliumReport(helpers.KubeSystemNamespace,
			"cilium service list",
			"cilium policy get",
			"cilium endpoint list")
	})

	JustBeforeEach(func() {
		microscopeErr, microscopeCancel = kubectl.MicroscopeStart()
		Expect(microscopeErr).To(BeNil(), "Microscope cannot be started")
	})

	JustAfterEach(func() {
		kubectl.ValidateNoErrorsOnLogs(CurrentGinkgoTestDescription().Duration)
		Expect(microscopeCancel()).To(BeNil(), "cannot stop microscope")
	})

	AfterEach(func() {
		err := kubectl.WaitCleanAllTerminatingPods()
		Expect(err).To(BeNil(), "Terminating containers are not deleted after timeout")
	})

	Context("With Basic Application", func() {

		execPodContainer := func(ns, pod, container, cmd string) *helpers.CmdRes {
			return kubectl.Exec(fmt.Sprintf("%s -n %s exec -t %s -c %s -- %s",
				helpers.KubectlCmd, ns, pod, container, cmd))
		}

		var (
			clusterIP     string
			httpd1Service string = "httpd1-service"
			appPods       map[string]string
			apps          []string = []string{
				helpers.Httpd1, helpers.Httpd2, helpers.App1, helpers.App2, helpers.App3}
		)

		BeforeAll(func() {
			res := kubeInject(demoPath, "apply")
			res.ExpectSuccess("cannot install demo: %s", res.CombineOutput())

			err := kubectl.WaitforPods(helpers.DefaultNamespace, "-l zgroup=testapp", 300)
			Expect(err).Should(BeNil(), "Test pods are not ready after timeout")

			clusterIP, _, err = kubectl.GetServiceHostPort(helpers.DefaultNamespace, httpd1Service)
			Expect(err).To(BeNil(), "Cannot get service on %q namespace", helpers.DefaultNamespace)

			appPods = helpers.GetAppPods(apps, helpers.DefaultNamespace, kubectl, "id")
		})

		AfterAll(func() {
			res := kubeInject(demoPath, helpers.Delete)
			res.ExpectSuccess("cannot install demo: %s", res.CombineOutput())
		})

		It("Basic connectivity test", func() {
			res := execPodContainer(
				helpers.DefaultNamespace, appPods[helpers.App1], container,
				helpers.CurlFail("http://%s/public", clusterIP))
			res.ExpectSuccess("%q cannot curl clusterIP %q", appPods[helpers.App1], clusterIP)

			res = execPodContainer(
				helpers.DefaultNamespace, appPods[helpers.App2], container,
				helpers.CurlFail("http://%s/public", clusterIP))
			res.ExpectSuccess("%q cannot curl clusterIP %q", appPods[helpers.App2], clusterIP)
		})
	})
})

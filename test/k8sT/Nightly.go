// Copyright 2017-2018 Authors of Cilium
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
	"context"
	"fmt"
	"path"
	"strings"
	"time"

	"github.com/cilium/cilium/api/v1/models"
	. "github.com/cilium/cilium/test/ginkgo-ext"
	"github.com/cilium/cilium/test/helpers"
	"github.com/cilium/cilium/test/helpers/policygen"

	"github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/sirupsen/logrus"
)

var (
	endpointTimeout  int64 = 60
	timeout          int64 = 300
	netcatDsManifest       = "netcat-ds.yaml"
)

var _ = Describe("NightlyEpsMeasurement", func() {

	var kubectl *helpers.Kubectl

	endpointCount := 45
	endpointsTimeout := endpointTimeout * int64(endpointCount)
	manifestPath := "tmp.yaml"
	vagrantManifestPath := path.Join(helpers.BasePath, manifestPath)
	var err error

	BeforeAll(func() {
		kubectl = helpers.CreateKubectl(helpers.K8s1VMName(), logger)

		_ = kubectl.Apply(helpers.DNSDeployment())

		// Deploy the etcd operator
		err := kubectl.DeployETCDOperator()
		Expect(err).To(BeNil(), "Unable to deploy etcd operator")

		err = kubectl.CiliumInstall(helpers.CiliumDefaultDSPatch, helpers.CiliumConfigMapPatch)
		Expect(err).To(BeNil(), "Cilium cannot be installed")

		ExpectCiliumReady(kubectl)
		ExpectKubeDNSReady(kubectl)
		ExpectETCDOperatorReady(kubectl)
	})
	deleteAll := func() {
		ctx, cancel := context.WithTimeout(context.Background(), 300*time.Second)
		defer cancel()
		kubectl.ExecContext(ctx, fmt.Sprintf(
			"%s delete --all pods,svc,cnp -n %s --grace-period=0 --force",
			helpers.KubectlCmd, helpers.DefaultNamespace))

		select {
		case <-ctx.Done():
			logger.Error("DeleteAll: delete all pods,services failed after 300 seconds")
		}
	}
	AfterAll(func() {
		deleteAll()
		ExpectAllPodsTerminated(kubectl)
	})

	AfterFailed(func() {
		kubectl.CiliumReport(helpers.KubeSystemNamespace,
			"cilium service list",
			"cilium endpoint list")
	})

	JustAfterEach(func() {
		kubectl.ValidateNoErrorsOnLogs(CurrentGinkgoTestDescription().Duration)
	})

	AfterEach(func() {
		ExpectAllPodsTerminated(kubectl)

		kubectl.Delete(vagrantManifestPath)
		ExpectAllPodsTerminated(kubectl)
	})

	deployEndpoints := func() {
		_, _, err = helpers.GenerateManifestForEndpoints(endpointCount, manifestPath)
		ExpectWithOffset(1, err).Should(BeNil(), "Manifest cannot be created correctly")
		res := kubectl.Apply(vagrantManifestPath)
		res.ExpectSuccess("cannot apply eps manifest :%s", res.GetDebugMessage())
	}

	getServices := func() map[string]string {
		// getServices returns a map of services, where service name is the key
		// and the ClusterIP is the value.
		services, err := kubectl.Get(helpers.DefaultNamespace, fmt.Sprintf("services -l zgroup=testapp")).Filter(
			`{range .items[*]}{.metadata.name}{"="}{.spec.clusterIP}{"\n"}{end}`)
		ExpectWithOffset(1, err).To(BeNil(), "cannot retrieve testapp services")
		result := make(map[string]string)
		for _, line := range strings.Split(services.String(), "\n") {
			vals := strings.Split(line, "=")
			if len(vals) == 2 {
				result[vals[0]] = vals[1]
			}
		}
		return result
	}

	Measure("The endpoint creation", func(b ginkgo.Benchmarker) {
		desiredState := string(models.EndpointStateReady)

		deployEndpoints()
		waitForPodsTime := b.Time("Wait for pods", func() {
			err := kubectl.WaitforPods(helpers.DefaultNamespace, "-l zgroup=testapp", endpointTimeout)
			Expect(err).Should(BeNil(),
				"Cannot retrieve %d pods in %d seconds", endpointCount, endpointsTimeout)
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

		services := getServices()
		Expect(len(services)).To(BeNumerically(">", 0), "Was not able to get services")

		pods, err := kubectl.GetPodNames(helpers.DefaultNamespace, "zgroup=testapp")
		Expect(err).To(BeNil(), "cannot retrieve pods names")

		err = kubectl.WaitforPods(helpers.DefaultNamespace, "", 300)
		Expect(err).Should(BeNil(), "Pods are not ready after timeout")

		By("Testing if http requests to multiple endpoints do not timeout")
		for i := 0; i < 5; i++ {
			for _, pod := range pods {
				for service, ip := range services {
					b.Time("Curl to service", func() {

						res := kubectl.ExecPodCmd(
							helpers.DefaultNamespace, pod,
							helpers.CurlFail(fmt.Sprintf("http://%s:80/", ip)))
						res.ExpectSuccess(
							"Cannot curl from %s to service %s on  ip %s", pod, service, ip)
					})
				}

			}
		}

	}, 1)

	Context("Nightly Policies", func() {

		numPods := 20
		bunchPods := 5
		podsCreated := 0

		AfterEach(func() {
			deleteAll()
			ExpectAllPodsTerminated(kubectl)
		})

		Measure(fmt.Sprintf("Applying policies to %d pods in a group of %d", numPods, bunchPods), func(b ginkgo.Benchmarker) {
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
					err := kubectl.WaitforPods(helpers.DefaultNamespace, "-l test=policygen", 600)
					Expect(err).To(BeNil(), "Pods are not ready after timeout")
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

	Context("Test long live connections", func() {
		getServer := func(port string) string {
			return fmt.Sprintf("nc -p %s -lk -v", port)
		}

		getClient := func(ip, port, filePipe string) string {
			return fmt.Sprintf(
				"rm %[1]s; touch %[1]s; tail -f %[1]s 2>&1 | nc -v %[2]s %[3]s",
				filePipe, ip, port)
		}

		HTTPRequest := func(uid, host string) string {
			request := `GET /public HTTP/1.1\r\n` +
				`host: %s:8888\r\n` +
				`user-agent: curl/7.54.0\r\n` +
				`accept: */*\r\n` +
				`UID: %s\r\n` +
				`content-length: 0\r\n`
			return fmt.Sprintf(request, host, uid)
		}
		// testConnectivity check that nc is running across the k8s nodes
		testConnectivity := func() {

			pipePath := "/tmp/nc_pipe.txt"
			listeningString := "listening on [::]:8888"

			err := kubectl.WaitforPods(helpers.DefaultNamespace, "-l zgroup=netcatds", 600)
			Expect(err).To(BeNil(), "Pods are not ready after timeout")

			netcatPods, err := kubectl.GetPodNames(helpers.DefaultNamespace, "zgroup=netcatds")
			Expect(err).To(BeNil(), "Cannot get pods names for netcatds")
			Expect(len(netcatPods)).To(BeNumerically(">", 0), "Pods are not ready")

			server := netcatPods[0]
			client := netcatPods[1]
			ips, err := kubectl.GetPodsIPs(helpers.DefaultNamespace, "zgroup=netcatds")
			Expect(err).To(BeNil(), "Cannot get netcat ips")

			ncServer := getServer("8888")
			ncClient := getClient(ips[server], "8888", pipePath)

			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			serverctx := kubectl.ExecPodCmdContext(ctx, helpers.DefaultNamespace, server, ncServer)
			err = serverctx.WaitUntilMatch(listeningString)
			Expect(err).To(BeNil(), "netcat server did not start correctly")

			_ = kubectl.ExecPodCmdContext(ctx, helpers.DefaultNamespace, client, ncClient)

			testNcConnectivity := func(sleep time.Duration) {
				helpers.Sleep(sleep)
				uid := helpers.MakeUID()
				_ = kubectl.ExecPodCmd(helpers.DefaultNamespace, client,
					fmt.Sprintf(`echo -e "%s" >> %s`, HTTPRequest(uid, ips[client]), pipePath))
				Expect(serverctx.WaitUntilMatch(uid)).To(BeNil(),
					"%q is not in the server output after timeout", uid)
				serverctx.ExpectContains(uid, "Cannot get server UUID")
			}
			By("Testing that simple nc works")
			testNcConnectivity(1)

			By("Sleeping for a minute to check tcp-keepalive")
			testNcConnectivity(60)

			By("Sleeping for six  minutes to check tcp-keepalive")
			testNcConnectivity(360)
		}

		It("Test TCP Keepalive with L7 Policy", func() {
			kubectl.ValidateNoErrorsOnLogs(CurrentGinkgoTestDescription().Duration)
			manifest := helpers.ManifestGet(netcatDsManifest)
			kubectl.Apply(manifest).ExpectSuccess("Cannot apply netcat ds")
			defer kubectl.Delete(manifest)
			testConnectivity()
		})

		It("Test TCP Keepalive without L7 Policy", func() {
			manifest := helpers.ManifestGet(netcatDsManifest)
			kubectl.Apply(manifest).ExpectSuccess("Cannot apply netcat ds")
			defer kubectl.Delete(manifest)
			kubectl.Exec(fmt.Sprintf(
				"%s delete --all cnp -n %s", helpers.KubectlCmd, helpers.DefaultNamespace))
			testConnectivity()
		})
	})
})

var _ = Describe("NightlyExamples", func() {

	var kubectl *helpers.Kubectl
	var demoPath string
	var l3Policy, l7Policy string

	BeforeAll(func() {
		kubectl = helpers.CreateKubectl(helpers.K8s1VMName(), logger)

		demoPath = helpers.ManifestGet("demo.yaml")
		l3Policy = helpers.ManifestGet("l3-l4-policy.yaml")
		l7Policy = helpers.ManifestGet("l7-policy.yaml")
	})

	AfterFailed(func() {
		kubectl.CiliumReport(helpers.KubeSystemNamespace,
			"cilium service list",
			"cilium endpoint list")
	})

	JustAfterEach(func() {
		kubectl.ValidateNoErrorsOnLogs(CurrentGinkgoTestDescription().Duration)
	})

	AfterEach(func() {
		kubectl.Delete(demoPath)
		kubectl.Delete(l3Policy)
		kubectl.Delete(l7Policy)

		ExpectAllPodsTerminated(kubectl)
	})

	Context("Upgrade test", func() {
		var cleanupCallback = func() { return }

		BeforeEach(func() {
			// Delete kube-dns because if not will be a restore the old endpoints
			// from master instead of create the new ones.
			_ = kubectl.Delete(helpers.DNSDeployment())

			// Delete etcd operator because sometimes when install from
			// clean-state the quorum is lost.
			// ETCD operator maybe is not installed at all, so no assert here.
			_ = kubectl.DeleteETCDOperator()
			ExpectAllPodsTerminated(kubectl)

		})

		AfterEach(func() {
			cleanupCallback()
		})

		AfterAll(func() {
			_ = kubectl.Apply(helpers.DNSDeployment())
		})

		for _, image := range helpers.NightlyStableUpgradesFrom {
			func(version string) {
				It(fmt.Sprintf("Update Cilium from %s to master", version), func() {
					var assertUpgradeSuccessful func()
					assertUpgradeSuccessful, cleanupCallback = InstallAndValidateCiliumUpgrades(
						kubectl, image, helpers.CiliumDeveloperImage)
					assertUpgradeSuccessful()
				})
			}(image)
		}
	})

	Context("Getting started guides", func() {

		var (
			GRPCManifest = "../examples/kubernetes-grpc/cc-door-app.yaml"
			GRPCPolicy   = "../examples/kubernetes-grpc/cc-door-ingress-security.yaml"

			AppManifest    = helpers.GetFilePath(GRPCManifest)
			PolicyManifest = helpers.GetFilePath(GRPCPolicy)
		)

		BeforeAll(func() {
			_ = kubectl.Apply(helpers.DNSDeployment())

			// Deploy the etcd operator
			err := kubectl.DeployETCDOperator()
			Expect(err).To(BeNil(), "Unable to deploy etcd operator")

			err = kubectl.CiliumInstall(helpers.CiliumDefaultDSPatch, helpers.CiliumConfigMapPatch)
			Expect(err).To(BeNil(), "Cilium cannot be installed")

			ExpectCiliumReady(kubectl)
			ExpectKubeDNSReady(kubectl)
			ExpectETCDOperatorReady(kubectl)
		})

		AfterAll(func() {
			kubectl.Delete(AppManifest)
			kubectl.Delete(PolicyManifest)
			ExpectAllPodsTerminated(kubectl)
		})

		It("GRPC example", func() {

			clientPod := "terminal-87"

			By("Testing the example config")
			kubectl.Apply(AppManifest).ExpectSuccess("cannot install the GRPC application")

			err := kubectl.WaitforPods(helpers.DefaultNamespace, "-l zgroup=grpcExample", 300)
			Expect(err).Should(BeNil(), "Pods are not ready after timeout")

			res := kubectl.ExecPodCmd(
				helpers.DefaultNamespace, clientPod,
				"python3 /cloudcity/cc_door_client.py GetName 1")
			res.ExpectSuccess("Client cannot get Name")

			res = kubectl.ExecPodCmd(
				helpers.DefaultNamespace, clientPod,
				"python3 /cloudcity/cc_door_client.py GetLocation 1")
			res.ExpectSuccess("Client cannot get Location")

			res = kubectl.ExecPodCmd(
				helpers.DefaultNamespace, clientPod,
				"python3 /cloudcity/cc_door_client.py SetAccessCode 1 999")
			res.ExpectSuccess("Client cannot set Accesscode")

			By("Testing with L7 policy")
			_, err = kubectl.CiliumPolicyAction(
				helpers.KubeSystemNamespace, PolicyManifest,
				helpers.KubectlApply, 300)
			Expect(err).To(BeNil(), "Cannot import GPRC policy")

			res = kubectl.ExecPodCmd(
				helpers.DefaultNamespace, clientPod,
				"python3 /cloudcity/cc_door_client.py GetName 1")
			res.ExpectSuccess("Client cannot get Name")

			res = kubectl.ExecPodCmd(
				helpers.DefaultNamespace, clientPod,
				"python3 /cloudcity/cc_door_client.py GetLocation 1")
			res.ExpectSuccess("Client cannot get Location")

			res = kubectl.ExecPodCmd(
				helpers.DefaultNamespace, clientPod,
				"python3 /cloudcity/cc_door_client.py SetAccessCode 1 999")
			res.ExpectFail("Client can set Accesscode and it shoud not")
		})
	})
})

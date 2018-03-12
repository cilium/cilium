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
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path"
	"strings"
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
	configMap        = "ConfigMap"
	endpointTimeout  = (60 * time.Second)
	timeout          = time.Duration(300)
	netcatDsManifest = "netcat_ds.yaml"
)

var _ = Describe("NightlyEpsMeasurement", func() {

	var kubectl *helpers.Kubectl
	var logger *logrus.Entry
	var once sync.Once
	var ciliumPath string

	endpointCount := 45
	endpointsTimeout := endpointTimeout * time.Duration(endpointCount)
	manifestPath := "tmp.yaml"
	vagrantManifestPath := path.Join(helpers.BasePath, manifestPath)
	var lastServer int
	var err error

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

		// Sometimes PolicyGen has a lot of pods running around without delete
		// it. Using this we are sure that we delete before this test start
		kubectl.Exec(fmt.Sprintf(
			"%s delete --all pods,svc,cnp -n %s", helpers.KubectlCmd, helpers.DefaultNamespace))

		err = kubectl.WaitCleanAllTerminatingPods()
		Expect(err).To(BeNil(), "Terminating containers are not deleted after timeout")
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
		err := kubectl.WaitCleanAllTerminatingPods()
		Expect(err).To(BeNil(), "Terminating containers are not deleted after timeout")

		kubectl.Delete(vagrantManifestPath)
		kubectl.WaitCleanAllTerminatingPods()
	})

	deployEndpoints := func() {
		_, lastServer, err = helpers.GenerateManifestForEndpoints(endpointCount, manifestPath)
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

	Measure("The endpoint creation", func(b Benchmarker) {
		desiredState := string(models.EndpointStateReady)

		deployEndpoints()
		waitForPodsTime := b.Time("Wait for pods", func() {
			pods, err := kubectl.WaitforPods(helpers.DefaultNamespace, "-l zgroup=testapp", endpointTimeout)
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

		services := getServices()
		Expect(len(services)).To(BeNumerically(">", 0), "Was not able to get services")

		pods, err := kubectl.GetPodNames(helpers.DefaultNamespace, "zgroup=testapp")
		Expect(err).To(BeNil(), "cannot retrieve pods names")

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

	Context("Test long live connections", func() {
		getServer := func(port string) string {
			return fmt.Sprintf("nc -p %s -lk -v", port)
		}

		getClient := func(ip, port, filePipe string) string {
			return fmt.Sprintf(
				"rm %[1]s; touch %[1]s; tail -f %[1]s 2>&1 | nc -v %[2]s %[3]s",
				filePipe, ip, port)
		}

		HTTPRequest := func(uid string) string {
			request := `GET /public HTTP/1.1\r\n` +
				`host: 10.10.1.93:8888\r\n` +
				`user-agent: curl/7.54.0\r\n` +
				`accept: */*\r\n` +
				`UID: %s\r\n` +
				`content-length: 0\r\n`
			return fmt.Sprintf(request, uid)
		}
		// testConnectivity check that nc is running across the k8s nodes
		testConnectivity := func() {

			pipePath := "/tmp/nc_pipe.txt"

			_, err := kubectl.WaitforPods(helpers.DefaultNamespace, "-l zgroup=netcatds", 600)
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
			_ = kubectl.ExecPodCmdContext(ctx, helpers.DefaultNamespace, client, ncClient)

			testNcConnectivity := func(sleep time.Duration) {
				helpers.Sleep(sleep)
				uid := helpers.MakeUID()
				_ = kubectl.ExecPodCmd(helpers.DefaultNamespace, client,
					fmt.Sprintf(`echo -e "%s" >> %s`, HTTPRequest(uid), pipePath))
				helpers.Sleep(5) // Give time to fill the buffer in context.
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
			manifest := kubectl.ManifestGet(netcatDsManifest)
			kubectl.Apply(manifest).ExpectSuccess("Cannot apply netcat ds")
			defer kubectl.Delete(manifest)
			testConnectivity()
		})

		It("Test TCP Keepalive without L7 Policy", func() {
			manifest := kubectl.ManifestGet(netcatDsManifest)
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
	var logger *logrus.Entry
	var once sync.Once
	var ciliumPath string
	var demoPath string
	var l3Policy, l7Policy string
	var appService = "app1-service"
	var apps []string

	initialize := func() {
		logger = log.WithFields(logrus.Fields{"testName": "NightlyK8sEpsMeasurement"})
		logger.Info("Starting")

		kubectl = helpers.CreateKubectl(helpers.K8s1VMName(), logger)
		kubectl.Delete(ciliumPath)

		apps = []string{helpers.App1, helpers.App2, helpers.App3}

		demoPath = kubectl.ManifestGet("demo.yaml")
		l3Policy = kubectl.ManifestGet("l3_l4_policy.yaml")
		l7Policy = kubectl.ManifestGet("l7_policy.yaml")

		// Sometimes PolicyGen has a lot of pods running around without delete
		// it. Using this we are sure that we delete before this test start
		kubectl.Exec(fmt.Sprintf(
			"%s delete --all pods,svc,cnp -n %s", helpers.KubectlCmd, helpers.DefaultNamespace))

		err := kubectl.WaitCleanAllTerminatingPods()
		Expect(err).To(BeNil(), "Terminating containers are not deleted after timeout")
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

		kubectl.Delete(demoPath)
		kubectl.Delete(l3Policy)
		kubectl.Delete(l7Policy)

		err := kubectl.WaitCleanAllTerminatingPods()
		Expect(err).To(BeNil(), "Terminating containers are not deleted after timeout")
	})

	Context("Cilium DaemonSet from example", func() {

		// InstallExampleCilium uses Cilium Kubernetes example from the repo,
		// changes the etcd parameter and installs the stable tag from docker-hub
		InstallExampleCilium := func() {

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

			kubectl.Apply(helpers.GetFilePath(newCiliumDSName)).ExpectSuccess(
				"cannot apply cilium example daemonset")

			status, err := kubectl.WaitforPods(
				helpers.KubeSystemNamespace, "-l k8s-app=cilium", timeout)
			Expect(status).Should(BeTrue(), "Cilium is not ready after timeout")
			Expect(err).Should(BeNil(), "Cilium is not ready after timeout")
		}

		waitEndpointReady := func() {
			ciliumPods, err := kubectl.GetCiliumPods(helpers.KubeSystemNamespace)
			Expect(err).To(BeNil(), "cannot retrieve cilium pods")
			for _, pod := range ciliumPods {
				ExpectWithOffset(1, kubectl.CiliumEndpointWait(pod)).To(BeTrue(),
					"Pod %v is not ready", pod)
			}
		}

		AfterEach(func() {
			kubectl.Exec(fmt.Sprintf(
				"%s -n %s delete ds cilium",
				helpers.KubectlCmd, helpers.KubeSystemNamespace)).ExpectSuccess(
				"Cilium DS cannot be deleted")
		})

		BeforeEach(func() {
			kubectl.Exec("sudo docker rmi cilium/cilium")
			InstallExampleCilium()
		})

		It("Check Kubernetes Example is working correctly", func() {
			kubectl.Apply(demoPath).ExpectSuccess()
			_, err := kubectl.WaitforPods(helpers.DefaultNamespace, "-l zgroup=testapp", timeout)
			Expect(err).Should(BeNil())

			_, err = kubectl.CiliumPolicyAction(
				helpers.KubeSystemNamespace, l3Policy, helpers.KubectlApply, timeout)
			Expect(err).Should(BeNil())

			appPods := helpers.GetAppPods(apps, helpers.DefaultNamespace, kubectl, "id")

			clusterIP, _, err := kubectl.GetServiceHostPort(helpers.DefaultNamespace, appService)
			Expect(err).Should(BeNil())

			res := kubectl.ExecPodCmd(
				helpers.DefaultNamespace, appPods[helpers.App2],
				helpers.CurlFail(fmt.Sprintf("http://%s/public", clusterIP)))
			res.ExpectSuccess("Cannot curl to %q from %q", clusterIP, appPods[helpers.App2])

			res = kubectl.ExecPodCmd(
				helpers.DefaultNamespace, appPods[helpers.App3],
				helpers.CurlFail(fmt.Sprintf("http://%s/public", clusterIP)))
			res.ExpectFail("Can curl to %q from %q and it shouldn't",
				clusterIP, appPods[helpers.App3])

		})

		It("Updating Cilium stable to master", func() {
			By("Creating some endpoints and L7 policy")
			kubectl.Apply(demoPath).ExpectSuccess()
			_, err := kubectl.WaitforPods(helpers.DefaultNamespace, "-l zgroup=testapp", timeout)
			Expect(err).Should(BeNil())

			kubectl.Exec(fmt.Sprintf("%s scale deployment %s --replicas=10",
				helpers.KubectlCmd, helpers.App1)).ExpectSuccess(
				"Cannot scale %v deployment", helpers.App1)

			_, err = kubectl.CiliumPolicyAction(
				helpers.KubeSystemNamespace, l7Policy, helpers.KubectlApply, timeout)
			Expect(err).Should(BeNil(), "cannot import l7 policy: %v", l7Policy)

			waitEndpointReady()

			appPods := helpers.GetAppPods(apps, helpers.DefaultNamespace, kubectl, "id")

			res := kubectl.ExecPodCmd(
				helpers.DefaultNamespace, appPods[helpers.App2],
				helpers.CurlFail(fmt.Sprintf("http://app1-service/public")))
			res.ExpectSuccess("Cannot curl app1-service")

			By("Updating cilium to master image")

			localImage := "k8s1:5000/cilium/cilium-dev"
			resource := "daemonset/cilium"

			kubectl.Exec(fmt.Sprintf("%s -n %s set image %s cilium-agent=%s",
				helpers.KubectlCmd, helpers.KubeSystemNamespace,
				resource, localImage)).ExpectSuccess(
				"Cannot update image")

			kubectl.Exec(fmt.Sprintf("%s rollout status %s -n %s",
				helpers.KubectlCmd, resource,
				helpers.KubeSystemNamespace)).ExpectSuccess("Cannot rollout the change")

			waitForUpdateImage := func() bool {
				pods, err := kubectl.GetCiliumPods(helpers.KubeSystemNamespace)
				if err != nil {
					return false
				}

				filter := `{.items[*].status.containerStatuses[0].image}`
				data, err := kubectl.GetPods(
					helpers.KubeSystemNamespace, "-l k8s-app=cilium").Filter(filter)
				if err != nil {
					return false
				}
				number := strings.Count(data.String(), localImage)
				if number == len(pods) {
					return true
				}
				logger.Infof("Only '%v' of '%v' cilium pods updated to the new image",
					number, len(pods))
				return false
			}

			err = helpers.WithTimeout(
				waitForUpdateImage,
				"Cilium Pods are not updating correctly",
				&helpers.TimeoutConfig{Timeout: timeout})
			Expect(err).To(BeNil(), "Pods are not updating")

			status, err := kubectl.WaitforPods(
				helpers.KubeSystemNamespace, "-l k8s-app=cilium", timeout)
			Expect(status).Should(BeTrue(), "Cilium is not ready after timeout")
			Expect(err).Should(BeNil(), "Cilium is not ready after timeout")

			res = kubectl.ExecPodCmd(
				helpers.DefaultNamespace, appPods[helpers.App2],
				helpers.CurlFail(fmt.Sprintf("http://app1-service/public")))
			res.ExpectSuccess("Cannot curl service after update")
		})
	})

	Context("Getting started guides", func() {

		var (
			GRPCManifest = "../examples/kubernetes-grpc/cc-door-app.yaml"
			GRPCPolicy   = "../examples/kubernetes-grpc/cc-door-ingress-security.yaml"
		)

		BeforeEach(func() {
			path := kubectl.ManifestGet("cilium_ds.yaml")
			kubectl.Apply(path)
			_, err := kubectl.WaitforPods(helpers.KubeSystemNamespace, "-l k8s-app=cilium", 600)
			Expect(err).Should(BeNil())

			err = kubectl.WaitKubeDNS()
			Expect(err).Should(BeNil())
		})

		AfterEach(func() {
			err := kubectl.WaitCleanAllTerminatingPods()
			Expect(err).To(BeNil(), "cannot clean all terminating pods")
		})

		It("GRPC example", func() {

			AppManifest := helpers.GetFilePath(GRPCManifest)
			PolicyManifest := helpers.GetFilePath(GRPCPolicy)
			clientPod := "terminal-87"

			defer func() {
				kubectl.Delete(AppManifest)
				kubectl.Delete(PolicyManifest)
			}()

			By("Testing the example config")
			kubectl.Apply(AppManifest).ExpectSuccess("cannot install the GRPC application")

			_, err := kubectl.WaitforPods(helpers.DefaultNamespace, "-l zgroup=grpcExample", 300)
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
				helpers.DefaultNamespace, PolicyManifest,
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

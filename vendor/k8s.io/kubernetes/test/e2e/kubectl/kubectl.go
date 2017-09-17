/*
Copyright 2015 The Kubernetes Authors.

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

// OWNER = sig/cli

package kubectl

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"mime/multipart"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"text/template"
	"time"

	"github.com/elazarl/goproxy"
	"github.com/ghodss/yaml"

	"k8s.io/api/core/v1"
	rbacv1beta1 "k8s.io/api/rbac/v1beta1"
	apierrs "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime/schema"
	utilnet "k8s.io/apimachinery/pkg/util/net"
	"k8s.io/apimachinery/pkg/util/uuid"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/apiserver/pkg/authentication/serviceaccount"
	genericregistry "k8s.io/apiserver/pkg/registry/generic/registry"
	clientset "k8s.io/client-go/kubernetes"
	"k8s.io/kubernetes/pkg/controller"
	"k8s.io/kubernetes/pkg/kubectl/cmd/util"
	utilversion "k8s.io/kubernetes/pkg/util/version"
	"k8s.io/kubernetes/test/e2e/framework"
	"k8s.io/kubernetes/test/e2e/generated"
	"k8s.io/kubernetes/test/e2e/scheduling"
	testutils "k8s.io/kubernetes/test/utils"
	uexec "k8s.io/utils/exec"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	imageutils "k8s.io/kubernetes/test/utils/image"
)

const (
	updateDemoSelector       = "name=update-demo"
	guestbookStartupTimeout  = 10 * time.Minute
	guestbookResponseTimeout = 3 * time.Minute
	simplePodSelector        = "name=nginx"
	simplePodName            = "nginx"
	nginxDefaultOutput       = "Welcome to nginx!"
	simplePodPort            = 80
	pausePodSelector         = "name=pause"
	pausePodName             = "pause"
	runJobTimeout            = 5 * time.Minute
	kubeCtlManifestPath      = "test/e2e/testing-manifests/kubectl"
	redisControllerFilename  = "redis-master-controller.json.in"
	redisServiceFilename     = "redis-master-service.json"
	nginxDeployment1Filename = "nginx-deployment1.yaml.in"
	nginxDeployment2Filename = "nginx-deployment2.yaml.in"
	nginxDeployment3Filename = "nginx-deployment3.yaml.in"
)

var (
	nautilusImage = imageutils.GetE2EImage(imageutils.Nautilus)
	kittenImage   = imageutils.GetE2EImage(imageutils.Kitten)
	redisImage    = imageutils.GetE2EImage(imageutils.Redis)
	nginxImage    = imageutils.GetE2EImage(imageutils.NginxSlim)
	busyboxImage  = imageutils.GetBusyBoxImage()
)

var testImages = struct {
	FrontendImage     string
	PauseImage        string
	NginxSlimImage    string
	NginxSlimNewImage string
	RedisImage        string
	RedisslaveImage   string
	NautilusImage     string
	KittenImage       string
}{
	imageutils.GetE2EImage(imageutils.Frontend),
	imageutils.GetE2EImage(imageutils.Pause),
	imageutils.GetE2EImage(imageutils.NginxSlim),
	imageutils.GetE2EImage(imageutils.NginxSlimNew),
	imageutils.GetE2EImage(imageutils.Redis),
	imageutils.GetE2EImage(imageutils.Redisslave),
	imageutils.GetE2EImage(imageutils.Nautilus),
	imageutils.GetE2EImage(imageutils.Kitten),
}
var (
	proxyRegexp = regexp.MustCompile("Starting to serve on 127.0.0.1:([0-9]+)")

	// Extended pod logging options were introduced in #13780 (v1.1.0) so we don't expect tests
	// that rely on extended pod logging options to work on clusters before that.
	//
	// TODO(ihmccreery): remove once we don't care about v1.0 anymore, (tentatively in v1.3).
	extendedPodLogFilterVersion = utilversion.MustParseSemantic("v1.1.0")

	// NodePorts were made optional in #12831 (v1.1.0) so we don't expect tests that used to
	// require NodePorts but no longer include them to work on clusters before that.
	//
	// TODO(ihmccreery): remove once we don't care about v1.0 anymore, (tentatively in v1.3).
	nodePortsOptionalVersion = utilversion.MustParseSemantic("v1.1.0")

	// Jobs were introduced in v1.1, so we don't expect tests that rely on jobs to work on
	// clusters before that.
	//
	// TODO(ihmccreery): remove once we don't care about v1.0 anymore, (tentatively in v1.3).
	jobsVersion = utilversion.MustParseSemantic("v1.1.0")

	// Deployments were introduced by default in v1.2, so we don't expect tests that rely on
	// deployments to work on clusters before that.
	//
	// TODO(ihmccreery): remove once we don't care about v1.1 anymore, (tentatively in v1.4).
	deploymentsVersion = utilversion.MustParseSemantic("v1.2.0-alpha.7.726")

	// Pod probe parameters were introduced in #15967 (v1.2) so we don't expect tests that use
	// these probe parameters to work on clusters before that.
	//
	// TODO(ihmccreery): remove once we don't care about v1.1 anymore, (tentatively in v1.4).
	podProbeParametersVersion = utilversion.MustParseSemantic("v1.2.0-alpha.4")

	// 'kubectl create quota' was introduced in #28351 (v1.4) so we don't expect tests that use
	// 'kubectl create quota' to work on kubectl clients before that.
	kubectlCreateQuotaVersion = utilversion.MustParseSemantic("v1.4.0-alpha.2")

	// Returning container command exit codes in kubectl run/exec was introduced in #26541 (v1.4)
	// so we don't expect tests that verifies return code to work on kubectl clients before that.
	kubectlContainerExitCodeVersion = utilversion.MustParseSemantic("v1.4.0-alpha.3")

	CronJobGroupVersionResourceAlpha = schema.GroupVersionResource{Group: "batch", Version: "v2alpha1", Resource: "cronjobs"}
	CronJobGroupVersionResourceBeta  = schema.GroupVersionResource{Group: "batch", Version: "v1beta1", Resource: "cronjobs"}
)

// Stops everything from filePath from namespace ns and checks if everything matching selectors from the given namespace is correctly stopped.
// Aware of the kubectl example files map.
func cleanupKubectlInputs(fileContents string, ns string, selectors ...string) {
	By("using delete to clean up resources")
	var nsArg string
	if ns != "" {
		nsArg = fmt.Sprintf("--namespace=%s", ns)
	}
	// support backward compatibility : file paths or raw json - since we are removing file path
	// dependencies from this test.
	framework.RunKubectlOrDieInput(fileContents, "delete", "--grace-period=0", "--force", "-f", "-", nsArg)
	framework.AssertCleanup(ns, selectors...)
}

func substituteImageName(content string) string {
	contentWithImageName := new(bytes.Buffer)
	tmpl, err := template.New("imagemanifest").Parse(content)
	if err != nil {
		framework.Failf("Failed Parse the template:", err)
	}
	err = tmpl.Execute(contentWithImageName, testImages)
	if err != nil {
		framework.Failf("Failed executing template:", err)
	}
	return contentWithImageName.String()
}

func readTestFileOrDie(file string) []byte {
	return generated.ReadOrDie(path.Join(kubeCtlManifestPath, file))
}

func runKubectlRetryOrDie(args ...string) string {
	var err error
	var output string
	for i := 0; i < 5; i++ {
		output, err = framework.RunKubectl(args...)
		if err == nil || (!strings.Contains(err.Error(), genericregistry.OptimisticLockErrorMsg) && !strings.Contains(err.Error(), "Operation cannot be fulfilled")) {
			break
		}
		time.Sleep(time.Second)
	}
	// Expect no errors to be present after retries are finished
	// Copied from framework #ExecOrDie
	framework.Logf("stdout: %q", output)
	Expect(err).NotTo(HaveOccurred())
	return output
}

// duplicated setup to avoid polluting "normal" clients with alpha features which confuses the generated clients
var _ = SIGDescribe("Kubectl alpha client", func() {
	defer GinkgoRecover()
	f := framework.NewDefaultFramework("kubectl")

	var c clientset.Interface
	var ns string
	BeforeEach(func() {
		c = f.ClientSet
		ns = f.Namespace.Name
	})

	// Customized Wait  / ForEach wrapper for this test.  These demonstrate the

	framework.KubeDescribe("Kubectl run CronJob", func() {
		var nsFlag string
		var cjName string

		BeforeEach(func() {
			nsFlag = fmt.Sprintf("--namespace=%v", ns)
			cjName = "e2e-test-echo-cronjob-alpha"
		})

		AfterEach(func() {
			framework.RunKubectlOrDie("delete", "cronjob.v2alpha1.batch", cjName, nsFlag)
		})

		It("should create a CronJob", func() {
			framework.SkipIfMissingResource(f.ClientPool, CronJobGroupVersionResourceAlpha, f.Namespace.Name)

			schedule := "*/5 * * * ?"
			framework.RunKubectlOrDie("run", cjName, "--restart=OnFailure", "--generator=cronjob/v2alpha1",
				"--schedule="+schedule, "--image="+busyboxImage, nsFlag)
			By("verifying the CronJob " + cjName + " was created")
			sj, err := c.BatchV1beta1().CronJobs(ns).Get(cjName, metav1.GetOptions{})
			if err != nil {
				framework.Failf("Failed getting CronJob %s: %v", cjName, err)
			}
			if sj.Spec.Schedule != schedule {
				framework.Failf("Failed creating a CronJob with correct schedule %s", schedule)
			}
			containers := sj.Spec.JobTemplate.Spec.Template.Spec.Containers
			if containers == nil || len(containers) != 1 || containers[0].Image != busyboxImage {
				framework.Failf("Failed creating CronJob %s for 1 pod with expected image %s: %#v", cjName, busyboxImage, containers)
			}
			if sj.Spec.JobTemplate.Spec.Template.Spec.RestartPolicy != v1.RestartPolicyOnFailure {
				framework.Failf("Failed creating a CronJob with correct restart policy for --restart=OnFailure")
			}
		})
	})
})

var _ = SIGDescribe("Kubectl client", func() {
	defer GinkgoRecover()
	f := framework.NewDefaultFramework("kubectl")

	// Reusable cluster state function.  This won't be adversely affected by lazy initialization of framework.
	clusterState := func() *framework.ClusterVerification {
		return f.NewClusterVerification(
			f.Namespace,
			framework.PodStateVerification{
				Selectors:   map[string]string{"app": "redis"},
				ValidPhases: []v1.PodPhase{v1.PodRunning /*v1.PodPending*/},
			})
	}
	forEachPod := func(podFunc func(p v1.Pod)) {
		clusterState().ForEach(podFunc)
	}
	var c clientset.Interface
	var ns string
	BeforeEach(func() {
		c = f.ClientSet
		ns = f.Namespace.Name
	})

	// Customized Wait  / ForEach wrapper for this test.  These demonstrate the
	// idiomatic way to wrap the ClusterVerification structs for syntactic sugar in large
	// test files.
	// Print debug info if atLeast Pods are not found before the timeout
	waitForOrFailWithDebug := func(atLeast int) {
		pods, err := clusterState().WaitFor(atLeast, framework.PodStartTimeout)
		if err != nil || len(pods) < atLeast {
			// TODO: Generalize integrating debug info into these tests so we always get debug info when we need it
			framework.DumpAllNamespaceInfo(f.ClientSet, ns)
			framework.Failf("Verified %v of %v pods , error : %v", len(pods), atLeast, err)
		}
	}

	framework.KubeDescribe("Update Demo", func() {
		var nautilus, kitten string
		BeforeEach(func() {
			updateDemoRoot := "test/fixtures/doc-yaml/user-guide/update-demo"
			nautilus = substituteImageName(string(generated.ReadOrDie(filepath.Join(updateDemoRoot, "nautilus-rc.yaml.in"))))
			kitten = substituteImageName(string(generated.ReadOrDie(filepath.Join(updateDemoRoot, "kitten-rc.yaml.in"))))
		})
		It("should create and stop a replication controller [Conformance]", func() {
			defer cleanupKubectlInputs(nautilus, ns, updateDemoSelector)

			By("creating a replication controller")
			framework.RunKubectlOrDieInput(nautilus, "create", "-f", "-", fmt.Sprintf("--namespace=%v", ns))
			framework.ValidateController(c, nautilusImage, 2, "update-demo", updateDemoSelector, getUDData("nautilus.jpg", ns), ns)
		})

		It("should scale a replication controller [Conformance]", func() {
			defer cleanupKubectlInputs(nautilus, ns, updateDemoSelector)

			By("creating a replication controller")
			framework.RunKubectlOrDieInput(nautilus, "create", "-f", "-", fmt.Sprintf("--namespace=%v", ns))
			framework.ValidateController(c, nautilusImage, 2, "update-demo", updateDemoSelector, getUDData("nautilus.jpg", ns), ns)
			By("scaling down the replication controller")
			framework.RunKubectlOrDie("scale", "rc", "update-demo-nautilus", "--replicas=1", "--timeout=5m", fmt.Sprintf("--namespace=%v", ns))
			framework.ValidateController(c, nautilusImage, 1, "update-demo", updateDemoSelector, getUDData("nautilus.jpg", ns), ns)
			By("scaling up the replication controller")
			framework.RunKubectlOrDie("scale", "rc", "update-demo-nautilus", "--replicas=2", "--timeout=5m", fmt.Sprintf("--namespace=%v", ns))
			framework.ValidateController(c, nautilusImage, 2, "update-demo", updateDemoSelector, getUDData("nautilus.jpg", ns), ns)
		})

		It("should do a rolling update of a replication controller [Conformance]", func() {
			By("creating the initial replication controller")
			framework.RunKubectlOrDieInput(string(nautilus[:]), "create", "-f", "-", fmt.Sprintf("--namespace=%v", ns))
			framework.ValidateController(c, nautilusImage, 2, "update-demo", updateDemoSelector, getUDData("nautilus.jpg", ns), ns)
			By("rolling-update to new replication controller")
			framework.RunKubectlOrDieInput(string(kitten[:]), "rolling-update", "update-demo-nautilus", "--update-period=1s", "-f", "-", fmt.Sprintf("--namespace=%v", ns))
			framework.ValidateController(c, kittenImage, 2, "update-demo", updateDemoSelector, getUDData("kitten.jpg", ns), ns)
			// Everything will hopefully be cleaned up when the namespace is deleted.
		})
	})

	framework.KubeDescribe("Guestbook application", func() {
		forEachGBFile := func(run func(s string)) {
			for _, gbAppFile := range []string{
				"examples/guestbook/frontend-deployment.yaml",
				"examples/guestbook/frontend-service.yaml",
				"examples/guestbook/redis-master-deployment.yaml",
				"examples/guestbook/redis-master-service.yaml",
				"examples/guestbook/redis-slave-deployment.yaml",
				"examples/guestbook/redis-slave-service.yaml",
			} {
				contents := generated.ReadOrDie(gbAppFile)
				run(string(contents))
			}
		}

		It("should create and stop a working application [Conformance]", func() {
			framework.SkipUnlessServerVersionGTE(deploymentsVersion, c.Discovery())

			defer forEachGBFile(func(contents string) {
				cleanupKubectlInputs(contents, ns)
			})
			By("creating all guestbook components")
			forEachGBFile(func(contents string) {
				framework.Logf(contents)
				framework.RunKubectlOrDieInput(contents, "create", "-f", "-", fmt.Sprintf("--namespace=%v", ns))
			})

			By("validating guestbook app")
			validateGuestbookApp(c, ns)
		})
	})

	framework.KubeDescribe("Simple pod", func() {
		podYaml := substituteImageName(string(readTestFileOrDie("pod-with-readiness-probe.yaml.in")))
		BeforeEach(func() {
			By(fmt.Sprintf("creating the pod from %v", podYaml))
			framework.RunKubectlOrDieInput(podYaml, "create", "-f", "-", fmt.Sprintf("--namespace=%v", ns))
			Expect(framework.CheckPodsRunningReady(c, ns, []string{simplePodName}, framework.PodStartTimeout)).To(BeTrue())
		})
		AfterEach(func() {
			cleanupKubectlInputs(podYaml, ns, simplePodSelector)
		})

		It("should support exec", func() {
			By("executing a command in the container")
			execOutput := framework.RunKubectlOrDie("exec", fmt.Sprintf("--namespace=%v", ns), simplePodName, "echo", "running", "in", "container")
			if e, a := "running in container", strings.TrimSpace(execOutput); e != a {
				framework.Failf("Unexpected kubectl exec output. Wanted %q, got %q", e, a)
			}

			By("executing a very long command in the container")
			veryLongData := make([]rune, 20000)
			for i := 0; i < len(veryLongData); i++ {
				veryLongData[i] = 'a'
			}
			execOutput = framework.RunKubectlOrDie("exec", fmt.Sprintf("--namespace=%v", ns), simplePodName, "echo", string(veryLongData))
			Expect(string(veryLongData)).To(Equal(strings.TrimSpace(execOutput)), "Unexpected kubectl exec output")

			By("executing a command in the container with noninteractive stdin")
			execOutput = framework.NewKubectlCommand("exec", fmt.Sprintf("--namespace=%v", ns), "-i", simplePodName, "cat").
				WithStdinData("abcd1234").
				ExecOrDie()
			if e, a := "abcd1234", execOutput; e != a {
				framework.Failf("Unexpected kubectl exec output. Wanted %q, got %q", e, a)
			}

			// pretend that we're a user in an interactive shell
			r, closer, err := newBlockingReader("echo hi\nexit\n")
			if err != nil {
				framework.Failf("Error creating blocking reader: %v", err)
			}
			// NOTE this is solely for test cleanup!
			defer closer.Close()

			By("executing a command in the container with pseudo-interactive stdin")
			execOutput = framework.NewKubectlCommand("exec", fmt.Sprintf("--namespace=%v", ns), "-i", simplePodName, "bash").
				WithStdinReader(r).
				ExecOrDie()
			if e, a := "hi", strings.TrimSpace(execOutput); e != a {
				framework.Failf("Unexpected kubectl exec output. Wanted %q, got %q", e, a)
			}
		})

		It("should support exec through an HTTP proxy", func() {
			// Fail if the variable isn't set
			if framework.TestContext.Host == "" {
				framework.Failf("--host variable must be set to the full URI to the api server on e2e run.")
			}

			By("Starting goproxy")
			testSrv, proxyLogs := startLocalProxy()
			defer testSrv.Close()
			proxyAddr := testSrv.URL

			for _, proxyVar := range []string{"https_proxy", "HTTPS_PROXY"} {
				proxyLogs.Reset()
				By("Running kubectl via an HTTP proxy using " + proxyVar)
				output := framework.NewKubectlCommand(fmt.Sprintf("--namespace=%s", ns), "exec", "nginx", "echo", "running", "in", "container").
					WithEnv(append(os.Environ(), fmt.Sprintf("%s=%s", proxyVar, proxyAddr))).
					ExecOrDie()

				// Verify we got the normal output captured by the exec server
				expectedExecOutput := "running in container\n"
				if output != expectedExecOutput {
					framework.Failf("Unexpected kubectl exec output. Wanted %q, got  %q", expectedExecOutput, output)
				}

				// Verify the proxy server logs saw the connection
				expectedProxyLog := fmt.Sprintf("Accepting CONNECT to %s", strings.TrimRight(strings.TrimLeft(framework.TestContext.Host, "https://"), "/api"))

				proxyLog := proxyLogs.String()
				if !strings.Contains(proxyLog, expectedProxyLog) {
					framework.Failf("Missing expected log result on proxy server for %s. Expected: %q, got %q", proxyVar, expectedProxyLog, proxyLog)
				}
			}
		})

		It("should support exec through kubectl proxy", func() {
			// Fail if the variable isn't set
			if framework.TestContext.Host == "" {
				framework.Failf("--host variable must be set to the full URI to the api server on e2e run.")
			}

			By("Starting kubectl proxy")
			port, proxyCmd, err := startProxyServer()
			framework.ExpectNoError(err)
			defer framework.TryKill(proxyCmd)

			//proxyLogs.Reset()
			host := fmt.Sprintf("--server=http://127.0.0.1:%d", port)
			By("Running kubectl via kubectl proxy using " + host)
			output := framework.NewKubectlCommand(
				host, fmt.Sprintf("--namespace=%s", ns),
				"exec", "nginx", "echo", "running", "in", "container",
			).ExecOrDie()

			// Verify we got the normal output captured by the exec server
			expectedExecOutput := "running in container\n"
			if output != expectedExecOutput {
				framework.Failf("Unexpected kubectl exec output. Wanted %q, got  %q", expectedExecOutput, output)
			}
		})

		It("should return command exit codes", func() {
			framework.SkipUnlessKubectlVersionGTE(kubectlContainerExitCodeVersion)
			nsFlag := fmt.Sprintf("--namespace=%v", ns)

			By("execing into a container with a successful command")
			_, err := framework.NewKubectlCommand(nsFlag, "exec", "nginx", "--", "/bin/sh", "-c", "exit 0").Exec()
			framework.ExpectNoError(err)

			By("execing into a container with a failing command")
			_, err = framework.NewKubectlCommand(nsFlag, "exec", "nginx", "--", "/bin/sh", "-c", "exit 42").Exec()
			ee, ok := err.(uexec.ExitError)
			Expect(ok).To(Equal(true))
			Expect(ee.ExitStatus()).To(Equal(42))

			By("running a successful command")
			_, err = framework.NewKubectlCommand(nsFlag, "run", "-i", "--image="+busyboxImage, "--restart=Never", "success", "--", "/bin/sh", "-c", "exit 0").Exec()
			framework.ExpectNoError(err)

			By("running a failing command")
			_, err = framework.NewKubectlCommand(nsFlag, "run", "-i", "--image="+busyboxImage, "--restart=Never", "failure-1", "--", "/bin/sh", "-c", "exit 42").Exec()
			ee, ok = err.(uexec.ExitError)
			Expect(ok).To(Equal(true))
			Expect(ee.ExitStatus()).To(Equal(42))

			By("running a failing command without --restart=Never")
			_, err = framework.NewKubectlCommand(nsFlag, "run", "-i", "--image="+busyboxImage, "--restart=OnFailure", "failure-2", "--", "/bin/sh", "-c", "cat && exit 42").
				WithStdinData("abcd1234").
				Exec()
			framework.ExpectNoError(err)

			By("running a failing command without --restart=Never, but with --rm")
			_, err = framework.NewKubectlCommand(nsFlag, "run", "-i", "--image="+busyboxImage, "--restart=OnFailure", "--rm", "failure-3", "--", "/bin/sh", "-c", "cat && exit 42").
				WithStdinData("abcd1234").
				Exec()
			framework.ExpectNoError(err)
			framework.WaitForPodToDisappear(f.ClientSet, ns, "failure-3", labels.Everything(), 2*time.Second, wait.ForeverTestTimeout)

			By("running a failing command with --leave-stdin-open")
			_, err = framework.NewKubectlCommand(nsFlag, "run", "-i", "--image="+busyboxImage, "--restart=Never", "failure-4", "--leave-stdin-open", "--", "/bin/sh", "-c", "exit 42").
				WithStdinData("abcd1234").
				Exec()
			framework.ExpectNoError(err)
		})

		It("should support inline execution and attach", func() {
			framework.SkipIfContainerRuntimeIs("rkt") // #23335
			framework.SkipUnlessServerVersionGTE(jobsVersion, c.Discovery())

			nsFlag := fmt.Sprintf("--namespace=%v", ns)

			By("executing a command with run and attach with stdin")
			runOutput := framework.NewKubectlCommand(nsFlag, "run", "run-test", "--image="+busyboxImage, "--restart=OnFailure", "--attach=true", "--stdin", "--", "sh", "-c", "cat && echo 'stdin closed'").
				WithStdinData("abcd1234").
				ExecOrDie()
			Expect(runOutput).To(ContainSubstring("abcd1234"))
			Expect(runOutput).To(ContainSubstring("stdin closed"))
			Expect(c.Batch().Jobs(ns).Delete("run-test", nil)).To(BeNil())

			By("executing a command with run and attach without stdin")
			runOutput = framework.NewKubectlCommand(fmt.Sprintf("--namespace=%v", ns), "run", "run-test-2", "--image="+busyboxImage, "--restart=OnFailure", "--attach=true", "--leave-stdin-open=true", "--", "sh", "-c", "cat && echo 'stdin closed'").
				WithStdinData("abcd1234").
				ExecOrDie()
			Expect(runOutput).ToNot(ContainSubstring("abcd1234"))
			Expect(runOutput).To(ContainSubstring("stdin closed"))
			Expect(c.Batch().Jobs(ns).Delete("run-test-2", nil)).To(BeNil())

			By("executing a command with run and attach with stdin with open stdin should remain running")
			runOutput = framework.NewKubectlCommand(nsFlag, "run", "run-test-3", "--image="+busyboxImage, "--restart=OnFailure", "--attach=true", "--leave-stdin-open=true", "--stdin", "--", "sh", "-c", "cat && echo 'stdin closed'").
				WithStdinData("abcd1234\n").
				ExecOrDie()
			Expect(runOutput).ToNot(ContainSubstring("stdin closed"))
			g := func(pods []*v1.Pod) sort.Interface { return sort.Reverse(controller.ActivePods(pods)) }
			runTestPod, _, err := util.GetFirstPod(f.InternalClientset.Core(), ns, labels.SelectorFromSet(map[string]string{"run": "run-test-3"}), 1*time.Minute, g)
			if err != nil {
				os.Exit(1)
			}
			if !framework.CheckPodsRunningReady(c, ns, []string{runTestPod.Name}, time.Minute) {
				framework.Failf("Pod %q of Job %q should still be running", runTestPod.Name, "run-test-3")
			}

			// NOTE: we cannot guarantee our output showed up in the container logs before stdin was closed, so we have
			// to loop test.
			err = wait.PollImmediate(time.Second, time.Minute, func() (bool, error) {
				if !framework.CheckPodsRunningReady(c, ns, []string{runTestPod.Name}, 1*time.Second) {
					framework.Failf("Pod %q of Job %q should still be running", runTestPod.Name, "run-test-3")
				}
				logOutput := framework.RunKubectlOrDie(nsFlag, "logs", runTestPod.Name)
				Expect(logOutput).ToNot(ContainSubstring("stdin closed"))
				return strings.Contains(logOutput, "abcd1234"), nil
			})
			if err != nil {
				os.Exit(1)
			}
			Expect(err).To(BeNil())

			Expect(c.Batch().Jobs(ns).Delete("run-test-3", nil)).To(BeNil())
		})

		It("should support port-forward", func() {
			By("forwarding the container port to a local port")
			cmd := runPortForward(ns, simplePodName, simplePodPort)
			defer cmd.Stop()

			By("curling local port output")
			localAddr := fmt.Sprintf("http://localhost:%d", cmd.port)
			body, err := curl(localAddr)
			framework.Logf("got: %s", body)
			if err != nil {
				framework.Failf("Failed http.Get of forwarded port (%s): %v", localAddr, err)
			}
			if !strings.Contains(body, nginxDefaultOutput) {
				framework.Failf("Container port output missing expected value. Wanted:'%s', got: %s", nginxDefaultOutput, body)
			}
		})

		It("should handle in-cluster config", func() {
			By("adding rbac permissions")
			// grant the view permission widely to allow inspection of the `invalid` namespace and the default namespace
			framework.BindClusterRole(f.ClientSet.RbacV1beta1(), "view", f.Namespace.Name,
				rbacv1beta1.Subject{Kind: rbacv1beta1.ServiceAccountKind, Namespace: f.Namespace.Name, Name: "default"})

			err := framework.WaitForAuthorizationUpdate(f.ClientSet.AuthorizationV1beta1(),
				serviceaccount.MakeUsername(f.Namespace.Name, "default"),
				f.Namespace.Name, "list", schema.GroupResource{Resource: "pods"}, true)
			framework.ExpectNoError(err)

			By("overriding icc with values provided by flags")
			kubectlPath := framework.TestContext.KubectlPath
			// we need the actual kubectl binary, not the script wrapper
			kubectlPathNormalizer := exec.Command("which", kubectlPath)
			if strings.HasSuffix(kubectlPath, "kubectl.sh") {
				kubectlPathNormalizer = exec.Command(kubectlPath, "path")
			}
			kubectlPathNormalized, err := kubectlPathNormalizer.Output()
			framework.ExpectNoError(err)
			kubectlPath = strings.TrimSpace(string(kubectlPathNormalized))

			inClusterHost := strings.TrimSpace(framework.RunHostCmdOrDie(ns, simplePodName, "printenv KUBERNETES_SERVICE_HOST"))
			inClusterPort := strings.TrimSpace(framework.RunHostCmdOrDie(ns, simplePodName, "printenv KUBERNETES_SERVICE_PORT"))

			framework.Logf("copying %s to the %s pod", kubectlPath, simplePodName)
			framework.RunKubectlOrDie("cp", kubectlPath, ns+"/"+simplePodName+":/tmp/")

			// Build a kubeconfig file that will make use of the injected ca and token,
			// but point at the DNS host and the default namespace
			tmpDir, err := ioutil.TempDir("", "icc-override")
			overrideKubeconfigName := "icc-override.kubeconfig"
			framework.ExpectNoError(err)
			defer func() { os.Remove(tmpDir) }()
			framework.ExpectNoError(ioutil.WriteFile(filepath.Join(tmpDir, overrideKubeconfigName), []byte(`
kind: Config
apiVersion: v1
clusters:
- cluster:
    api-version: v1
    server: https://kubernetes.default.svc:443
    certificate-authority: /var/run/secrets/kubernetes.io/serviceaccount/ca.crt
  name: kubeconfig-cluster
contexts:
- context:
    cluster: kubeconfig-cluster
    namespace: default
    user: kubeconfig-user
  name: kubeconfig-context
current-context: kubeconfig-context
users:
- name: kubeconfig-user
  user:
    tokenFile: /var/run/secrets/kubernetes.io/serviceaccount/token
`), os.FileMode(0755)))
			framework.Logf("copying override kubeconfig to the %s pod", simplePodName)
			framework.RunKubectlOrDie("cp", filepath.Join(tmpDir, overrideKubeconfigName), ns+"/"+simplePodName+":/tmp/")

			framework.ExpectNoError(ioutil.WriteFile(filepath.Join(tmpDir, "invalid-configmap-with-namespace.yaml"), []byte(`
kind: ConfigMap
apiVersion: v1
metadata:
  name: "configmap with namespace and invalid name"
  namespace: configmap-namespace
`), os.FileMode(0755)))
			framework.ExpectNoError(ioutil.WriteFile(filepath.Join(tmpDir, "invalid-configmap-without-namespace.yaml"), []byte(`
kind: ConfigMap
apiVersion: v1
metadata:
  name: "configmap without namespace and invalid name"
`), os.FileMode(0755)))
			framework.Logf("copying configmap manifests to the %s pod", simplePodName)
			framework.RunKubectlOrDie("cp", filepath.Join(tmpDir, "invalid-configmap-with-namespace.yaml"), ns+"/"+simplePodName+":/tmp/")
			framework.RunKubectlOrDie("cp", filepath.Join(tmpDir, "invalid-configmap-without-namespace.yaml"), ns+"/"+simplePodName+":/tmp/")

			By("getting pods with in-cluster configs")
			execOutput := framework.RunHostCmdOrDie(ns, simplePodName, "/tmp/kubectl get pods --v=7 2>&1")
			Expect(execOutput).To(MatchRegexp("nginx +1/1 +Running"))
			Expect(execOutput).To(ContainSubstring("Using in-cluster namespace"))
			Expect(execOutput).To(ContainSubstring("Using in-cluster configuration"))

			By("creating an object containing a namespace with in-cluster config")
			_, err = framework.RunHostCmd(ns, simplePodName, "/tmp/kubectl create -f /tmp/invalid-configmap-with-namespace.yaml --v=7 2>&1")
			Expect(err).To(ContainSubstring("Using in-cluster namespace"))
			Expect(err).To(ContainSubstring("Using in-cluster configuration"))
			Expect(err).To(ContainSubstring(fmt.Sprintf("POST https://%s:%s/api/v1/namespaces/configmap-namespace/configmaps", inClusterHost, inClusterPort)))

			By("creating an object not containing a namespace with in-cluster config")
			_, err = framework.RunHostCmd(ns, simplePodName, "/tmp/kubectl create -f /tmp/invalid-configmap-without-namespace.yaml --v=7 2>&1")
			Expect(err).To(ContainSubstring("Using in-cluster namespace"))
			Expect(err).To(ContainSubstring("Using in-cluster configuration"))
			Expect(err).To(ContainSubstring(fmt.Sprintf("POST https://%s:%s/api/v1/namespaces/%s/configmaps", inClusterHost, inClusterPort, f.Namespace.Name)))

			By("trying to use kubectl with invalid token")
			_, err = framework.RunHostCmd(ns, simplePodName, "/tmp/kubectl get pods --token=invalid --v=7 2>&1")
			framework.Logf("got err %v", err)
			Expect(err).To(HaveOccurred())
			Expect(err).To(ContainSubstring("Using in-cluster namespace"))
			Expect(err).To(ContainSubstring("Using in-cluster configuration"))
			Expect(err).To(ContainSubstring("Authorization: Bearer invalid"))
			Expect(err).To(ContainSubstring("Response Status: 401 Unauthorized"))

			By("trying to use kubectl with invalid server")
			_, err = framework.RunHostCmd(ns, simplePodName, "/tmp/kubectl get pods --server=invalid --v=6 2>&1")
			framework.Logf("got err %v", err)
			Expect(err).To(HaveOccurred())
			Expect(err).To(ContainSubstring("Unable to connect to the server"))
			Expect(err).To(ContainSubstring("GET http://invalid/api"))

			By("trying to use kubectl with invalid namespace")
			execOutput = framework.RunHostCmdOrDie(ns, simplePodName, "/tmp/kubectl get pods --namespace=invalid --v=6 2>&1")
			Expect(execOutput).To(ContainSubstring("No resources found"))
			Expect(execOutput).ToNot(ContainSubstring("Using in-cluster namespace"))
			Expect(execOutput).To(ContainSubstring("Using in-cluster configuration"))
			Expect(execOutput).To(MatchRegexp(fmt.Sprintf("GET http[s]?://%s:%s/api/v1/namespaces/invalid/pods", inClusterHost, inClusterPort)))

			By("trying to use kubectl with kubeconfig")
			execOutput = framework.RunHostCmdOrDie(ns, simplePodName, "/tmp/kubectl get pods --kubeconfig=/tmp/"+overrideKubeconfigName+" --v=6 2>&1")
			Expect(execOutput).ToNot(ContainSubstring("Using in-cluster namespace"))
			Expect(execOutput).ToNot(ContainSubstring("Using in-cluster configuration"))
			Expect(execOutput).To(ContainSubstring("GET https://kubernetes.default.svc:443/api/v1/namespaces/default/pods"))
		})
	})

	framework.KubeDescribe("Kubectl api-versions", func() {
		It("should check if v1 is in available api versions [Conformance]", func() {
			By("validating api versions")
			output := framework.RunKubectlOrDie("api-versions")
			if !strings.Contains(output, "v1") {
				framework.Failf("No v1 in kubectl api-versions")
			}
		})
	})

	framework.KubeDescribe("Kubectl apply", func() {
		It("should apply a new configuration to an existing RC", func() {
			controllerJson := substituteImageName(string(readTestFileOrDie(redisControllerFilename)))

			nsFlag := fmt.Sprintf("--namespace=%v", ns)
			By("creating Redis RC")
			framework.RunKubectlOrDieInput(controllerJson, "create", "-f", "-", nsFlag)
			By("applying a modified configuration")
			stdin := modifyReplicationControllerConfiguration(controllerJson)
			framework.NewKubectlCommand("apply", "-f", "-", nsFlag).
				WithStdinReader(stdin).
				ExecOrDie()
			By("checking the result")
			forEachReplicationController(c, ns, "app", "redis", validateReplicationControllerConfiguration)
		})
		It("should reuse port when apply to an existing SVC", func() {
			serviceJson := readTestFileOrDie(redisServiceFilename)
			nsFlag := fmt.Sprintf("--namespace=%v", ns)

			By("creating Redis SVC")
			framework.RunKubectlOrDieInput(string(serviceJson[:]), "create", "-f", "-", nsFlag)

			By("getting the original port")
			originalNodePort := framework.RunKubectlOrDie("get", "service", "redis-master", nsFlag, "-o", "jsonpath={.spec.ports[0].port}")

			By("applying the same configuration")
			framework.RunKubectlOrDieInput(string(serviceJson[:]), "apply", "-f", "-", nsFlag)

			By("getting the port after applying configuration")
			currentNodePort := framework.RunKubectlOrDie("get", "service", "redis-master", nsFlag, "-o", "jsonpath={.spec.ports[0].port}")

			By("checking the result")
			if originalNodePort != currentNodePort {
				framework.Failf("port should keep the same")
			}
		})

		It("apply set/view last-applied", func() {
			deployment1Yaml := substituteImageName(string(readTestFileOrDie(nginxDeployment1Filename)))
			deployment2Yaml := substituteImageName(string(readTestFileOrDie(nginxDeployment2Filename)))
			deployment3Yaml := substituteImageName(string(readTestFileOrDie(nginxDeployment3Filename)))
			nsFlag := fmt.Sprintf("--namespace=%v", ns)

			By("deployment replicas number is 2")
			framework.RunKubectlOrDieInput(deployment1Yaml, "apply", "-f", "-", nsFlag)

			By("check the last-applied matches expectations annotations")
			output := framework.RunKubectlOrDieInput(deployment1Yaml, "apply", "view-last-applied", "-f", "-", nsFlag, "-o", "json")
			requiredString := "\"replicas\": 2"
			if !strings.Contains(output, requiredString) {
				framework.Failf("Missing %s in kubectl view-last-applied", requiredString)
			}

			By("apply file doesn't have replicas")
			framework.RunKubectlOrDieInput(deployment2Yaml, "apply", "set-last-applied", "-f", "-", nsFlag)

			By("check last-applied has been updated, annotations doesn't replicas")
			output = framework.RunKubectlOrDieInput(deployment1Yaml, "apply", "view-last-applied", "-f", "-", nsFlag, "-o", "json")
			requiredString = "\"replicas\": 2"
			if strings.Contains(output, requiredString) {
				framework.Failf("Missing %s in kubectl view-last-applied", requiredString)
			}

			By("scale set replicas to 3")
			nginxDeploy := "nginx-deployment"
			framework.RunKubectlOrDie("scale", "deployment", nginxDeploy, "--replicas=3", nsFlag)

			By("apply file doesn't have replicas but image changed")
			framework.RunKubectlOrDieInput(deployment3Yaml, "apply", "-f", "-", nsFlag)

			By("verify replicas still is 3 and image has been updated")
			output = framework.RunKubectlOrDieInput(deployment3Yaml, "get", "-f", "-", nsFlag, "-o", "json")
			requiredItems := []string{"\"replicas\": 3", imageutils.GetE2EImage(imageutils.NginxSlim)}
			for _, item := range requiredItems {
				if !strings.Contains(output, item) {
					framework.Failf("Missing %s in kubectl apply", item)
				}
			}
		})
	})

	framework.KubeDescribe("Kubectl cluster-info", func() {
		It("should check if Kubernetes master services is included in cluster-info [Conformance]", func() {
			By("validating cluster-info")
			output := framework.RunKubectlOrDie("cluster-info")
			// Can't check exact strings due to terminal control commands (colors)
			requiredItems := []string{"Kubernetes master", "is running at"}
			if framework.ProviderIs("gce", "gke") {
				requiredItems = append(requiredItems, "KubeDNS", "Heapster")
			}
			for _, item := range requiredItems {
				if !strings.Contains(output, item) {
					framework.Failf("Missing %s in kubectl cluster-info", item)
				}
			}
		})
	})

	framework.KubeDescribe("Kubectl describe", func() {
		It("should check if kubectl describe prints relevant information for rc and pods [Conformance]", func() {
			framework.SkipUnlessServerVersionGTE(nodePortsOptionalVersion, c.Discovery())
			kv, err := framework.KubectlVersion()
			Expect(err).NotTo(HaveOccurred())
			framework.SkipUnlessServerVersionGTE(kv, c.Discovery())
			controllerJson := substituteImageName(string(readTestFileOrDie(redisControllerFilename)))
			serviceJson := readTestFileOrDie(redisServiceFilename)

			nsFlag := fmt.Sprintf("--namespace=%v", ns)
			framework.RunKubectlOrDieInput(controllerJson, "create", "-f", "-", nsFlag)
			framework.RunKubectlOrDieInput(string(serviceJson[:]), "create", "-f", "-", nsFlag)

			By("Waiting for Redis master to start.")
			waitForOrFailWithDebug(1)

			// Pod
			forEachPod(func(pod v1.Pod) {
				output := framework.RunKubectlOrDie("describe", "pod", pod.Name, nsFlag)
				requiredStrings := [][]string{
					{"Name:", "redis-master-"},
					{"Namespace:", ns},
					{"Node:"},
					{"Labels:", "app=redis"},
					{"role=master"},
					{"Annotations:"},
					{"Status:", "Running"},
					{"IP:"},
					{"Created By:", "ReplicationController/redis-master"},
					{"Controlled By:", "ReplicationController/redis-master"},
					{"Image:", redisImage},
					{"State:", "Running"},
					{"QoS Class:", "BestEffort"},
				}
				checkOutput(output, requiredStrings)
			})

			// Rc
			requiredStrings := [][]string{
				{"Name:", "redis-master"},
				{"Namespace:", ns},
				{"Selector:", "app=redis,role=master"},
				{"Labels:", "app=redis"},
				{"role=master"},
				{"Annotations:"},
				{"Replicas:", "1 current", "1 desired"},
				{"Pods Status:", "1 Running", "0 Waiting", "0 Succeeded", "0 Failed"},
				{"Pod Template:"},
				{"Image:", redisImage},
				{"Events:"}}
			checkKubectlOutputWithRetry(requiredStrings, "describe", "rc", "redis-master", nsFlag)

			// Service
			output := framework.RunKubectlOrDie("describe", "service", "redis-master", nsFlag)
			requiredStrings = [][]string{
				{"Name:", "redis-master"},
				{"Namespace:", ns},
				{"Labels:", "app=redis"},
				{"role=master"},
				{"Annotations:"},
				{"Selector:", "app=redis", "role=master"},
				{"Type:", "ClusterIP"},
				{"IP:"},
				{"Port:", "<unset>", "6379/TCP"},
				{"Endpoints:"},
				{"Session Affinity:", "None"}}
			checkOutput(output, requiredStrings)

			// Node
			// It should be OK to list unschedulable Nodes here.
			nodes, err := c.Core().Nodes().List(metav1.ListOptions{})
			Expect(err).NotTo(HaveOccurred())
			node := nodes.Items[0]
			output = framework.RunKubectlOrDie("describe", "node", node.Name)
			requiredStrings = [][]string{
				{"Name:", node.Name},
				{"Labels:"},
				{"Annotations:"},
				{"CreationTimestamp:"},
				{"Conditions:"},
				{"Type", "Status", "LastHeartbeatTime", "LastTransitionTime", "Reason", "Message"},
				{"Addresses:"},
				{"Capacity:"},
				{"Version:"},
				{"Kernel Version:"},
				{"OS Image:"},
				{"Container Runtime Version:"},
				{"Kubelet Version:"},
				{"Kube-Proxy Version:"},
				{"Pods:"}}
			checkOutput(output, requiredStrings)

			// Namespace
			output = framework.RunKubectlOrDie("describe", "namespace", ns)
			requiredStrings = [][]string{
				{"Name:", ns},
				{"Labels:"},
				{"Annotations:"},
				{"Status:", "Active"}}
			checkOutput(output, requiredStrings)

			// Quota and limitrange are skipped for now.
		})
	})

	framework.KubeDescribe("Kubectl expose", func() {
		It("should create services for rc [Conformance]", func() {
			controllerJson := substituteImageName(string(readTestFileOrDie(redisControllerFilename)))
			nsFlag := fmt.Sprintf("--namespace=%v", ns)

			redisPort := 6379

			By("creating Redis RC")

			framework.Logf("namespace %v", ns)
			framework.RunKubectlOrDieInput(controllerJson, "create", "-f", "-", nsFlag)

			// It may take a while for the pods to get registered in some cases, wait to be sure.
			By("Waiting for Redis master to start.")
			waitForOrFailWithDebug(1)
			forEachPod(func(pod v1.Pod) {
				framework.Logf("wait on redis-master startup in %v ", ns)
				framework.LookForStringInLog(ns, pod.Name, "redis-master", "The server is now ready to accept connections", framework.PodStartTimeout)
			})
			validateService := func(name string, servicePort int, timeout time.Duration) {
				err := wait.Poll(framework.Poll, timeout, func() (bool, error) {
					endpoints, err := c.Core().Endpoints(ns).Get(name, metav1.GetOptions{})
					if err != nil {
						// log the real error
						framework.Logf("Get endpoints failed (interval %v): %v", framework.Poll, err)

						// if the error is API not found or could not find default credentials or TLS handshake timeout, try again
						if apierrs.IsNotFound(err) ||
							apierrs.IsUnauthorized(err) ||
							apierrs.IsServerTimeout(err) {
							err = nil
						}
						return false, err
					}

					uidToPort := framework.GetContainerPortsByPodUID(endpoints)
					if len(uidToPort) == 0 {
						framework.Logf("No endpoint found, retrying")
						return false, nil
					}
					if len(uidToPort) > 1 {
						framework.Failf("Too many endpoints found")
					}
					for _, port := range uidToPort {
						if port[0] != redisPort {
							framework.Failf("Wrong endpoint port: %d", port[0])
						}
					}
					return true, nil
				})
				Expect(err).NotTo(HaveOccurred())

				service, err := c.Core().Services(ns).Get(name, metav1.GetOptions{})
				Expect(err).NotTo(HaveOccurred())

				if len(service.Spec.Ports) != 1 {
					framework.Failf("1 port is expected")
				}
				port := service.Spec.Ports[0]
				if port.Port != int32(servicePort) {
					framework.Failf("Wrong service port: %d", port.Port)
				}
				if port.TargetPort.IntValue() != redisPort {
					framework.Failf("Wrong target port: %d", port.TargetPort.IntValue())
				}
			}

			By("exposing RC")
			framework.RunKubectlOrDie("expose", "rc", "redis-master", "--name=rm2", "--port=1234", fmt.Sprintf("--target-port=%d", redisPort), nsFlag)
			framework.WaitForService(c, ns, "rm2", true, framework.Poll, framework.ServiceStartTimeout)
			validateService("rm2", 1234, framework.ServiceStartTimeout)

			By("exposing service")
			framework.RunKubectlOrDie("expose", "service", "rm2", "--name=rm3", "--port=2345", fmt.Sprintf("--target-port=%d", redisPort), nsFlag)
			framework.WaitForService(c, ns, "rm3", true, framework.Poll, framework.ServiceStartTimeout)
			validateService("rm3", 2345, framework.ServiceStartTimeout)
		})
	})

	framework.KubeDescribe("Kubectl label", func() {
		podYaml := substituteImageName(string(readTestFileOrDie("pause-pod.yaml.in")))
		var nsFlag string
		BeforeEach(func() {
			By("creating the pod")
			nsFlag = fmt.Sprintf("--namespace=%v", ns)
			framework.RunKubectlOrDieInput(podYaml, "create", "-f", "-", nsFlag)
			Expect(framework.CheckPodsRunningReady(c, ns, []string{pausePodName}, framework.PodStartTimeout)).To(BeTrue())
		})
		AfterEach(func() {
			cleanupKubectlInputs(podYaml, ns, pausePodSelector)
		})

		It("should update the label on a resource [Conformance]", func() {
			labelName := "testing-label"
			labelValue := "testing-label-value"

			By("adding the label " + labelName + " with value " + labelValue + " to a pod")
			framework.RunKubectlOrDie("label", "pods", pausePodName, labelName+"="+labelValue, nsFlag)
			By("verifying the pod has the label " + labelName + " with the value " + labelValue)
			output := framework.RunKubectlOrDie("get", "pod", pausePodName, "-L", labelName, nsFlag)
			if !strings.Contains(output, labelValue) {
				framework.Failf("Failed updating label " + labelName + " to the pod " + pausePodName)
			}

			By("removing the label " + labelName + " of a pod")
			framework.RunKubectlOrDie("label", "pods", pausePodName, labelName+"-", nsFlag)
			By("verifying the pod doesn't have the label " + labelName)
			output = framework.RunKubectlOrDie("get", "pod", pausePodName, "-L", labelName, nsFlag)
			if strings.Contains(output, labelValue) {
				framework.Failf("Failed removing label " + labelName + " of the pod " + pausePodName)
			}
		})
	})

	framework.KubeDescribe("Kubectl logs", func() {
		var nsFlag string
		rc := substituteImageName(string(readTestFileOrDie(redisControllerFilename)))
		containerName := "redis-master"
		BeforeEach(func() {
			By("creating an rc")
			nsFlag = fmt.Sprintf("--namespace=%v", ns)
			framework.RunKubectlOrDieInput(rc, "create", "-f", "-", nsFlag)
		})
		AfterEach(func() {
			cleanupKubectlInputs(rc, ns, simplePodSelector)
		})

		It("should be able to retrieve and filter logs [Conformance]", func() {
			framework.SkipUnlessServerVersionGTE(extendedPodLogFilterVersion, c.Discovery())

			// Split("something\n", "\n") returns ["something", ""], so
			// strip trailing newline first
			lines := func(out string) []string {
				return strings.Split(strings.TrimRight(out, "\n"), "\n")
			}

			By("Waiting for Redis master to start.")
			waitForOrFailWithDebug(1)
			forEachPod(func(pod v1.Pod) {
				By("checking for a matching strings")
				_, err := framework.LookForStringInLog(ns, pod.Name, containerName, "The server is now ready to accept connections", framework.PodStartTimeout)
				Expect(err).NotTo(HaveOccurred())

				By("limiting log lines")
				out := framework.RunKubectlOrDie("log", pod.Name, containerName, nsFlag, "--tail=1")
				Expect(len(out)).NotTo(BeZero())
				Expect(len(lines(out))).To(Equal(1))

				By("limiting log bytes")
				out = framework.RunKubectlOrDie("log", pod.Name, containerName, nsFlag, "--limit-bytes=1")
				Expect(len(lines(out))).To(Equal(1))
				Expect(len(out)).To(Equal(1))

				By("exposing timestamps")
				out = framework.RunKubectlOrDie("log", pod.Name, containerName, nsFlag, "--tail=1", "--timestamps")
				l := lines(out)
				Expect(len(l)).To(Equal(1))
				words := strings.Split(l[0], " ")
				Expect(len(words)).To(BeNumerically(">", 1))
				if _, err := time.Parse(time.RFC3339Nano, words[0]); err != nil {
					if _, err := time.Parse(time.RFC3339, words[0]); err != nil {
						framework.Failf("expected %q to be RFC3339 or RFC3339Nano", words[0])
					}
				}

				By("restricting to a time range")
				// Note: we must wait at least two seconds,
				// because the granularity is only 1 second and
				// it could end up rounding the wrong way.
				time.Sleep(2500 * time.Millisecond) // ensure that startup logs on the node are seen as older than 1s
				recent_out := framework.RunKubectlOrDie("log", pod.Name, containerName, nsFlag, "--since=1s")
				recent := len(strings.Split(recent_out, "\n"))
				older_out := framework.RunKubectlOrDie("log", pod.Name, containerName, nsFlag, "--since=24h")
				older := len(strings.Split(older_out, "\n"))
				Expect(recent).To(BeNumerically("<", older), "expected recent(%v) to be less than older(%v)\nrecent lines:\n%v\nolder lines:\n%v\n", recent, older, recent_out, older_out)
			})
		})
	})

	framework.KubeDescribe("Kubectl patch", func() {
		It("should add annotations for pods in rc [Conformance]", func() {
			controllerJson := substituteImageName(string(readTestFileOrDie(redisControllerFilename)))
			nsFlag := fmt.Sprintf("--namespace=%v", ns)
			By("creating Redis RC")
			framework.RunKubectlOrDieInput(controllerJson, "create", "-f", "-", nsFlag)
			By("Waiting for Redis master to start.")
			waitForOrFailWithDebug(1)
			By("patching all pods")
			forEachPod(func(pod v1.Pod) {
				framework.RunKubectlOrDie("patch", "pod", pod.Name, nsFlag, "-p", "{\"metadata\":{\"annotations\":{\"x\":\"y\"}}}")
			})

			By("checking annotations")
			forEachPod(func(pod v1.Pod) {
				found := false
				for key, val := range pod.Annotations {
					if key == "x" && val == "y" {
						found = true
						break
					}
				}
				if !found {
					framework.Failf("Added annotation not found")
				}
			})
		})
	})

	framework.KubeDescribe("Kubectl version", func() {
		It("should check is all data is printed [Conformance]", func() {
			version := framework.RunKubectlOrDie("version")
			requiredItems := []string{"Client Version:", "Server Version:", "Major:", "Minor:", "GitCommit:"}
			for _, item := range requiredItems {
				if !strings.Contains(version, item) {
					framework.Failf("Required item %s not found in %s", item, version)
				}
			}
		})
	})

	framework.KubeDescribe("Kubectl run default", func() {
		var nsFlag string
		var name string

		var cleanUp func()

		BeforeEach(func() {
			nsFlag = fmt.Sprintf("--namespace=%v", ns)
			gte, err := framework.ServerVersionGTE(deploymentsVersion, c.Discovery())
			if err != nil {
				framework.Failf("Failed to get server version: %v", err)
			}
			if gte {
				name = "e2e-test-nginx-deployment"
				cleanUp = func() { framework.RunKubectlOrDie("delete", "deployment", name, nsFlag) }
			} else {
				name = "e2e-test-nginx-rc"
				cleanUp = func() { framework.RunKubectlOrDie("delete", "rc", name, nsFlag) }
			}
		})

		AfterEach(func() {
			cleanUp()
		})

		It("should create an rc or deployment from an image [Conformance]", func() {
			By("running the image " + nginxImage)
			framework.RunKubectlOrDie("run", name, "--image="+nginxImage, nsFlag)
			By("verifying the pod controlled by " + name + " gets created")
			label := labels.SelectorFromSet(labels.Set(map[string]string{"run": name}))
			podlist, err := framework.WaitForPodsWithLabel(c, ns, label)
			if err != nil {
				framework.Failf("Failed getting pod controlled by %s: %v", name, err)
			}
			pods := podlist.Items
			if pods == nil || len(pods) != 1 || len(pods[0].Spec.Containers) != 1 || pods[0].Spec.Containers[0].Image != nginxImage {
				framework.RunKubectlOrDie("get", "pods", "-L", "run", nsFlag)
				framework.Failf("Failed creating 1 pod with expected image %s. Number of pods = %v", nginxImage, len(pods))
			}
		})
	})

	framework.KubeDescribe("Kubectl run rc", func() {
		var nsFlag string
		var rcName string

		BeforeEach(func() {
			nsFlag = fmt.Sprintf("--namespace=%v", ns)
			rcName = "e2e-test-nginx-rc"
		})

		AfterEach(func() {
			framework.RunKubectlOrDie("delete", "rc", rcName, nsFlag)
		})

		It("should create an rc from an image [Conformance]", func() {
			By("running the image " + nginxImage)
			framework.RunKubectlOrDie("run", rcName, "--image="+nginxImage, "--generator=run/v1", nsFlag)
			By("verifying the rc " + rcName + " was created")
			rc, err := c.Core().ReplicationControllers(ns).Get(rcName, metav1.GetOptions{})
			if err != nil {
				framework.Failf("Failed getting rc %s: %v", rcName, err)
			}
			containers := rc.Spec.Template.Spec.Containers
			if containers == nil || len(containers) != 1 || containers[0].Image != nginxImage {
				framework.Failf("Failed creating rc %s for 1 pod with expected image %s", rcName, nginxImage)
			}

			By("verifying the pod controlled by rc " + rcName + " was created")
			label := labels.SelectorFromSet(labels.Set(map[string]string{"run": rcName}))
			podlist, err := framework.WaitForPodsWithLabel(c, ns, label)
			if err != nil {
				framework.Failf("Failed getting pod controlled by rc %s: %v", rcName, err)
			}
			pods := podlist.Items
			if pods == nil || len(pods) != 1 || len(pods[0].Spec.Containers) != 1 || pods[0].Spec.Containers[0].Image != nginxImage {
				framework.RunKubectlOrDie("get", "pods", "-L", "run", nsFlag)
				framework.Failf("Failed creating 1 pod with expected image %s. Number of pods = %v", nginxImage, len(pods))
			}

			By("confirm that you can get logs from an rc")
			podNames := []string{}
			for _, pod := range pods {
				podNames = append(podNames, pod.Name)
			}
			if !framework.CheckPodsRunningReady(c, ns, podNames, framework.PodStartTimeout) {
				framework.Failf("Pods for rc %s were not ready", rcName)
			}
			_, err = framework.RunKubectl("logs", "rc/"+rcName, nsFlag)
			// a non-nil error is fine as long as we actually found a pod.
			if err != nil && !strings.Contains(err.Error(), " in pod ") {
				framework.Failf("Failed getting logs by rc %s: %v", rcName, err)
			}
		})
	})

	framework.KubeDescribe("Kubectl rolling-update", func() {
		var nsFlag string
		var rcName string
		var c clientset.Interface

		BeforeEach(func() {
			c = f.ClientSet
			nsFlag = fmt.Sprintf("--namespace=%v", ns)
			rcName = "e2e-test-nginx-rc"
		})

		AfterEach(func() {
			framework.RunKubectlOrDie("delete", "rc", rcName, nsFlag)
		})

		It("should support rolling-update to same image [Conformance]", func() {
			By("running the image " + nginxImage)
			framework.RunKubectlOrDie("run", rcName, "--image="+nginxImage, "--generator=run/v1", nsFlag)
			By("verifying the rc " + rcName + " was created")
			rc, err := c.Core().ReplicationControllers(ns).Get(rcName, metav1.GetOptions{})
			if err != nil {
				framework.Failf("Failed getting rc %s: %v", rcName, err)
			}
			containers := rc.Spec.Template.Spec.Containers
			if containers == nil || len(containers) != 1 || containers[0].Image != nginxImage {
				framework.Failf("Failed creating rc %s for 1 pod with expected image %s", rcName, nginxImage)
			}
			framework.WaitForRCToStabilize(c, ns, rcName, framework.PodStartTimeout)

			By("rolling-update to same image controller")

			runKubectlRetryOrDie("rolling-update", rcName, "--update-period=1s", "--image="+nginxImage, "--image-pull-policy="+string(v1.PullIfNotPresent), nsFlag)
			framework.ValidateController(c, nginxImage, 1, rcName, "run="+rcName, noOpValidatorFn, ns)
		})
	})

	framework.KubeDescribe("Kubectl run deployment", func() {
		var nsFlag string
		var dName string

		BeforeEach(func() {
			nsFlag = fmt.Sprintf("--namespace=%v", ns)
			dName = "e2e-test-nginx-deployment"
		})

		AfterEach(func() {
			err := wait.Poll(framework.Poll, 2*time.Minute, func() (bool, error) {
				out, err := framework.RunKubectl("delete", "deployment", dName, nsFlag)
				if err != nil {
					if strings.Contains(err.Error(), "could not find default credentials") {
						err = nil
					}
					return false, fmt.Errorf("kubectl delete failed output: %s, err: %v", out, err)
				}
				return true, nil
			})
			Expect(err).NotTo(HaveOccurred())
		})

		It("should create a deployment from an image [Conformance]", func() {
			framework.SkipUnlessServerVersionGTE(deploymentsVersion, c.Discovery())

			By("running the image " + nginxImage)
			framework.RunKubectlOrDie("run", dName, "--image="+nginxImage, "--generator=deployment/v1beta1", nsFlag)
			By("verifying the deployment " + dName + " was created")
			d, err := c.Extensions().Deployments(ns).Get(dName, metav1.GetOptions{})
			if err != nil {
				framework.Failf("Failed getting deployment %s: %v", dName, err)
			}
			containers := d.Spec.Template.Spec.Containers
			if containers == nil || len(containers) != 1 || containers[0].Image != nginxImage {
				framework.Failf("Failed creating deployment %s for 1 pod with expected image %s", dName, nginxImage)
			}

			By("verifying the pod controlled by deployment " + dName + " was created")
			label := labels.SelectorFromSet(labels.Set(map[string]string{"run": dName}))
			podlist, err := framework.WaitForPodsWithLabel(c, ns, label)
			if err != nil {
				framework.Failf("Failed getting pod controlled by deployment %s: %v", dName, err)
			}
			pods := podlist.Items
			if pods == nil || len(pods) != 1 || len(pods[0].Spec.Containers) != 1 || pods[0].Spec.Containers[0].Image != nginxImage {
				framework.RunKubectlOrDie("get", "pods", "-L", "run", nsFlag)
				framework.Failf("Failed creating 1 pod with expected image %s. Number of pods = %v", nginxImage, len(pods))
			}
		})
	})

	framework.KubeDescribe("Kubectl run job", func() {
		var nsFlag string
		var jobName string

		BeforeEach(func() {
			nsFlag = fmt.Sprintf("--namespace=%v", ns)
			jobName = "e2e-test-nginx-job"
		})

		AfterEach(func() {
			framework.RunKubectlOrDie("delete", "jobs", jobName, nsFlag)
		})

		It("should create a job from an image when restart is OnFailure [Conformance]", func() {
			framework.SkipUnlessServerVersionGTE(jobsVersion, c.Discovery())

			By("running the image " + nginxImage)
			framework.RunKubectlOrDie("run", jobName, "--restart=OnFailure", "--generator=job/v1", "--image="+nginxImage, nsFlag)
			By("verifying the job " + jobName + " was created")
			job, err := c.Batch().Jobs(ns).Get(jobName, metav1.GetOptions{})
			if err != nil {
				framework.Failf("Failed getting job %s: %v", jobName, err)
			}
			containers := job.Spec.Template.Spec.Containers
			if containers == nil || len(containers) != 1 || containers[0].Image != nginxImage {
				framework.Failf("Failed creating job %s for 1 pod with expected image %s: %#v", jobName, nginxImage, containers)
			}
			if job.Spec.Template.Spec.RestartPolicy != v1.RestartPolicyOnFailure {
				framework.Failf("Failed creating a job with correct restart policy for --restart=OnFailure")
			}
		})
	})

	framework.KubeDescribe("Kubectl run CronJob", func() {
		var nsFlag string
		var cjName string

		BeforeEach(func() {
			nsFlag = fmt.Sprintf("--namespace=%v", ns)
			cjName = "e2e-test-echo-cronjob-beta"
		})

		AfterEach(func() {
			framework.RunKubectlOrDie("delete", "cronjob.v1beta1.batch", cjName, nsFlag)
		})

		It("should create a CronJob", func() {
			framework.SkipIfMissingResource(f.ClientPool, CronJobGroupVersionResourceBeta, f.Namespace.Name)

			schedule := "*/5 * * * ?"
			framework.RunKubectlOrDie("run", cjName, "--restart=OnFailure", "--generator=cronjob/v1beta1",
				"--schedule="+schedule, "--image="+busyboxImage, nsFlag)
			By("verifying the CronJob " + cjName + " was created")
			cj, err := c.BatchV1beta1().CronJobs(ns).Get(cjName, metav1.GetOptions{})
			if err != nil {
				framework.Failf("Failed getting CronJob %s: %v", cjName, err)
			}
			if cj.Spec.Schedule != schedule {
				framework.Failf("Failed creating a CronJob with correct schedule %s", schedule)
			}
			containers := cj.Spec.JobTemplate.Spec.Template.Spec.Containers
			if containers == nil || len(containers) != 1 || containers[0].Image != busyboxImage {
				framework.Failf("Failed creating CronJob %s for 1 pod with expected image %s: %#v", cjName, busyboxImage, containers)
			}
			if cj.Spec.JobTemplate.Spec.Template.Spec.RestartPolicy != v1.RestartPolicyOnFailure {
				framework.Failf("Failed creating a CronJob with correct restart policy for --restart=OnFailure")
			}
		})
	})

	framework.KubeDescribe("Kubectl run pod", func() {
		var nsFlag string
		var podName string

		BeforeEach(func() {
			nsFlag = fmt.Sprintf("--namespace=%v", ns)
			podName = "e2e-test-nginx-pod"
		})

		AfterEach(func() {
			framework.RunKubectlOrDie("delete", "pods", podName, nsFlag)
		})

		It("should create a pod from an image when restart is Never [Conformance]", func() {
			framework.SkipUnlessServerVersionGTE(jobsVersion, c.Discovery())

			By("running the image " + nginxImage)
			framework.RunKubectlOrDie("run", podName, "--restart=Never", "--generator=run-pod/v1", "--image="+nginxImage, nsFlag)
			By("verifying the pod " + podName + " was created")
			pod, err := c.Core().Pods(ns).Get(podName, metav1.GetOptions{})
			if err != nil {
				framework.Failf("Failed getting pod %s: %v", podName, err)
			}
			containers := pod.Spec.Containers
			if containers == nil || len(containers) != 1 || containers[0].Image != nginxImage {
				framework.Failf("Failed creating pod %s with expected image %s", podName, nginxImage)
			}
			if pod.Spec.RestartPolicy != v1.RestartPolicyNever {
				framework.Failf("Failed creating a pod with correct restart policy for --restart=Never")
			}
		})
	})

	framework.KubeDescribe("Kubectl replace", func() {
		var nsFlag string
		var podName string

		BeforeEach(func() {
			nsFlag = fmt.Sprintf("--namespace=%v", ns)
			podName = "e2e-test-nginx-pod"
		})

		AfterEach(func() {
			framework.RunKubectlOrDie("delete", "pods", podName, nsFlag)
		})

		It("should update a single-container pod's image [Conformance]", func() {
			framework.SkipUnlessServerVersionGTE(jobsVersion, c.Discovery())

			By("running the image " + nginxImage)
			framework.RunKubectlOrDie("run", podName, "--generator=run-pod/v1", "--image="+nginxImage, "--labels=run="+podName, nsFlag)

			By("verifying the pod " + podName + " is running")
			label := labels.SelectorFromSet(labels.Set(map[string]string{"run": podName}))
			err := testutils.WaitForPodsWithLabelRunning(c, ns, label)
			if err != nil {
				framework.Failf("Failed getting pod %s: %v", podName, err)
			}

			By("verifying the pod " + podName + " was created")
			podJson := framework.RunKubectlOrDie("get", "pod", podName, nsFlag, "-o", "json")
			if !strings.Contains(podJson, podName) {
				framework.Failf("Failed to find pod %s in [%s]", podName, podJson)
			}

			By("replace the image in the pod")
			podJson = strings.Replace(podJson, nginxImage, busyboxImage, 1)
			framework.RunKubectlOrDieInput(podJson, "replace", "-f", "-", nsFlag)

			By("verifying the pod " + podName + " has the right image " + busyboxImage)
			pod, err := c.Core().Pods(ns).Get(podName, metav1.GetOptions{})
			if err != nil {
				framework.Failf("Failed getting deployment %s: %v", podName, err)
			}
			containers := pod.Spec.Containers
			if containers == nil || len(containers) != 1 || containers[0].Image != busyboxImage {
				framework.Failf("Failed creating pod with expected image %s", busyboxImage)
			}
		})
	})

	framework.KubeDescribe("Kubectl run --rm job", func() {
		jobName := "e2e-test-rm-busybox-job"

		It("should create a job from an image, then delete the job [Conformance]", func() {
			nsFlag := fmt.Sprintf("--namespace=%v", ns)

			// The rkt runtime doesn't support attach, see #23335
			framework.SkipIfContainerRuntimeIs("rkt")
			framework.SkipUnlessServerVersionGTE(jobsVersion, c.Discovery())

			By("executing a command with run --rm and attach with stdin")
			t := time.NewTimer(runJobTimeout)
			defer t.Stop()
			runOutput := framework.NewKubectlCommand(nsFlag, "run", jobName, "--image="+busyboxImage, "--rm=true", "--generator=job/v1", "--restart=OnFailure", "--attach=true", "--stdin", "--", "sh", "-c", "cat && echo 'stdin closed'").
				WithStdinData("abcd1234").
				WithTimeout(t.C).
				ExecOrDie()
			Expect(runOutput).To(ContainSubstring("abcd1234"))
			Expect(runOutput).To(ContainSubstring("stdin closed"))

			By("verifying the job " + jobName + " was deleted")
			_, err := c.Batch().Jobs(ns).Get(jobName, metav1.GetOptions{})
			Expect(err).To(HaveOccurred())
			Expect(apierrs.IsNotFound(err)).To(BeTrue())
		})
	})

	framework.KubeDescribe("Proxy server", func() {
		// TODO: test proxy options (static, prefix, etc)
		It("should support proxy with --port 0 [Conformance]", func() {
			By("starting the proxy server")
			port, cmd, err := startProxyServer()
			if cmd != nil {
				defer framework.TryKill(cmd)
			}
			if err != nil {
				framework.Failf("Failed to start proxy server: %v", err)
			}
			By("curling proxy /api/ output")
			localAddr := fmt.Sprintf("http://localhost:%d/api/", port)
			apiVersions, err := getAPIVersions(localAddr)
			if err != nil {
				framework.Failf("Expected at least one supported apiversion, got error %v", err)
			}
			if len(apiVersions.Versions) < 1 {
				framework.Failf("Expected at least one supported apiversion, got %v", apiVersions)
			}
		})

		It("should support --unix-socket=/path [Conformance]", func() {
			By("Starting the proxy")
			tmpdir, err := ioutil.TempDir("", "kubectl-proxy-unix")
			if err != nil {
				framework.Failf("Failed to create temporary directory: %v", err)
			}
			path := filepath.Join(tmpdir, "test")
			defer os.Remove(path)
			defer os.Remove(tmpdir)
			cmd := framework.KubectlCmd("proxy", fmt.Sprintf("--unix-socket=%s", path))
			stdout, stderr, err := framework.StartCmdAndStreamOutput(cmd)
			if err != nil {
				framework.Failf("Failed to start kubectl command: %v", err)
			}
			defer stdout.Close()
			defer stderr.Close()
			defer framework.TryKill(cmd)
			buf := make([]byte, 128)
			if _, err = stdout.Read(buf); err != nil {
				framework.Failf("Expected output from kubectl proxy: %v", err)
			}
			By("retrieving proxy /api/ output")
			_, err = curlUnix("http://unused/api", path)
			if err != nil {
				framework.Failf("Failed get of /api at %s: %v", path, err)
			}
		})
	})

	// This test must run [Serial] because it modifies the node so it doesn't allow pods to execute on
	// it, which will affect anything else running in parallel.
	framework.KubeDescribe("Kubectl taint [Serial]", func() {
		It("should update the taint on a node", func() {
			testTaint := v1.Taint{
				Key:    fmt.Sprintf("kubernetes.io/e2e-taint-key-001-%s", string(uuid.NewUUID())),
				Value:  "testing-taint-value",
				Effect: v1.TaintEffectNoSchedule,
			}

			nodeName := scheduling.GetNodeThatCanRunPod(f)

			By("adding the taint " + testTaint.ToString() + " to a node")
			runKubectlRetryOrDie("taint", "nodes", nodeName, testTaint.ToString())
			defer framework.RemoveTaintOffNode(f.ClientSet, nodeName, testTaint)

			By("verifying the node has the taint " + testTaint.ToString())
			output := runKubectlRetryOrDie("describe", "node", nodeName)
			requiredStrings := [][]string{
				{"Name:", nodeName},
				{"Taints:"},
				{testTaint.ToString()},
			}
			checkOutput(output, requiredStrings)

			By("removing the taint " + testTaint.ToString() + " of a node")
			runKubectlRetryOrDie("taint", "nodes", nodeName, testTaint.Key+":"+string(testTaint.Effect)+"-")
			By("verifying the node doesn't have the taint " + testTaint.Key)
			output = runKubectlRetryOrDie("describe", "node", nodeName)
			if strings.Contains(output, testTaint.Key) {
				framework.Failf("Failed removing taint " + testTaint.Key + " of the node " + nodeName)
			}
		})

		It("should remove all the taints with the same key off a node", func() {
			testTaint := v1.Taint{
				Key:    fmt.Sprintf("kubernetes.io/e2e-taint-key-002-%s", string(uuid.NewUUID())),
				Value:  "testing-taint-value",
				Effect: v1.TaintEffectNoSchedule,
			}

			nodeName := scheduling.GetNodeThatCanRunPod(f)

			By("adding the taint " + testTaint.ToString() + " to a node")
			runKubectlRetryOrDie("taint", "nodes", nodeName, testTaint.ToString())
			defer framework.RemoveTaintOffNode(f.ClientSet, nodeName, testTaint)

			By("verifying the node has the taint " + testTaint.ToString())
			output := runKubectlRetryOrDie("describe", "node", nodeName)
			requiredStrings := [][]string{
				{"Name:", nodeName},
				{"Taints:"},
				{testTaint.ToString()},
			}
			checkOutput(output, requiredStrings)

			newTestTaint := v1.Taint{
				Key:    testTaint.Key,
				Value:  "another-testing-taint-value",
				Effect: v1.TaintEffectPreferNoSchedule,
			}
			By("adding another taint " + newTestTaint.ToString() + " to the node")
			runKubectlRetryOrDie("taint", "nodes", nodeName, newTestTaint.ToString())
			defer framework.RemoveTaintOffNode(f.ClientSet, nodeName, newTestTaint)

			By("verifying the node has the taint " + newTestTaint.ToString())
			output = runKubectlRetryOrDie("describe", "node", nodeName)
			requiredStrings = [][]string{
				{"Name:", nodeName},
				{"Taints:"},
				{newTestTaint.ToString()},
			}
			checkOutput(output, requiredStrings)

			noExecuteTaint := v1.Taint{
				Key:    testTaint.Key,
				Value:  "testing-taint-value-no-execute",
				Effect: v1.TaintEffectNoExecute,
			}
			By("adding NoExecute taint " + noExecuteTaint.ToString() + " to the node")
			runKubectlRetryOrDie("taint", "nodes", nodeName, noExecuteTaint.ToString())
			defer framework.RemoveTaintOffNode(f.ClientSet, nodeName, noExecuteTaint)

			By("verifying the node has the taint " + noExecuteTaint.ToString())
			output = runKubectlRetryOrDie("describe", "node", nodeName)
			requiredStrings = [][]string{
				{"Name:", nodeName},
				{"Taints:"},
				{noExecuteTaint.ToString()},
			}
			checkOutput(output, requiredStrings)

			By("removing all taints that have the same key " + testTaint.Key + " of the node")
			runKubectlRetryOrDie("taint", "nodes", nodeName, testTaint.Key+"-")
			By("verifying the node doesn't have the taints that have the same key " + testTaint.Key)
			output = runKubectlRetryOrDie("describe", "node", nodeName)
			if strings.Contains(output, testTaint.Key) {
				framework.Failf("Failed removing taints " + testTaint.Key + " of the node " + nodeName)
			}
		})
	})

	framework.KubeDescribe("Kubectl create quota", func() {
		It("should create a quota without scopes", func() {
			framework.SkipUnlessKubectlVersionGTE(kubectlCreateQuotaVersion)
			nsFlag := fmt.Sprintf("--namespace=%v", ns)
			quotaName := "million"

			By("calling kubectl quota")
			framework.RunKubectlOrDie("create", "quota", quotaName, "--hard=pods=1000000,services=1000000", nsFlag)

			By("verifying that the quota was created")
			quota, err := c.Core().ResourceQuotas(ns).Get(quotaName, metav1.GetOptions{})
			if err != nil {
				framework.Failf("Failed getting quota %s: %v", quotaName, err)
			}

			if len(quota.Spec.Scopes) != 0 {
				framework.Failf("Expected empty scopes, got %v", quota.Spec.Scopes)
			}
			if len(quota.Spec.Hard) != 2 {
				framework.Failf("Expected two resources, got %v", quota.Spec.Hard)
			}
			r, found := quota.Spec.Hard[v1.ResourcePods]
			if expected := resource.MustParse("1000000"); !found || (&r).Cmp(expected) != 0 {
				framework.Failf("Expected pods=1000000, got %v", r)
			}
			r, found = quota.Spec.Hard[v1.ResourceServices]
			if expected := resource.MustParse("1000000"); !found || (&r).Cmp(expected) != 0 {
				framework.Failf("Expected services=1000000, got %v", r)
			}
		})

		It("should create a quota with scopes", func() {
			framework.SkipUnlessKubectlVersionGTE(kubectlCreateQuotaVersion)
			nsFlag := fmt.Sprintf("--namespace=%v", ns)
			quotaName := "scopes"

			By("calling kubectl quota")
			framework.RunKubectlOrDie("create", "quota", quotaName, "--hard=pods=1000000", "--scopes=BestEffort,NotTerminating", nsFlag)

			By("verifying that the quota was created")
			quota, err := c.Core().ResourceQuotas(ns).Get(quotaName, metav1.GetOptions{})
			if err != nil {
				framework.Failf("Failed getting quota %s: %v", quotaName, err)
			}

			if len(quota.Spec.Scopes) != 2 {
				framework.Failf("Expected two scopes, got %v", quota.Spec.Scopes)
			}
			scopes := make(map[v1.ResourceQuotaScope]struct{})
			for _, scope := range quota.Spec.Scopes {
				scopes[scope] = struct{}{}
			}
			if _, found := scopes[v1.ResourceQuotaScopeBestEffort]; !found {
				framework.Failf("Expected BestEffort scope, got %v", quota.Spec.Scopes)
			}
			if _, found := scopes[v1.ResourceQuotaScopeNotTerminating]; !found {
				framework.Failf("Expected NotTerminating scope, got %v", quota.Spec.Scopes)
			}
		})

		It("should reject quota with invalid scopes", func() {
			framework.SkipUnlessKubectlVersionGTE(kubectlCreateQuotaVersion)
			nsFlag := fmt.Sprintf("--namespace=%v", ns)
			quotaName := "scopes"

			By("calling kubectl quota")
			out, err := framework.RunKubectl("create", "quota", quotaName, "--hard=hard=pods=1000000", "--scopes=Foo", nsFlag)
			if err == nil {
				framework.Failf("Expected kubectl to fail, but it succeeded: %s", out)
			}
		})
	})
})

// Checks whether the output split by line contains the required elements.
func checkOutputReturnError(output string, required [][]string) error {
	outputLines := strings.Split(output, "\n")
	currentLine := 0
	for _, requirement := range required {
		for currentLine < len(outputLines) && !strings.Contains(outputLines[currentLine], requirement[0]) {
			currentLine++
		}
		if currentLine == len(outputLines) {
			return fmt.Errorf("failed to find %s in %s", requirement[0], output)
		}
		for _, item := range requirement[1:] {
			if !strings.Contains(outputLines[currentLine], item) {
				return fmt.Errorf("failed to find %s in %s", item, outputLines[currentLine])
			}
		}
	}
	return nil
}

func checkOutput(output string, required [][]string) {
	err := checkOutputReturnError(output, required)
	if err != nil {
		framework.Failf("%v", err)
	}
}

func checkKubectlOutputWithRetry(required [][]string, args ...string) {
	var pollErr error
	wait.PollImmediate(time.Second, time.Minute, func() (bool, error) {
		output := framework.RunKubectlOrDie(args...)
		err := checkOutputReturnError(output, required)
		if err != nil {
			pollErr = err
			return false, nil
		}
		pollErr = nil
		return true, nil
	})
	if pollErr != nil {
		framework.Failf("%v", pollErr)
	}
	return
}

func getAPIVersions(apiEndpoint string) (*metav1.APIVersions, error) {
	body, err := curl(apiEndpoint)
	if err != nil {
		return nil, fmt.Errorf("Failed http.Get of %s: %v", apiEndpoint, err)
	}
	var apiVersions metav1.APIVersions
	if err := json.Unmarshal([]byte(body), &apiVersions); err != nil {
		return nil, fmt.Errorf("Failed to parse /api output %s: %v", body, err)
	}
	return &apiVersions, nil
}

func startProxyServer() (int, *exec.Cmd, error) {
	// Specifying port 0 indicates we want the os to pick a random port.
	cmd := framework.KubectlCmd("proxy", "-p", "0", "--disable-filter")
	stdout, stderr, err := framework.StartCmdAndStreamOutput(cmd)
	if err != nil {
		return -1, nil, err
	}
	defer stdout.Close()
	defer stderr.Close()
	buf := make([]byte, 128)
	var n int
	if n, err = stdout.Read(buf); err != nil {
		return -1, cmd, fmt.Errorf("Failed to read from kubectl proxy stdout: %v", err)
	}
	output := string(buf[:n])
	match := proxyRegexp.FindStringSubmatch(output)
	if len(match) == 2 {
		if port, err := strconv.Atoi(match[1]); err == nil {
			return port, cmd, nil
		}
	}
	return -1, cmd, fmt.Errorf("Failed to parse port from proxy stdout: %s", output)
}

func curlUnix(url string, path string) (string, error) {
	dial := func(proto, addr string) (net.Conn, error) {
		return net.Dial("unix", path)
	}
	transport := utilnet.SetTransportDefaults(&http.Transport{
		Dial: dial,
	})
	return curlTransport(url, transport)
}

func curlTransport(url string, transport *http.Transport) (string, error) {
	client := &http.Client{Transport: transport}
	resp, err := client.Get(url)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	return string(body[:]), nil
}

func curl(url string) (string, error) {
	return curlTransport(url, utilnet.SetTransportDefaults(&http.Transport{}))
}

func validateGuestbookApp(c clientset.Interface, ns string) {
	framework.Logf("Waiting for all frontend pods to be Running.")
	label := labels.SelectorFromSet(labels.Set(map[string]string{"tier": "frontend", "app": "guestbook"}))
	err := testutils.WaitForPodsWithLabelRunning(c, ns, label)
	Expect(err).NotTo(HaveOccurred())
	framework.Logf("Waiting for frontend to serve content.")
	if !waitForGuestbookResponse(c, "get", "", `{"data": ""}`, guestbookStartupTimeout, ns) {
		framework.Failf("Frontend service did not start serving content in %v seconds.", guestbookStartupTimeout.Seconds())
	}

	framework.Logf("Trying to add a new entry to the guestbook.")
	if !waitForGuestbookResponse(c, "set", "TestEntry", `{"message": "Updated"}`, guestbookResponseTimeout, ns) {
		framework.Failf("Cannot added new entry in %v seconds.", guestbookResponseTimeout.Seconds())
	}

	framework.Logf("Verifying that added entry can be retrieved.")
	if !waitForGuestbookResponse(c, "get", "", `{"data": "TestEntry"}`, guestbookResponseTimeout, ns) {
		framework.Failf("Entry to guestbook wasn't correctly added in %v seconds.", guestbookResponseTimeout.Seconds())
	}
}

// Returns whether received expected response from guestbook on time.
func waitForGuestbookResponse(c clientset.Interface, cmd, arg, expectedResponse string, timeout time.Duration, ns string) bool {
	for start := time.Now(); time.Since(start) < timeout; time.Sleep(5 * time.Second) {
		res, err := makeRequestToGuestbook(c, cmd, arg, ns)
		if err == nil && res == expectedResponse {
			return true
		}
		framework.Logf("Failed to get response from guestbook. err: %v, response: %s", err, res)
	}
	return false
}

func makeRequestToGuestbook(c clientset.Interface, cmd, value string, ns string) (string, error) {
	proxyRequest, errProxy := framework.GetServicesProxyRequest(c, c.Core().RESTClient().Get())
	if errProxy != nil {
		return "", errProxy
	}

	ctx, cancel := context.WithTimeout(context.Background(), framework.SingleCallTimeout)
	defer cancel()

	result, err := proxyRequest.Namespace(ns).
		Context(ctx).
		Name("frontend").
		Suffix("/guestbook.php").
		Param("cmd", cmd).
		Param("key", "messages").
		Param("value", value).
		Do().
		Raw()
	return string(result), err
}

type updateDemoData struct {
	Image string
}

const applyTestLabel = "kubectl.kubernetes.io/apply-test"

func readBytesFromFile(filename string) []byte {
	file, err := os.Open(filename)
	if err != nil {
		framework.Failf(err.Error())
	}
	defer file.Close()

	data, err := ioutil.ReadAll(file)
	if err != nil {
		framework.Failf(err.Error())
	}

	return data
}

func readReplicationControllerFromString(contents string) *v1.ReplicationController {
	rc := v1.ReplicationController{}
	if err := yaml.Unmarshal([]byte(contents), &rc); err != nil {
		framework.Failf(err.Error())
	}

	return &rc
}

func modifyReplicationControllerConfiguration(contents string) io.Reader {
	rc := readReplicationControllerFromString(contents)
	rc.Labels[applyTestLabel] = "ADDED"
	rc.Spec.Selector[applyTestLabel] = "ADDED"
	rc.Spec.Template.Labels[applyTestLabel] = "ADDED"
	data, err := json.Marshal(rc)
	if err != nil {
		framework.Failf("json marshal failed: %s\n", err)
	}

	return bytes.NewReader(data)
}

func forEachReplicationController(c clientset.Interface, ns, selectorKey, selectorValue string, fn func(v1.ReplicationController)) {
	var rcs *v1.ReplicationControllerList
	var err error
	for t := time.Now(); time.Since(t) < framework.PodListTimeout; time.Sleep(framework.Poll) {
		label := labels.SelectorFromSet(labels.Set(map[string]string{selectorKey: selectorValue}))
		options := metav1.ListOptions{LabelSelector: label.String()}
		rcs, err = c.Core().ReplicationControllers(ns).List(options)
		Expect(err).NotTo(HaveOccurred())
		if len(rcs.Items) > 0 {
			break
		}
	}

	if rcs == nil || len(rcs.Items) == 0 {
		framework.Failf("No replication controllers found")
	}

	for _, rc := range rcs.Items {
		fn(rc)
	}
}

func validateReplicationControllerConfiguration(rc v1.ReplicationController) {
	if rc.Name == "redis-master" {
		if _, ok := rc.Annotations[v1.LastAppliedConfigAnnotation]; !ok {
			framework.Failf("Annotation not found in modified configuration:\n%v\n", rc)
		}

		if value, ok := rc.Labels[applyTestLabel]; !ok || value != "ADDED" {
			framework.Failf("Added label %s not found in modified configuration:\n%v\n", applyTestLabel, rc)
		}
	}
}

// getUDData creates a validator function based on the input string (i.e. kitten.jpg).
// For example, if you send "kitten.jpg", this function verifies that the image jpg = kitten.jpg
// in the container's json field.
func getUDData(jpgExpected string, ns string) func(clientset.Interface, string) error {

	// getUDData validates data.json in the update-demo (returns nil if data is ok).
	return func(c clientset.Interface, podID string) error {
		framework.Logf("validating pod %s", podID)
		subResourceProxyAvailable, err := framework.ServerVersionGTE(framework.SubResourcePodProxyVersion, c.Discovery())
		if err != nil {
			return err
		}

		ctx, cancel := context.WithTimeout(context.Background(), framework.SingleCallTimeout)
		defer cancel()

		var body []byte
		if subResourceProxyAvailable {
			body, err = c.Core().RESTClient().Get().
				Namespace(ns).
				Resource("pods").
				SubResource("proxy").
				Name(podID).
				Suffix("data.json").
				Do().
				Raw()
		} else {
			body, err = c.Core().RESTClient().Get().
				Prefix("proxy").
				Namespace(ns).
				Resource("pods").
				Name(podID).
				Suffix("data.json").
				Do().
				Raw()
		}
		if err != nil {
			if ctx.Err() != nil {
				framework.Failf("Failed to retrieve data from container: %v", err)
			}
			return err
		}
		framework.Logf("got data: %s", body)
		var data updateDemoData
		if err := json.Unmarshal(body, &data); err != nil {
			return err
		}
		framework.Logf("Unmarshalled json jpg/img => %s , expecting %s .", data, jpgExpected)
		if strings.Contains(data.Image, jpgExpected) {
			return nil
		} else {
			return fmt.Errorf("data served up in container is inaccurate, %s didn't contain %s", data, jpgExpected)
		}
	}
}

func noOpValidatorFn(c clientset.Interface, podID string) error { return nil }

// newBlockingReader returns a reader that allows reading the given string,
// then blocks until Close() is called on the returned closer.
//
// We're explicitly returning the reader and closer separately, because
// the closer needs to be the *os.File we get from os.Pipe(). This is required
// so the exec of kubectl can pass the underlying file descriptor to the exec
// syscall, instead of creating another os.Pipe and blocking on the io.Copy
// between the source (e.g. stdin) and the write half of the pipe.
func newBlockingReader(s string) (io.Reader, io.Closer, error) {
	r, w, err := os.Pipe()
	if err != nil {
		return nil, nil, err
	}
	w.Write([]byte(s))
	return r, w, nil
}

// newStreamingUpload creates a new http.Request that will stream POST
// a file to a URI.
func newStreamingUpload(filePath string) (*io.PipeReader, *multipart.Writer, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, nil, err
	}
	defer file.Close()

	r, w := io.Pipe()

	postBodyWriter := multipart.NewWriter(w)

	go streamingUpload(file, filepath.Base(filePath), postBodyWriter, w)
	return r, postBodyWriter, err
}

// streamingUpload streams a file via a pipe through a multipart.Writer.
// Generally one should use newStreamingUpload instead of calling this directly.
func streamingUpload(file *os.File, fileName string, postBodyWriter *multipart.Writer, w *io.PipeWriter) {
	defer GinkgoRecover()
	defer file.Close()
	defer w.Close()

	// Set up the form file
	fileWriter, err := postBodyWriter.CreateFormFile("file", fileName)
	if err != nil {
		framework.Failf("Unable to to write file at %s to buffer. Error: %s", fileName, err)
	}

	// Copy kubectl binary into the file writer
	if _, err := io.Copy(fileWriter, file); err != nil {
		framework.Failf("Unable to to copy file at %s into the file writer. Error: %s", fileName, err)
	}

	// Nothing more should be written to this instance of the postBodyWriter
	if err := postBodyWriter.Close(); err != nil {
		framework.Failf("Unable to close the writer for file upload. Error: %s", err)
	}
}

func startLocalProxy() (srv *httptest.Server, logs *bytes.Buffer) {
	logs = &bytes.Buffer{}
	p := goproxy.NewProxyHttpServer()
	p.Verbose = true
	p.Logger = log.New(logs, "", 0)
	return httptest.NewServer(p), logs
}

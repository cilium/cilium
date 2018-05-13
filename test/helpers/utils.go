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

package helpers

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"io/ioutil"
	"math/rand"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/cilium/cilium/test/config"
	ginkgoext "github.com/cilium/cilium/test/ginkgo-ext"

	"github.com/Jeffail/gabs"
	"github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"k8s.io/apimachinery/pkg/util/yaml"
)

// IsRunningOnJenkins detects if the currently running Ginkgo application is
// most likely running in a Jenkins environment. Returns true if certain
// environment variables that are present in Jenkins jobs are set, false
// otherwise.
func IsRunningOnJenkins() bool {
	result := true

	env := []string{"JENKINS_HOME", "NODE_NAME"}

	for _, varName := range env {
		if val := os.Getenv(varName); val == "" {
			result = false
			log.Infof("build is not running on Jenkins; environment variable '%v' is not set", varName)
		}
	}
	return result
}

// Sleep sleeps for the specified duration in seconds
func Sleep(delay time.Duration) {
	time.Sleep(delay * time.Second)
}

// CountValues returns the count of the occurrences of key in data, as well as
// the length of data.
func CountValues(key string, data []string) (int, int) {
	var result int

	for _, x := range data {
		if x == key {
			result++
		}
	}
	return result, len(data)
}

// MakeUID returns a randomly generated string.
func MakeUID() string {
	return fmt.Sprintf("%08x", rand.Uint32())
}

// RenderTemplateToFile renders a text/template string into a target filename
// with specific persmisions. Returns eturn an error if the template cannot be
// validated or the file cannot be created.
func RenderTemplateToFile(filename string, tmplt string, perm os.FileMode) error {
	t, err := template.New("").Parse(tmplt)
	if err != nil {
		return err
	}
	content := new(bytes.Buffer)
	err = t.Execute(content, nil)
	if err != nil {
		return err
	}

	err = ioutil.WriteFile(filename, content.Bytes(), perm)
	if err != nil {
		return err
	}
	return nil
}

// TimeoutConfig represents the configuration for the timeout of a command.
type TimeoutConfig struct {
	Ticker  time.Duration // Check interval in duration.
	Timeout time.Duration // Timeout definition
}

// WithTimeout executes body using the time interval specified in config until
// the timeout in config is reached. Returns an error if the timeout is
// exceeded for body to execute successfully.
func WithTimeout(body func() bool, msg string, config *TimeoutConfig) error {
	if config.Ticker == 0 {
		config.Ticker = 5
	}

	done := time.After(config.Timeout * time.Second)
	ticker := time.NewTicker(config.Ticker * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			if body() {
				return nil
			}
		case <-done:
			return fmt.Errorf("Timeout reached: %s", msg)
		}
	}
}

// WithTimeoutErr executes body using the time interval specified. The function
// f is executed until bool returns true or the given context signalizes Done.
func WithTimeoutErr(ctx context.Context, f func() (bool, error), freq time.Duration) error {
	ticker := time.NewTicker(freq)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			exit, err := f()
			if err != nil {
				return err
			}
			if exit {
				return nil
			}
		}
	}
}

// InstallExampleCilium uses Cilium Kubernetes example from the repo,
// changes the etcd parameter and installs the stable tag from docker-hub
func InstallExampleCilium(kubectl *Kubectl) {

	var path = filepath.Join("..", "examples", "kubernetes", GetCurrentK8SEnv(), "cilium.yaml")
	var result bytes.Buffer
	timeout := time.Duration(300)

	newCiliumDSName := fmt.Sprintf("cilium_ds_%s.json", MakeUID())

	objects, err := DecodeYAMLOrJSON(path)
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
		value, _ = jsonObj.Path("kind").Data().(string)
		if value == daemonSet {
			container := jsonObj.Path("spec.template.spec.containers").Index(0)
			container.Set(StableImage, "image")
		}
		result.WriteString(jsonObj.String())
	}

	fp, err := os.Create(newCiliumDSName)
	defer fp.Close()
	Expect(err).To(BeNil())

	fmt.Fprint(fp, result.String())

	kubectl.Apply(GetFilePath(newCiliumDSName)).ExpectSuccess(
		"cannot apply cilium example daemonset")

	err = kubectl.WaitforPods(
		KubeSystemNamespace, "-l k8s-app=cilium", timeout)
	ExpectWithOffset(1, err).Should(BeNil(), "Cilium is not ready after timeout")

	ginkgoext.By(fmt.Sprintf("Checking that installed image is %q", StableImage))

	filter := `{.items[*].status.containerStatuses[0].image}`
	data, err := kubectl.GetPods(
		KubeSystemNamespace, "-l k8s-app=cilium").Filter(filter)
	ExpectWithOffset(1, err).To(BeNil(), "Cannot get cilium pods")

	for _, val := range strings.Split(data.String(), " ") {
		ExpectWithOffset(1, val).To(Equal(StableImage), "Cilium image didn't update correctly")
	}
}

// GetAppPods fetches app pod names for a namespace.
// For Http based tests, we identify pods with format id=<pod_name>, while
// for Kafka based tests, we identify pods with the format app=<pod_name>.
func GetAppPods(apps []string, namespace string, kubectl *Kubectl, appFmt string) map[string]string {
	appPods := make(map[string]string)
	for _, v := range apps {
		res, err := kubectl.GetPodNames(namespace, fmt.Sprintf("%s=%s", appFmt, v))
		Expect(err).Should(BeNil())
		Expect(res).Should(Not(BeNil()))
		appPods[v] = res[0]
		log.Infof("GetAppPods: pod=%q assigned to %q", res[0], v)
	}
	return appPods
}

// WaitCiliumEndpointReady gets cilium pod for a ginkgo node (k8s1/k8s2)
// and waits for all the endpoints of that node to be ready.
func (kubectl *Kubectl) WaitCiliumEndpointReady(podFilter string, k8sNode string) (string, EndpointMap) {
	ciliumPod, err := kubectl.GetCiliumPodOnNode(KubeSystemNamespace, k8sNode)
	Expect(err).Should(BeNil())

	status := kubectl.CiliumExec(ciliumPod, fmt.Sprintf("cilium config %s=%s", PolicyEnforcement, PolicyEnforcementDefault))
	status.ExpectSuccess()

	kubectl.CiliumEndpointWait(ciliumPod)

	epsStatus := WithTimeout(func() bool {
		endpoints, err := kubectl.CiliumEndpointsListByLabel(ciliumPod, podFilter)
		if err != nil {
			return false
		}
		return endpoints.AreReady()
	}, "Could not get endpoints", &TimeoutConfig{Timeout: 100})
	Expect(epsStatus).Should(BeNil())

	endpoints, err := kubectl.CiliumEndpointsListByLabel(ciliumPod, podFilter)
	Expect(err).Should(BeNil())

	Expect(endpoints.AreReady()).Should(BeTrue())
	return ciliumPod, endpoints
}

// WaitUntilEndpointUpdates checks the policy version and then iterates through
// all endpoints waiting for the endpoints to have updated policies.
func WaitUntilEndpointUpdates(pod string, eps map[string]int64, min int, kubectl *Kubectl) error {
	body := func() bool {
		updated := 0
		newEps := kubectl.CiliumEndpointPolicyVersion(pod)
		for k, v := range newEps {
			if eps[k] < v {
				log.Infof("Endpoint %s had version %d now %d updated : %d", k, eps[k], v, updated)
				updated++
			}
		}
		return updated >= min
	}
	err := WithTimeout(body, "No new version applied", &TimeoutConfig{Timeout: 100})
	return err
}

// Fail is a Ginkgo failure handler which raises a SIGSTOP for the test process
// when there is a failure, so that developers can debug the live environment.
// It is only triggered if the developer provides a commandline flag.
func Fail(description string, callerSkip ...int) {
	if len(callerSkip) > 0 {
		callerSkip[0]++
	} else {
		callerSkip = []int{1}
	}

	if config.CiliumTestConfig.HoldEnvironment {
		test := ginkgo.CurrentGinkgoTestDescription()
		pid := syscall.Getpid()

		fmt.Fprintf(os.Stdout, "\n---\n%s", test.FullTestText)
		fmt.Fprintf(os.Stdout, "\nat %s:%d", test.FileName, test.LineNumber)
		fmt.Fprintf(os.Stdout, "\n\n%s", description)
		fmt.Fprintf(os.Stdout, "\n\nPausing test for debug, use vagrant to access test setup.")
		fmt.Fprintf(os.Stdout, "\nRun \"kill -SIGCONT %d\" to continue.\n", pid)
		syscall.Kill(pid, syscall.SIGSTOP)
	}
	ginkgoext.Fail(description, callerSkip...)
}

// CreateReportDirectory creates and returns the directory path to export all report
// commands that need to be run in the case that a test has failed.
// If the directory cannot be created it'll return an error
func CreateReportDirectory() (string, error) {
	prefix := ""
	testName := ginkgoext.GetTestName()
	if strings.HasPrefix(strings.ToLower(testName), K8s) {
		prefix = fmt.Sprintf("%s-", strings.Replace(GetCurrentK8SEnv(), ".", "", -1))
	}

	testPath := filepath.Join(
		TestResultsPath,
		prefix,
		testName)
	if _, err := os.Stat(testPath); err == nil {
		return testPath, nil
	}
	err := os.MkdirAll(testPath, os.ModePerm)
	return testPath, err
}

// CreateLogFile creates the ReportDirectory if it is not present, writes the
// given data to the given filename.
func CreateLogFile(filename string, data []byte) error {
	path, err := CreateReportDirectory()
	if err != nil {
		log.WithError(err).Errorf("ReportDirectory cannot be created")
		return err
	}

	finalPath := filepath.Join(path, filename)
	err = ioutil.WriteFile(finalPath, data, LogPerm)
	return err
}

// reportMap saves the output of the given commands to the specified filename.
// Function needs a directory path where the files are going to be written and
// a *SSHMeta instance to execute the commands
func reportMap(path string, reportCmds map[string]string, node *SSHMeta) {
	if node == nil {
		log.Errorf("cannot execute reportMap due invalid node instance")
		return
	}

	for cmd, logfile := range reportCmds {
		res := node.Exec(cmd, ExecOptions{SkipLog: true})
		err := ioutil.WriteFile(
			fmt.Sprintf("%s/%s", path, logfile),
			res.CombineOutput().Bytes(),
			LogPerm)
		if err != nil {
			log.WithError(err).Errorf("cannot create test results for command '%s'", cmd)
		}
	}
}

// DecodeYAMLOrJSON reads a json or yaml file and exports all documents as an
// array of interfaces. In case of an invalid path or invalid format it returns
// an error.
func DecodeYAMLOrJSON(path string) ([]interface{}, error) {
	var result []interface{}
	content, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}
	d := yaml.NewYAMLOrJSONDecoder(bytes.NewReader(content), 4096)
	for {
		var ext interface{}
		if err := d.Decode(&ext); err != nil {
			if err == io.EOF {
				break
			}
			return nil, fmt.Errorf("cannot decode the content: %s", err)
		}
		result = append(result, ext)
	}
	return result, nil
}

// ManifestGet returns the full path of the given manifest corresponding to the
// Kubernetes version being tested, if such a manifest exists, if not it
// returns the global manifest file.
func ManifestGet(manifestFilename string) string {
	fullPath := filepath.Join(manifestsPath, GetCurrentK8SEnv(), manifestFilename)
	_, err := os.Stat(fullPath)
	if err == nil {
		return filepath.Join(BasePath, fullPath)
	}
	return filepath.Join(BasePath, "k8sT", "manifests", manifestFilename)
}

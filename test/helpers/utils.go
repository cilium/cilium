// Copyright 2017-2019 Authors of Cilium
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
	"fmt"
	"html/template"
	"io"
	"io/ioutil"
	"math/rand"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/cilium/cilium/pkg/versioncheck"
	"github.com/cilium/cilium/test/config"
	"github.com/cilium/cilium/test/ginkgo-ext"

	go_version "github.com/hashicorp/go-version"
	"github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

func init() {
	// ensure that our random numbers are seeded differently on each run
	rand.Seed(time.Now().UnixNano())
}

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
	Ticker  time.Duration // Check interval
	Timeout time.Duration // Limit for how long to spend in the command
}

// WithTimeout executes body using the time interval specified in config until
// the timeout in config is reached. Returns an error if the timeout is
// exceeded for body to execute successfully.
func WithTimeout(body func() bool, msg string, config *TimeoutConfig) error {
	if config.Ticker == 0 {
		config.Ticker = 5
	}

	done := time.After(config.Timeout)
	ticker := time.NewTicker(config.Ticker)
	defer ticker.Stop()
	if body() {
		return nil
	}
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

// WithContext executes body with the given frequency. The function
// f is executed until bool returns true or the given context signalizes Done.
// `f` should stop if context is canceled.
func WithContext(ctx context.Context, f func(ctx context.Context) (bool, error), freq time.Duration) error {
	ticker := time.NewTicker(freq)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			stop, err := f(ctx)
			if err != nil {
				select {
				case <-ctx.Done():
					return ctx.Err()
				default:
					return err
				}
			}
			if stop {
				select {
				case <-ctx.Done():
					return ctx.Err()
				default:
					return nil
				}
			}
		}
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

// HoldEnvironment prints the current test status, then pauses the test
// execution. Developers who are writing tests may wish to invoke this function
// directly from test code to assist troubleshooting and test development.
func HoldEnvironment(description ...string) {
	test := ginkgo.CurrentGinkgoTestDescription()
	pid := syscall.Getpid()

	fmt.Fprintf(os.Stdout, "\n---\n%s", test.FullTestText)
	fmt.Fprintf(os.Stdout, "\nat %s:%d", test.FileName, test.LineNumber)
	fmt.Fprintf(os.Stdout, "\n\n%s", description)
	fmt.Fprintf(os.Stdout, "\n\nPausing test for debug, use vagrant to access test setup.")
	fmt.Fprintf(os.Stdout, "\nRun \"kill -SIGCONT %d\" to continue.\n", pid)
	syscall.Kill(pid, syscall.SIGSTOP)
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
		HoldEnvironment(description)
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

// ManifestGet returns the full path of the given manifest corresponding to the
// Kubernetes version being tested, if such a manifest exists, if not it
// returns the global manifest file.
func ManifestGet(manifestFilename string) string {
	// try dependent integration file
	fullPath := filepath.Join(manifestsPath, GetCurrentIntegration(), manifestFilename)
	_, err := os.Stat(fullPath)
	if err == nil {
		return filepath.Join(BasePath, fullPath)
	}

	// try dependent k8s version and integration file
	fullPath = filepath.Join(manifestsPath, GetCurrentK8SEnv(), GetCurrentIntegration(), manifestFilename)
	_, err = os.Stat(fullPath)
	if err == nil {
		return filepath.Join(BasePath, fullPath)
	}

	// try dependent k8s version
	fullPath = filepath.Join(manifestsPath, GetCurrentK8SEnv(), manifestFilename)
	_, err = os.Stat(fullPath)
	if err == nil {
		return filepath.Join(BasePath, fullPath)
	}
	return filepath.Join(BasePath, "k8sT", "manifests", manifestFilename)
}

// GetK8sDescriptor returns the full path of the given descriptorFilename that
// exists in the descriptorsPath. If not found, the returned path will be empty.
func GetK8sDescriptor(descriptorFilename string) string {
	fullPath := filepath.Join(descriptorsPath, GetCurrentK8SEnv(), descriptorFilename)
	_, err := os.Stat(fullPath)
	if err == nil {
		return filepath.Join(BasePath, fullPath)
	}
	return ""
}

// WriteOrAppendToFile writes data to a file named by filename.
// If the file does not exist, WriteFile creates it with permissions perm;
// otherwise WriteFile appends the data to the file
func WriteOrAppendToFile(filename string, data []byte, perm os.FileMode) error {
	f, err := os.OpenFile(filename, os.O_APPEND|os.O_WRONLY|os.O_CREATE, perm)
	if err != nil {
		return err
	}
	n, err := f.Write(data)
	if err == nil && n < len(data) {
		err = io.ErrShortWrite
	}
	if err1 := f.Close(); err == nil {
		err = err1
	}
	return err
}

// DNSDeployment returns the manifest to install dns engine on the server.
func DNSDeployment() string {
	var DNSEngine = "kubedns"
	k8sVersion := GetCurrentK8SEnv()
	switch k8sVersion {
	case "1.11", "1.12", "1.13":
		DNSEngine = "coredns"
	}
	fullPath := filepath.Join("provision", "manifest", k8sVersion, DNSEngine+"_deployment.yaml")
	_, err := os.Stat(fullPath)
	if err == nil {
		return filepath.Join(BasePath, fullPath)
	}
	return filepath.Join(BasePath, "provision", "manifest", DNSEngine+"_deployment.yaml")
}

// getK8sSupportedConstraints returns the Kubernetes versions supported by
// a specific Cilium version.
func getK8sSupportedConstraints(ciliumVersion string) (go_version.Constraints, error) {
	cst, err := go_version.NewVersion(ciliumVersion)
	if err != nil {
		return nil, err
	}
	// Make pre-releases part of the official release
	strSegments := make([]string, len(cst.Segments()))
	if cst.Prerelease() != "" {
		for i, segment := range cst.Segments() {
			strSegments[i] = strconv.Itoa(segment)
		}
		ciliumVersion = strings.Join(strSegments, ".")
		cst, err = go_version.NewVersion(ciliumVersion)
		if err != nil {
			return nil, err
		}
	}
	switch {
	case CiliumV1_0.Check(cst):
		return versioncheck.MustCompile(">= 1.7, <1.13"), nil
	case CiliumV1_1.Check(cst):
		return versioncheck.MustCompile(">= 1.8, <1.13"), nil
	case CiliumV1_2.Check(cst):
		return versioncheck.MustCompile(">= 1.8, <1.13"), nil
	case CiliumV1_3.Check(cst):
		return versioncheck.MustCompile(">= 1.8, <1.13"), nil
	case CiliumV1_4.Check(cst):
		return versioncheck.MustCompile(">= 1.8, <1.14"), nil
	case CiliumV1_5.Check(cst):
		return versioncheck.MustCompile(">= 1.8, <1.14"), nil
	default:
		return nil, fmt.Errorf("unrecognized version '%s'", ciliumVersion)
	}
}

// CanRunK8sVersion returns true if the givel ciliumVersion can run in the given
// Kubernetes version. If any version is unparsable, an error is returned.
func CanRunK8sVersion(ciliumVersion, k8sVersionStr string) (bool, error) {
	k8sVersion, err := go_version.NewVersion(k8sVersionStr)
	if err != nil {
		return false, err
	}
	constraint, err := getK8sSupportedConstraints(ciliumVersion)
	if err != nil {
		return false, err
	}
	return constraint.Check(k8sVersion), nil
}

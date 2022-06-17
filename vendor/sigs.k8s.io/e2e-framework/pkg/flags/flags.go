/*
Copyright 2021 The Kubernetes Authors.

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

package flags

import (
	"flag"
	"fmt"
	"os"
	"strings"

	"k8s.io/klog/v2"
)

const (
	flagNamespaceName      = "namespace"
	flagKubecofigName      = "kubeconfig"
	flagFeatureName        = "feature"
	flagAssessName         = "assess"
	flagLabelsName         = "labels"
	flagSkipLabelName      = "skip-labels"
	flagSkipFeatureName    = "skip-features"
	flagSkipAssessmentName = "skip-assessment"
	flagParallelTestsName  = "parallel"
	flagDryRunName         = "dry-run"
	flagFailFast           = "fail-fast"
)

// Supported flag definitions
var (
	featureFlag = flag.Flag{
		Name:  flagFeatureName,
		Usage: "Regular expression to select feature(s) to test",
	}
	assessFlag = flag.Flag{
		Name:  flagAssessName,
		Usage: "Regular expression to select assessment(s) to run",
	}
	labelsFlag = flag.Flag{
		Name:  flagLabelsName,
		Usage: "Comma-separated key=value to filter features by labels",
	}
	kubecfgFlag = flag.Flag{
		Name:  flagKubecofigName,
		Usage: "Path to a cluster kubeconfig file (optional)",
	}
	kubeNSFlag = flag.Flag{
		Name:  flagNamespaceName,
		Usage: "A namespace value to use for testing (optional)",
	}
	skipLabelsFlag = flag.Flag{
		Name:  flagSkipLabelName,
		Usage: "Regular expression to skip label(s) to run",
	}
	skipFeatureFlag = flag.Flag{
		Name:  flagSkipFeatureName,
		Usage: "Regular expression to skip feature(s) to run",
	}
	skipAssessmentFlag = flag.Flag{
		Name:  flagSkipAssessmentName,
		Usage: "Regular expression to skip assessment(s) to run",
	}
	parallelTestsFlag = flag.Flag{
		Name:  flagParallelTestsName,
		Usage: "Run test features in parallel",
	}
	dryRunFlag = flag.Flag{
		Name:  flagDryRunName,
		Usage: "Run Test suite in dry-run mode. This will list the tests to be executed without actually running them",
	}

	failFastFlag = flag.Flag{
		Name:  flagFailFast,
		Usage: "Fail immediately and stop running untested code",
	}
)

// EnvFlags surfaces all resolved flag values for the testing framework
type EnvFlags struct {
	feature         string
	assess          string
	labels          LabelsMap
	kubeconfig      string
	namespace       string
	skiplabels      LabelsMap
	skipFeatures    string
	skipAssessments string
	parallelTests   bool
	dryRun          bool
	failFast        bool
}

// Feature returns value for `-feature` flag
func (f *EnvFlags) Feature() string {
	return f.feature
}

// Assessment returns value for `-assess` flag
func (f *EnvFlags) Assessment() string {
	return f.assess
}

// Labels returns a map of parsed key/value from `-labels` flag
func (f *EnvFlags) Labels() LabelsMap {
	return f.labels
}

// Namespace returns an optional namespace flag value
func (f *EnvFlags) Namespace() string {
	return f.namespace
}

// SkipFeatures is used to get a RegExp pattern that can be used
// to skip test features from getting executed
func (f *EnvFlags) SkipFeatures() string {
	return f.skipFeatures
}

// SkipAssessment is used to track the RegExp pattern that can be
// used to skip certain assessments of the current feature being
// executed
func (f *EnvFlags) SkipAssessment() string {
	return f.skipAssessments
}

// SkipLabels is used to define a series of labels that can be used
// to skip test cases during execution
func (f *EnvFlags) SkipLabels() LabelsMap {
	return f.skiplabels
}

// Kubeconfig returns an optional path for kubeconfig file
func (f *EnvFlags) Kubeconfig() string {
	return f.kubeconfig
}

// Parallel is used to indicate if the test features should be run in parallel
// under a go-routine
func (f *EnvFlags) Parallel() bool {
	return f.parallelTests
}

func (f *EnvFlags) DryRun() bool {
	return f.dryRun
}

// FailFast is used to indicate if the failure of an assessment should continue
// assessing the rest of the features or skip it and continue to the next one.
// This is set to false by default.
func (f *EnvFlags) FailFast() bool {
	return f.failFast
}

// Parse parses defined CLI args os.Args[1:]
func Parse() (*EnvFlags, error) {
	return ParseArgs(os.Args[1:])
}

// ParseArgs parses the specified args from global flag.CommandLine
// and returns a set of environment flag values.
func ParseArgs(args []string) (*EnvFlags, error) {
	var (
		feature        string
		assess         string
		namespace      string
		kubeconfig     string
		skipFeature    string
		skipAssessment string
		parallelTests  bool
		dryRun         bool
		failFast       bool
	)

	labels := make(LabelsMap)
	skipLabels := make(LabelsMap)

	if flag.Lookup(featureFlag.Name) == nil {
		flag.StringVar(&feature, featureFlag.Name, featureFlag.DefValue, featureFlag.Usage)
	}

	if flag.Lookup(assessFlag.Name) == nil {
		flag.StringVar(&assess, assessFlag.Name, assessFlag.DefValue, assessFlag.Usage)
	}

	if flag.Lookup(kubecfgFlag.Name) == nil {
		flag.StringVar(&kubeconfig, kubecfgFlag.Name, kubecfgFlag.DefValue, kubecfgFlag.Usage)
	}

	if flag.Lookup(kubeNSFlag.Name) == nil {
		flag.StringVar(&namespace, kubeNSFlag.Name, kubeNSFlag.DefValue, kubeNSFlag.Usage)
	}

	if flag.Lookup(labelsFlag.Name) == nil {
		flag.Var(&labels, labelsFlag.Name, labelsFlag.Usage)
	}

	if flag.Lookup(skipLabelsFlag.Name) == nil {
		flag.Var(&skipLabels, skipLabelsFlag.Name, skipLabelsFlag.Usage)
	}

	if flag.Lookup(skipAssessmentFlag.Name) == nil {
		flag.StringVar(&skipAssessment, skipAssessmentFlag.Name, skipAssessmentFlag.DefValue, skipAssessmentFlag.Usage)
	}

	if flag.Lookup(skipFeatureFlag.Name) == nil {
		flag.StringVar(&skipFeature, skipFeatureFlag.Name, skipFeatureFlag.DefValue, skipFeatureFlag.Usage)
	}

	if flag.Lookup(parallelTestsFlag.Name) == nil {
		flag.BoolVar(&parallelTests, parallelTestsFlag.Name, false, parallelTestsFlag.Usage)
	}

	if flag.Lookup(dryRunFlag.Name) == nil {
		flag.BoolVar(&dryRun, dryRunFlag.Name, false, dryRunFlag.Usage)
	}

	if flag.Lookup(failFastFlag.Name) == nil {
		flag.BoolVar(&failFast, failFastFlag.Name, false, failFastFlag.Usage)
	}

	// Enable klog/v2 flag integration
	klog.InitFlags(nil)

	if err := flag.CommandLine.Parse(args); err != nil {
		return nil, fmt.Errorf("flags parsing: %w", err)
	}

	// Hook into the default test.list of the `go test` and integrate that with the `--dry-run` behavior. Treat them the same way
	if !dryRun && flag.Lookup("test.list") != nil && flag.Lookup("test.list").Value.String() == "true" {
		klog.V(2).Info("Enabling dry-run mode as the tests were invoked in list mode")
		dryRun = true
	}

	if failFast && parallelTests {
		panic(fmt.Errorf("--fail-fast and --parallel are mutually exclusive options"))
	}

	return &EnvFlags{
		feature:         feature,
		assess:          assess,
		labels:          labels,
		namespace:       namespace,
		kubeconfig:      kubeconfig,
		skiplabels:      skipLabels,
		skipFeatures:    skipFeature,
		skipAssessments: skipAssessment,
		parallelTests:   parallelTests,
		dryRun:          dryRun,
		failFast:        failFast,
	}, nil
}

type LabelsMap map[string]string

func (m LabelsMap) String() string {
	i := map[string]string(m)
	return fmt.Sprint(i)
}

func (m LabelsMap) Set(val string) error {
	// label: []string{"key=value",...}
	for _, label := range strings.Split(val, ",") {
		// split into k,v
		kv := strings.Split(label, "=")
		if len(kv) != 2 {
			return fmt.Errorf("label format error: %s", label)
		}
		m[strings.TrimSpace(kv[0])] = strings.TrimSpace(kv[1])
	}

	return nil
}

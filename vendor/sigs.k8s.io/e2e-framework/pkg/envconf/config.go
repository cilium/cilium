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

package envconf

import (
	"encoding/hex"
	"fmt"
	"math/rand"
	"regexp"
	"time"

	log "k8s.io/klog/v2"

	"sigs.k8s.io/e2e-framework/klient"
	"sigs.k8s.io/e2e-framework/pkg/flags"
)

// Config represents and environment configuration
type Config struct {
	client              klient.Client
	kubeconfig          string
	namespace           string
	assessmentRegex     *regexp.Regexp
	featureRegex        *regexp.Regexp
	labels              map[string]string
	skipFeatureRegex    *regexp.Regexp
	skipLabels          map[string]string
	skipAssessmentRegex *regexp.Regexp
	parallelTests       bool
	dryRun              bool
	failFast            bool
}

// New creates and initializes an empty environment configuration
func New() *Config {
	return &Config{}
}

// NewWithKubeConfig creates and initializes an empty environment configuration
func NewWithKubeConfig(kubeconfig string) *Config {
	c := &Config{}
	return c.WithKubeconfigFile(kubeconfig)
}

// NewFromFlags initializes an environment config using flag values
// parsed from command-line arguments and returns an error on parsing failure.
func NewFromFlags() (*Config, error) {
	envFlags, err := flags.Parse()
	if err != nil {
		log.Fatalf("flags parse failed: %s", err)
	}
	e := New()
	if envFlags.Assessment() != "" {
		e.assessmentRegex = regexp.MustCompile(envFlags.Assessment())
	}
	if envFlags.Feature() != "" {
		e.featureRegex = regexp.MustCompile(envFlags.Feature())
	}
	e.labels = envFlags.Labels()
	e.namespace = envFlags.Namespace()
	e.kubeconfig = envFlags.Kubeconfig()
	if envFlags.SkipFeatures() != "" {
		e.skipFeatureRegex = regexp.MustCompile(envFlags.SkipFeatures())
	}
	if envFlags.SkipAssessment() != "" {
		e.skipAssessmentRegex = regexp.MustCompile(envFlags.SkipAssessment())
	}
	e.skipLabels = envFlags.SkipLabels()
	e.parallelTests = envFlags.Parallel()
	e.dryRun = envFlags.DryRun()
	e.failFast = envFlags.FailFast()

	return e, nil
}

// WithKubeconfigFile creates a new klient.Client and injects it in the cfg
func (c *Config) WithKubeconfigFile(kubecfg string) *Config {
	c.kubeconfig = kubecfg
	return c
}

func (c *Config) KubeconfigFile() string {
	return c.kubeconfig
}

// WithClient used to update the environment klient.Client
func (c *Config) WithClient(client klient.Client) *Config {
	c.client = client
	return c
}

// NewClient is a constructor function that returns a previously
// created klient.Client or create a new one based on configuration
// previously set. Will return an error if unable to do so.
func (c *Config) NewClient() (klient.Client, error) {
	if c.client != nil {
		return c.client, nil
	}

	client, err := klient.NewWithKubeConfigFile(c.kubeconfig)
	if err != nil {
		return nil, fmt.Errorf("envconfig: client failed: %w", err)
	}
	c.client = client

	return c.client, nil
}

// Client is a constructor function that returns a previously
// created klient.Client or creates a new one based on configuration
// previously set. Will panic on any error so it is recommended that you
// are confident in the configuration or call NewClient() to ensure its
// safe creation.
func (c *Config) Client() klient.Client {
	if c.client != nil {
		return c.client
	}

	client, err := klient.NewWithKubeConfigFile(c.kubeconfig)
	if err != nil {
		panic(fmt.Errorf("envconfig: client failed: %w", err).Error())
	}
	c.client = client
	return c.client
}

// WithNamespace updates the environment namespace value
func (c *Config) WithNamespace(ns string) *Config {
	c.namespace = ns
	return c
}

// WithRandomNamespace sets the environment's namespace
// to a random value
func (c *Config) WithRandomNamespace() *Config {
	c.namespace = randNS()
	return c
}

// Namespace returns the namespace for the environment
func (c *Config) Namespace() string {
	return c.namespace
}

// WithAssessmentRegex sets the environment assessment regex filter
func (c *Config) WithAssessmentRegex(regex string) *Config {
	c.assessmentRegex = regexp.MustCompile(regex)
	return c
}

// AssessmentRegex returns the environment assessment filter
func (c *Config) AssessmentRegex() *regexp.Regexp {
	return c.assessmentRegex
}

// WithSkipAssessmentRegex sets the environment assessment regex filter
func (c *Config) WithSkipAssessmentRegex(regex string) *Config {
	c.skipAssessmentRegex = regexp.MustCompile(regex)
	return c
}

// SkipAssessmentRegex returns the environment assessment filter
func (c *Config) SkipAssessmentRegex() *regexp.Regexp {
	return c.skipAssessmentRegex
}

// WithFeatureRegex sets the environment's feature regex filter
func (c *Config) WithFeatureRegex(regex string) *Config {
	c.featureRegex = regexp.MustCompile(regex)
	return c
}

// FeatureRegex returns the environment's feature regex filter
func (c *Config) FeatureRegex() *regexp.Regexp {
	return c.featureRegex
}

// WithSkipFeatureRegex sets the environment's skip feature regex filter
func (c *Config) WithSkipFeatureRegex(regex string) *Config {
	c.skipFeatureRegex = regexp.MustCompile(regex)
	return c
}

// SkipFeatureRegex returns the environment's skipfeature regex filter
func (c *Config) SkipFeatureRegex() *regexp.Regexp {
	return c.skipFeatureRegex
}

// WithLabels sets the environment label filters
func (c *Config) WithLabels(lbls map[string]string) *Config {
	c.labels = lbls
	return c
}

// Labels returns the environment's label filters
func (c *Config) Labels() map[string]string {
	return c.labels
}

// WithSkipLabels sets the environment label filters
func (c *Config) WithSkipLabels(lbls map[string]string) *Config {
	c.skipLabels = lbls
	return c
}

// SkipLabels returns the environment's label filters
func (c *Config) SkipLabels() map[string]string {
	return c.skipLabels
}

// WithParallelTestEnabled can be used to enable parallel run of the test
// features
func (c *Config) WithParallelTestEnabled() *Config {
	c.parallelTests = true
	return c
}

// ParallelTestEnabled indicates if the test features are being run in
// parallel or not
func (c *Config) ParallelTestEnabled() bool {
	return c.parallelTests
}

func (c *Config) WithDryRunMode() *Config {
	c.dryRun = true
	return c
}

func (c *Config) DryRunMode() bool {
	return c.dryRun
}

// WithFailFast can be used to enable framework specific fail fast mode
// that controls the test execution of the features and assessments under
// test
func (c *Config) WithFailFast() *Config {
	c.failFast = true
	return c
}

// FailFast indicate if the framework is running in fail fast mode. This
// controls the behavior of how the assessments and features are handled
// if a test encounters a failure result
func (c *Config) FailFast() bool {
	return c.failFast
}

func randNS() string {
	return RandomName("testns-", 32)
}

// RandomName generates a random name of n length with the provided
// prefix. If prefix is omitted, the then entire name is random char.
func RandomName(prefix string, n int) string {
	if n == 0 {
		n = 32
	}
	if len(prefix) >= n {
		return prefix
	}
	rand.Seed(time.Now().UnixNano())
	p := make([]byte, n)
	rand.Read(p)
	return fmt.Sprintf("%s-%s", prefix, hex.EncodeToString(p))[:n]
}

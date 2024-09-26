/*
Copyright 2024 The Kubernetes Authors.

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

package conformance

import (
	"io/fs"
	"os"
	"testing"

	v1 "sigs.k8s.io/gateway-api/apis/v1"
	"sigs.k8s.io/gateway-api/apis/v1alpha2"
	"sigs.k8s.io/gateway-api/apis/v1alpha3"
	"sigs.k8s.io/gateway-api/apis/v1beta1"
	confv1 "sigs.k8s.io/gateway-api/conformance/apis/v1"
	"sigs.k8s.io/gateway-api/conformance/tests"
	conformanceconfig "sigs.k8s.io/gateway-api/conformance/utils/config"
	"sigs.k8s.io/gateway-api/conformance/utils/flags"
	"sigs.k8s.io/gateway-api/conformance/utils/suite"

	"github.com/stretchr/testify/require"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	clientset "k8s.io/client-go/kubernetes"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/config"
	"sigs.k8s.io/yaml"
)

// DefaultOptions will parse command line flags to populate a
// ConformanceOptions struct. It will also initialize the various clients
// required by the tests.
func DefaultOptions(t *testing.T) suite.ConformanceOptions {
	cfg, err := config.GetConfig()
	require.NoError(t, err, "error loading Kubernetes config")
	clientOptions := client.Options{}
	client, err := client.New(cfg, clientOptions)
	require.NoError(t, err, "error initializing Kubernetes client")

	// This clientset is needed in addition to the client only because
	// controller-runtime client doesn't support non CRUD sub-resources yet
	// (https://github.com/kubernetes-sigs/controller-runtime/issues/452).
	clientset, err := clientset.NewForConfig(cfg)
	require.NoError(t, err, "error initializing Kubernetes clientset")

	require.NoError(t, v1alpha3.Install(client.Scheme()))
	require.NoError(t, v1alpha2.Install(client.Scheme()))
	require.NoError(t, v1beta1.Install(client.Scheme()))
	require.NoError(t, v1.Install(client.Scheme()))
	require.NoError(t, apiextensionsv1.AddToScheme(client.Scheme()))

	supportedFeatures := suite.ParseSupportedFeatures(*flags.SupportedFeatures)
	exemptFeatures := suite.ParseSupportedFeatures(*flags.ExemptFeatures)
	skipTests := suite.ParseSkipTests(*flags.SkipTests)
	namespaceLabels := suite.ParseKeyValuePairs(*flags.NamespaceLabels)
	namespaceAnnotations := suite.ParseKeyValuePairs(*flags.NamespaceAnnotations)
	conformanceProfiles := suite.ParseConformanceProfiles(*flags.ConformanceProfiles)

	implementation := suite.ParseImplementation(
		*flags.ImplementationOrganization,
		*flags.ImplementationProject,
		*flags.ImplementationURL,
		*flags.ImplementationVersion,
		*flags.ImplementationContact,
	)

	return suite.ConformanceOptions{
		AllowCRDsMismatch:          *flags.AllowCRDsMismatch,
		CleanupBaseResources:       *flags.CleanupBaseResources,
		Client:                     client,
		ClientOptions:              clientOptions,
		Clientset:                  clientset,
		ConformanceProfiles:        conformanceProfiles,
		Debug:                      *flags.ShowDebug,
		EnableAllSupportedFeatures: *flags.EnableAllSupportedFeatures,
		ExemptFeatures:             exemptFeatures,
		ManifestFS:                 []fs.FS{&Manifests},
		GatewayClassName:           *flags.GatewayClassName,
		Implementation:             implementation,
		Mode:                       *flags.Mode,
		NamespaceAnnotations:       namespaceAnnotations,
		NamespaceLabels:            namespaceLabels,
		ReportOutputPath:           *flags.ReportOutput,
		RestConfig:                 cfg,
		RunTest:                    *flags.RunTest,
		SkipTests:                  skipTests,
		SupportedFeatures:          supportedFeatures,
		TimeoutConfig:              conformanceconfig.DefaultTimeoutConfig(),
		SkipProvisionalTests:       *flags.SkipProvisionalTests,
	}
}

// RunConformance will run the Gateway API Conformance tests
// using the default ConformanceOptions computed from command line flags.
func RunConformance(t *testing.T) {
	RunConformanceWithOptions(t, DefaultOptions(t))
}

// RunConformanceWithOptions will run the Gateway API Conformance tests
// with the supplied options
func RunConformanceWithOptions(t *testing.T, opts suite.ConformanceOptions) {
	if err := opts.Implementation.Validate(); err != nil && opts.ReportOutputPath != "" {
		require.NoError(t, err, "supplied Implementation details are not valid")
	}

	// if no FS is provided, use the default Manifests FS
	if opts.ManifestFS == nil {
		opts.ManifestFS = []fs.FS{&Manifests}
	}

	t.Log("Running conformance tests with:")
	logOptions(t, opts)

	cSuite, err := suite.NewConformanceTestSuite(opts)
	require.NoError(t, err, "error initializing conformance suite")

	cSuite.Setup(t, tests.ConformanceTests)
	err = cSuite.Run(t, tests.ConformanceTests)
	require.NoError(t, err)

	if opts.ReportOutputPath != "" {
		report, err := cSuite.Report()
		require.NoError(t, err, "error generating conformance profile report")
		require.NoError(t, writeReport(t.Logf, *report, opts.ReportOutputPath), "error writing report")
	}
}

func logOptions(t *testing.T, opts suite.ConformanceOptions) {
	t.Logf("  GatewayClass: %s", opts.GatewayClassName)
	t.Logf("  Cleanup Resources: %t", opts.CleanupBaseResources)
	t.Logf("  Debug: %t", opts.Debug)
	t.Logf("  Enable All Features: %t", opts.EnableAllSupportedFeatures)
	t.Logf("  Supported Features: %v", opts.SupportedFeatures.UnsortedList())
	t.Logf("  ExemptFeatures: %v", opts.ExemptFeatures.UnsortedList())
}

func writeReport(logf func(string, ...any), report confv1.ConformanceReport, output string) error {
	rawReport, err := yaml.Marshal(report)
	if err != nil {
		return err
	}

	if output != "" {
		if err = os.WriteFile(output, rawReport, 0o600); err != nil {
			return err
		}
	}
	logf("Conformance report:\n%s", string(rawReport))
	return nil
}

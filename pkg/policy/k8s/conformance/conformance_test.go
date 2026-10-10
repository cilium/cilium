// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package conformance

import (
	"flag"
	"os"
	"strings"
	"testing"

	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/client-go/kubernetes"
	_ "k8s.io/client-go/plugin/pkg/client/auth"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/config"
	"sigs.k8s.io/yaml"

	api "sigs.k8s.io/network-policy-api/apis/v1alpha2"
	confv1a1 "sigs.k8s.io/network-policy-api/conformance/apis/v1alpha1"
	"sigs.k8s.io/network-policy-api/conformance/tests"
	"sigs.k8s.io/network-policy-api/conformance/utils/flags"
	"sigs.k8s.io/network-policy-api/conformance/utils/suite"

	"github.com/cilium/cilium/pkg/testutils"
)

var (
	skipTestsFlag            = flag.String("skip-tests", "", "Comma-separated list of tests to skip")
	experimentalFeaturesFlag = flag.Bool("experimental-features", false, "Whether to enable experimental features for conformance tests")
)

func preflightCheck(t *testing.T, clientSet kubernetes.Interface, supportedFeatures sets.Set[suite.SupportedFeature]) {
	t.Helper()

	cm, err := clientSet.CoreV1().ConfigMaps("kube-system").Get(t.Context(), "cilium-config", metav1.GetOptions{})
	if err != nil {
		t.Fatalf("Preflight check failed: unable to get kube-system/cilium-config ConfigMap: %v", err)
	}

	var missing []string
	if cm.Data["enable-k8s-cluster-network-policy"] != "true" {
		missing = append(missing, "enable-k8s-cluster-network-policy=true (Helm: k8sClusterNetworkPolicy.enabled=true)")
	}
	if cm.Data["enable-sctp"] != "true" {
		missing = append(missing, "enable-sctp=true (Helm: sctp.enabled=true)")
	}
	if !strings.Contains(cm.Data["policy-cidr-match-mode"], "pods") {
		missing = append(missing, "policy-cidr-match-mode=pods (Helm: policyCIDRMatchMode=pods)")
	}
	// Cilium's default 30s identity allocation jitter exceeds the upstream
	// conformance suite's readiness timeout when creating new test namespaces.
	if cm.Data["identity-max-jitter"] == "" {
		missing = append(missing, "identity-max-jitter=2s (Helm: extraConfig.identity-max-jitter=2s)")
	}
	if (supportedFeatures.Has(suite.SupportClusterNetworkPolicyEgressNodePeers) || *flags.EnableAllSupportedFeatures) &&
		cm.Data["enable-node-selector-labels"] != "true" {
		missing = append(missing, "enable-node-selector-labels=true (Helm: nodeSelectorLabels=true)")
	}

	if len(missing) > 0 {
		t.Fatalf("Preflight check failed: Cilium is missing required configuration for kCNP conformance tests:\n  - %s\n\nWhen using Kind, install Cilium with:\n  make kind-install-cilium ADDITIONAL_KIND_VALUES_FILE=contrib/testing/kind-kcnp.yaml",
			strings.Join(missing, "\n  - "))
	}
}

// TestConformance runs the upstream conformance tests for kCNP (sigs.k8s.io/network-policy-api).
//
// The below command can be used to run the standard conformance tests locally against a cluster with Cilium installed:
//
//	KCNP_CONFORMANCE_TESTS=1 go test -v ./pkg/policy/k8s/conformance \
//		--cleanup-base-resources=false
//
// To include experimental features:
//
//	KCNP_CONFORMANCE_TESTS=1 go test -v ./pkg/policy/k8s/conformance \
//		--experimental-features --cleanup-base-resources=false
//
// To generate a conformance profile report:
//
//	KCNP_CONFORMANCE_TESTS=1 go test -v ./pkg/policy/k8s/conformance \
//		--conformance-profiles ClusterNetworkPolicy \
//		--organization cilium --project cilium \
//		--url github.com/cilium/cilium --version main \
//		--contact https://github.com/cilium/community/blob/main/roles/Maintainers.md \
//		--additional-info https://github.com/cilium/cilium/blob/main/.github/workflows/conformance-kcnp.yaml \
//		--report-output kcnp-conformance-report.yaml
func TestConformance(t *testing.T) {
	testutils.KCNPConformanceTest(t)

	cfg, err := config.GetConfig()
	if err != nil {
		t.Fatalf("Error loading Kubernetes config: %v", err)
	}
	c, err := client.New(cfg, client.Options{})
	if err != nil {
		t.Fatalf("Error initializing Kubernetes client: %v", err)
	}

	clientSet, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		t.Fatalf("Error creating Kubernetes ClientSet: %v", err)
	}

	if err := api.Install(c.Scheme()); err != nil {
		t.Fatalf("Error installing api scheme: %v", err)
	}
	if err := apiextensionsv1.AddToScheme(c.Scheme()); err != nil {
		t.Fatalf("Error installing apiextensions scheme: %v", err)
	}

	supportedFeatures := suite.ParseSupportedFeatures(*flags.SupportedFeatures)
	if *experimentalFeaturesFlag {
		if supportedFeatures == nil {
			supportedFeatures = sets.New[suite.SupportedFeature]()
		}
		for feature := range suite.ExperimentalFeatures {
			supportedFeatures.Insert(feature)
		}
	}
	exemptFeatures := suite.ParseSupportedFeatures(*flags.ExemptFeatures)
	conformanceProfiles := suite.ParseConformanceProfiles(*flags.ConformanceProfiles)

	preflightCheck(t, clientSet, supportedFeatures.Difference(exemptFeatures))

	var skipTests []string
	if *skipTestsFlag != "" {
		skipTests = strings.Split(*skipTestsFlag, ",")
	}

	suiteOptions := suite.Options{
		Client:                     c,
		ClientSet:                  clientSet,
		KubeConfig:                 *cfg,
		Debug:                      *flags.ShowDebug,
		CleanupBaseResources:       *flags.CleanupBaseResources,
		SupportedFeatures:          supportedFeatures,
		ExemptFeatures:             exemptFeatures,
		EnableAllSupportedFeatures: *flags.EnableAllSupportedFeatures,
		SkipTests:                  skipTests,
	}

	if conformanceProfiles.Len() > 0 {
		implementation, err := suite.ParseImplementation(
			*flags.ImplementationOrganization,
			*flags.ImplementationProject,
			*flags.ImplementationURL,
			*flags.ImplementationVersion,
			*flags.ImplementationContact,
			*flags.ImplementationAdditionalInformation,
		)
		if err != nil {
			t.Fatalf("Error parsing implementation details: %v", err)
		}

		cSuite, err := suite.NewConformanceProfileTestSuite(suite.ConformanceProfileOptions{
			Options:             suiteOptions,
			Implementation:      *implementation,
			ConformanceProfiles: conformanceProfiles,
		})
		if err != nil {
			t.Fatalf("Error creating conformance profile test suite: %v", err)
		}

		cSuite.Setup(t)
		cSuite.Run(t, tests.ConformanceTests)
		report, err := cSuite.Report()
		if err != nil {
			t.Fatalf("Error generating conformance profile report: %v", err)
		}
		if err := writeReport(t.Logf, *report, *flags.ReportOutput); err != nil {
			t.Fatalf("Error writing conformance report: %v", err)
		}
	} else {
		cSuite := suite.New(suiteOptions)
		cSuite.Setup(t)
		cSuite.Run(t, tests.ConformanceTests)
	}
}

func writeReport(logf func(string, ...any), report confv1a1.ConformanceReport, output string) error {
	rawReport, err := yaml.Marshal(report)
	if err != nil {
		return err
	}

	if output != "" {
		if err = os.WriteFile(output, rawReport, 0600); err != nil {
			return err
		}
	}
	logf("Conformance report:\n%s", string(rawReport))

	return nil
}

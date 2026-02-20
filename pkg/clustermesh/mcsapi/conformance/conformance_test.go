// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package conformance

import (
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	_ "sigs.k8s.io/mcs-api/conformance"

	"github.com/cilium/cilium/pkg/testutils"
)

// TestConformance runs the conformance tests for MCS-API
// Adapted from similar conformance tests in Cilium from Gateway API
//
// The below command can be used to run the conformance tests locally, you can also run directly from
// IDEs (e.g. Goland, VSCode) with the same settings.
//
//	MCS_API_CONFORMANCE_TESTS=1 go test -v ./pkg/clustermesh/mcsapi/conformance \
//			-contexts kind-clustermesh1,kind-clustermesh2 --debug
//
// You can also pass -ginkgo.focus to run a specific test
//
//	MCS_API_CONFORMANCE_TESTS=1 go test -v ./pkg/clustermesh/mcsapi/conformance \
//			-contexts kind-clustermesh1,kind-clustermesh2 --debug \
//			-ginkgo.focus "Only labels and annotations specified as exported"
func TestConformance(t *testing.T) {
	testutils.MCSAPIConformanceTest(t)

	suiteConfig, reporterConfig := GinkgoConfiguration()
	// Skip this test as Cilium only creates MCS EndpointSlices for headless services
	suiteConfig.SkipStrings = []string{
		"Exporting a service should create an MCS EndpointSlice",
	}
	RegisterFailHandler(Fail)
	RunSpecs(t, "MCS-API Conformance Suite", suiteConfig, reporterConfig)
}

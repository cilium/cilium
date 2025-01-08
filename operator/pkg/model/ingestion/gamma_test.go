// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ingestion

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/operator/pkg/model"
)

const (
	basedGammaTestdataDir = "testdata/gamma"
)

func TestGammaConformance(t *testing.T) {
	tests := map[string]struct {
	}{
		"Mesh Split":    {},
		"Mesh Ports":    {},
		"Mesh Frontend": {},
	}

	for name := range tests {
		t.Run(name, func(t *testing.T) {
			input := readGammaInput(t, name)
			listeners := GammaHTTPRoutes(input)

			expected := []model.HTTPListener{}
			readOutput(t, fmt.Sprintf("%s/%s/%s", basedGammaTestdataDir, rewriteTestName(name), "output-listeners.yaml"), &expected)

			require.Equal(t, expected, listeners, "Listeners did not match")
		})
	}
}

func readGammaInput(t *testing.T, testName string) GammaInput {
	input := GammaInput{}

	readInput(t, fmt.Sprintf("%s/%s/%s", basedGammaTestdataDir, rewriteTestName(testName), "input-httproute.yaml"), &input.HTTPRoutes)
	readInput(t, fmt.Sprintf("%s/%s/%s", basedGammaTestdataDir, rewriteTestName(testName), "input-service.yaml"), &input.Services)
	readInput(t, fmt.Sprintf("%s/%s/%s", basedGammaTestdataDir, rewriteTestName(testName), "input-referencegrant.yaml"), &input.ReferenceGrants)

	return input
}

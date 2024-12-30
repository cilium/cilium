// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ingestion

import (
	"errors"
	"os"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	k8syaml "sigs.k8s.io/yaml"
)

func readInput(t *testing.T, file string, obj any) {
	inputYaml, err := os.ReadFile(file)
	if errors.Is(err, os.ErrNotExist) {
		return
	}
	require.NoError(t, err)
	require.NoError(t, k8syaml.Unmarshal(inputYaml, obj))
}

func readOutput(t *testing.T, file string, obj any) string {
	// unmarshal and marshal to prevent formatting diffs
	outputYaml, err := os.ReadFile(file)
	require.NoError(t, err)

	if strings.TrimSpace(string(outputYaml)) == "" {
		return strings.TrimSpace(string(outputYaml))
	}

	require.NoError(t, k8syaml.Unmarshal(outputYaml, obj))

	yamlText := toYaml(t, obj)

	return strings.TrimSpace(yamlText)
}

func toYaml(t *testing.T, obj any) string {
	yamlText, err := k8syaml.Marshal(obj)
	require.NoError(t, err)

	return strings.TrimSpace(string(yamlText))
}

func writeOutput(t *testing.T, file string, obj any) {
	yamlText := toYaml(t, obj)

	require.NoError(t, os.WriteFile(file, []byte(yamlText), 0644))
}

func toTestDataDir(testName string) string {
	return strings.Replace(strings.Replace(testName, " ", "_", -1), "-", "_", -1)
}

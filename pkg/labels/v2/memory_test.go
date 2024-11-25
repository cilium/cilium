// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package v2

import (
	"fmt"
	"os"
	"runtime"
	"testing"

	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

type nameAndLabels struct {
	Name   string   `yaml:"name"`
	Labels []string `yaml:"labels"`
}

func TestIdentityLabelsMemoryUse(t *testing.T) {
	// This test was used to calculate optimal values for:
	// - cacheSize
	// - smallLabelsSize
	//
	// This test requires the dataset in /tmp/identitylabels.yaml and
	// thus is skipped by default.
	t.Skip()

	b, err := os.ReadFile("/tmp/identitylabels.yaml")
	require.NoError(t, err, "ReadFile")

	var m []nameAndLabels
	require.NoError(t, yaml.Unmarshal(b, &m))

	allLabels := []Labels{}

	var after runtime.MemStats

	for _, nl := range m {
		lbls := make([]Label, len(nl.Labels))
		for i := range nl.Labels {
			lbls[i] = ParseLabel(nl.Labels[i])
		}
		allLabels = append(allLabels, NewLabels(lbls...))
	}

	m = nil
	runtime.GC()
	runtime.GC()
	runtime.GC()
	runtime.ReadMemStats(&after)

	var _ = allLabels[0].String()

	fmt.Printf("%d label sets, heap objects: %d, heap in-use: %.2fkB\n",
		len(allLabels),
		after.HeapObjects,
		float64(after.HeapInuse)/1024,
	)
	fmt.Printf("labelCache: %d hit, %d miss\n", labelCache.hit.Load(), labelCache.miss.Load())
	fmt.Printf("labelsCache: %d hit, %d miss\n", labelsCache.hit.Load(), labelsCache.miss.Load())
}

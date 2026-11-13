// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package command

import (
	"testing"

	"github.com/stretchr/testify/require"

	operatormodels "github.com/cilium/cilium/api/v1/operator/models"
)

func TestDumpJSON(t *testing.T) {
	type sampleData struct {
		ID   int
		Name string
	}

	tt := sampleData{
		ID:   1,
		Name: "test",
	}

	err := dumpJSON(tt, "")
	require.NoError(t, err)

	err = dumpJSON(tt, "{.Id}")
	require.NoError(t, err)

	err = dumpJSON(tt, "{{.Id}}")
	if err == nil {
		t.Fatalf("Dumpjson jsonpath no error with invalid path '%s'", err)
	}
}

func TestDumpJSONToStringMetrics(t *testing.T) {
	metrics := []*operatormodels.Metric{
		{Name: "zero", Value: 0},
		{Name: "one", Value: 1},
		{Name: "fractional", Value: 1.5},
	}

	for _, tt := range []struct {
		name     string
		jsonPath string
		want     string
	}{
		{
			name:     "positive values",
			jsonPath: `{[?(@.value>0.0)].name}`,
			want:     "one fractional",
		},
		{
			name:     "integer-valued float",
			jsonPath: `{[?(@.value==1.0)].name}`,
			want:     "one",
		},
		{
			name:     "zero-valued float",
			jsonPath: `{[?(@.value==0.0)].name}`,
			want:     "zero",
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			got, err := DumpJSONToString(metrics, tt.jsonPath)
			require.NoError(t, err)
			require.Equal(t, tt.want, got)
		})
	}
}

func TestDumpYAML(t *testing.T) {
	type sampleData struct {
		ID   int
		Name string
	}

	tt := sampleData{
		ID:   1,
		Name: "test",
	}

	err := dumpYAML(tt)
	require.NoError(t, err)
}

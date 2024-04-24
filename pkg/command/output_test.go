// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package command

import (
	"testing"

	"github.com/stretchr/testify/require"
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

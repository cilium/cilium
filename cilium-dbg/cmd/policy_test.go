// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadInvalidPolicyJSON(t *testing.T) {
	invalidJSON := []byte(`
		[{
			"endpointSelector": {
				"matchLabels":{"id.httpd1":""}
			},`)

	invalidPolicy := filepath.Join(t.TempDir(), "invalid.json")
	err := os.WriteFile(invalidPolicy, invalidJSON, 0666)
	if err != nil {
		t.Fatalf("failed to write policy JSON file: %v", err)
	}

	_, err = loadPolicyFile(invalidPolicy)
	if err == nil {
		t.Error("loading invalid policy JSON unexpectedly succeeded")
	}
	if !strings.Contains(err.Error(), "malformed policy") {
		t.Errorf("expected malformed policy error, got %v", err)
	}
}

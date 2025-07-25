// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package install

import (
	"bytes"
	"os"
	"testing"

	"github.com/blang/semver/v4"
	"github.com/stretchr/testify/assert"
	"go.yaml.in/yaml/v3"

	"github.com/cilium/cilium/cilium-cli/k8s"
)

func TestK8sInstaller_getHelmValuesKind(t *testing.T) {
	installer := K8sInstaller{
		params:       Parameters{},
		flavor:       k8s.Flavor{Kind: k8s.KindKind},
		chartVersion: semver.MustParse("1.14.0"),
	}
	values, err := installer.getHelmValues()
	assert.NoError(t, err)
	var actual bytes.Buffer
	encoder := yaml.NewEncoder(&actual)
	encoder.SetIndent(2)
	err = encoder.Encode(values)
	assert.NoError(t, err)
	expected, err := os.ReadFile("testdata/kind.yaml")
	assert.NoError(t, err)
	assert.Equal(t, string(expected), actual.String())
}

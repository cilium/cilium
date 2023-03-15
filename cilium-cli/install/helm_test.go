// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package install

import (
	"os"
	"testing"

	"github.com/cilium/cilium-cli/k8s"

	"github.com/blang/semver/v4"
	"github.com/stretchr/testify/assert"
	"gopkg.in/yaml.v2"
)

func TestK8sInstaller_getHelmValuesKind(t *testing.T) {
	installer := K8sInstaller{
		params:       Parameters{},
		flavor:       k8s.Flavor{Kind: k8s.KindKind},
		chartVersion: semver.MustParse("1.13.0"),
	}
	values, err := installer.getHelmValues()
	assert.NoError(t, err)
	actual, err := yaml.Marshal(values)
	assert.NoError(t, err)
	expected, err := os.ReadFile("testdata/kind.yaml")
	assert.NoError(t, err)
	assert.Equal(t, string(expected), string(actual))
}

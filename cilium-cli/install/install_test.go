// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package install

import (
	"testing"

	"github.com/blang/semver/v4"
	"github.com/stretchr/testify/assert"
	"helm.sh/helm/v4/pkg/cli"
	"helm.sh/helm/v4/pkg/cli/values"
	"helm.sh/helm/v4/pkg/getter"
)

func Test_spireAgentScheduleAffinity(t *testing.T) {
	for _, tt := range []struct {
		version string
		prefix  string
	}{
		{"1.19.0", "authentication.mutual.spire"},
		{"1.20.0", "authentication.mutual.spire"},
		{"1.20.1", "authentication.mutual.spire"},
		{"1.21.0-dev", "encryption.ztunnel.spire"},
		{"1.21.0-rc.1", "encryption.ztunnel.spire"},
		{"1.21.0", "encryption.ztunnel.spire"},
		{"1.22.0", "encryption.ztunnel.spire"},
	} {
		t.Run(tt.version, func(t *testing.T) {
			installer := K8sInstaller{chartVersion: semver.MustParse(tt.version)}
			prefix := tt.prefix + ".install.agent.affinity.nodeAffinity.requiredDuringSchedulingIgnoredDuringExecution.nodeSelectorTerms[0].matchExpressions[0]."
			assert.Equal(t, []string{
				prefix + "key=cilium.io/no-schedule",
				prefix + "operator=NotIn",
				prefix + "values[0]=true",
			}, installer.spireAgentScheduleAffinity())
		})
	}
}

func Test_getChainingMode(t *testing.T) {
	assert.Empty(t, getChainingMode(nil))

	opts := values.Options{}
	vals, err := opts.MergeValues(getter.All(cli.New()))
	assert.NoError(t, err)
	assert.Empty(t, getChainingMode(vals))

	opts = values.Options{JSONValues: []string{"cni={}"}}
	vals, err = opts.MergeValues(getter.All(cli.New()))
	assert.NoError(t, err)
	assert.Empty(t, getChainingMode(vals))

	opts = values.Options{Values: []string{"cni.chainingMode=aws-cni"}}
	vals, err = opts.MergeValues(getter.All(cli.New()))
	assert.NoError(t, err)
	assert.Equal(t, "aws-cni", getChainingMode(vals))
}

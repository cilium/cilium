// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package install

import (
	"testing"

	"helm.sh/helm/v4/pkg/cli"
	"helm.sh/helm/v4/pkg/cli/values"
	"helm.sh/helm/v4/pkg/getter"

	"github.com/stretchr/testify/assert"
)

func Test_getClusterName(t *testing.T) {
	assert.Empty(t, getClusterName(nil))

	opts := values.Options{}
	vals, err := opts.MergeValues(getter.All(cli.New()))
	assert.NoError(t, err)
	assert.Empty(t, getClusterName(vals))

	opts = values.Options{JSONValues: []string{"cluster={}"}}
	vals, err = opts.MergeValues(getter.All(cli.New()))
	assert.NoError(t, err)
	assert.Empty(t, getClusterName(vals))

	opts = values.Options{Values: []string{"cluster.name=my-cluster"}}
	vals, err = opts.MergeValues(getter.All(cli.New()))
	assert.NoError(t, err)
	assert.Equal(t, "my-cluster", getClusterName(vals))
}

func Test_trimEKSClusterName(t *testing.T) {
	vals := ""
	assert.Empty(t, trimEKSClusterName(vals))

	vals = "invalid-arn-format"
	assert.Equal(t, "invalid-arn-format", trimEKSClusterName(vals))

	vals = "arn:aws:eks:region:account-id:cluster/"
	assert.Empty(t, trimEKSClusterName(vals))

	vals = "arn:aws:eks:eu-west-1:111111111111:cluster/my-cluster"
	assert.Equal(t, "my-cluster", trimEKSClusterName(vals))

	vals = "arn:aws:eks:us-west-1:123456789012:cluster/eks-my-cluster"
	assert.Equal(t, "eks-my-cluster", trimEKSClusterName(vals))

	vals = "my-cluster.eu-west-1.eksctl.io"
	assert.Equal(t, "my-cluster", trimEKSClusterName(vals))

	vals = "eks-cilium-test-1.ap-northeast-1.eksctl.io"
	assert.Equal(t, "eks-cilium-test-1", trimEKSClusterName(vals))
}

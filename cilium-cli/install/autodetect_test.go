// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package install

import (
	"testing"

	"helm.sh/helm/v3/pkg/cli"
	"helm.sh/helm/v3/pkg/cli/values"
	"helm.sh/helm/v3/pkg/getter"

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

func Test_trimEKSClusterARN(t *testing.T) {
	vals := ""
	assert.Empty(t, trimEKSClusterARN(vals))

	vals = "arn:aws:eks:eu-west-1:111111111111:cluster/my-cluster"
	assert.Equal(t, "my-cluster", trimEKSClusterARN(vals))

	vals = "cluster/my-cluster"
	assert.Equal(t, "my-cluster", trimEKSClusterARN(vals))

	vals = "arn:aws:eks:region:account-id:cluster/"
	assert.Empty(t, trimEKSClusterARN(vals))

	vals = "invalid-arn-format"
	assert.Equal(t, "invalid-arn-format", trimEKSClusterARN(vals))
}

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
	assert.Equal(t, "", getClusterName(nil))

	opts := values.Options{}
	vals, err := opts.MergeValues(getter.All(cli.New()))
	assert.NoError(t, err)
	assert.Equal(t, "", getClusterName(vals))

	opts = values.Options{JSONValues: []string{"cluster={}"}}
	vals, err = opts.MergeValues(getter.All(cli.New()))
	assert.NoError(t, err)
	assert.Equal(t, "", getClusterName(vals))

	opts = values.Options{Values: []string{"cluster.name=my-cluster"}}
	vals, err = opts.MergeValues(getter.All(cli.New()))
	assert.NoError(t, err)
	assert.Equal(t, "my-cluster", getClusterName(vals))
}

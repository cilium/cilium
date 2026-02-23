// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package install

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"helm.sh/helm/v4/pkg/cli"
	"helm.sh/helm/v4/pkg/cli/values"
	"helm.sh/helm/v4/pkg/getter"
)

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

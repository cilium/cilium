// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package client

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/api/v1/models"
)

func TestHint(t *testing.T) {
	var err error
	require.NoError(t, Hint(err))

	err = errors.New("foo bar")
	require.EqualError(t, Hint(err), "foo bar")

	err = fmt.Errorf("ayy lmao")
	require.EqualError(t, Hint(err), "ayy lmao")

	err = context.DeadlineExceeded
	require.EqualError(t, Hint(err), "Cilium API client timeout exceeded")

	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Millisecond)
	defer cancel()

	<-ctx.Done()
	err = ctx.Err()

	require.EqualError(t, Hint(err), "Cilium API client timeout exceeded")
}

func TestClusterReadiness(t *testing.T) {
	require.Equal(t, "ready", clusterReadiness(&models.RemoteCluster{Ready: true}))
	require.Equal(t, "not-ready", clusterReadiness(&models.RemoteCluster{Ready: false}))
}

func TestNumReadyClusters(t *testing.T) {
	require.Equal(t, 0, numReadyClusters(&models.ClusterMeshStatus{}))
	require.Equal(t, 2, numReadyClusters(&models.ClusterMeshStatus{
		Clusters: []*models.RemoteCluster{{Ready: true}, {Ready: true}, {Ready: false}},
	}))
}

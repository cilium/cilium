// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package client

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	. "github.com/cilium/checkmate"

	"github.com/cilium/cilium/api/v1/models"
)

// Hook up gocheck into the "go test" runner.
type ClientTestSuite struct{}

var _ = Suite(&ClientTestSuite{})

func Test(t *testing.T) {
	TestingT(t)
}

func (cs *ClientTestSuite) TestHint(c *C) {
	var err error
	c.Assert(Hint(err), IsNil)

	err = errors.New("foo bar")
	c.Assert(Hint(err), ErrorMatches, "foo bar")

	err = fmt.Errorf("ayy lmao")
	c.Assert(Hint(err), ErrorMatches, "ayy lmao")

	err = context.DeadlineExceeded
	c.Assert(Hint(err), ErrorMatches, "Cilium API client timeout exceeded")

	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Millisecond)
	defer cancel()

	<-ctx.Done()
	err = ctx.Err()

	c.Assert(Hint(err), ErrorMatches, "Cilium API client timeout exceeded")
}

func (cs *ClientTestSuite) TestClusterReadiness(c *C) {
	c.Assert(clusterReadiness(&models.RemoteCluster{Ready: true}), Equals, "ready")
	c.Assert(clusterReadiness(&models.RemoteCluster{Ready: false}), Equals, "not-ready")
}

func (cs *ClientTestSuite) TestNumReadyClusters(c *C) {
	c.Assert(numReadyClusters(&models.ClusterMeshStatus{}), Equals, 0)
	c.Assert(numReadyClusters(&models.ClusterMeshStatus{
		Clusters: []*models.RemoteCluster{{Ready: true}, {Ready: true}, {Ready: false}},
	}), Equals, 2)
}

// Copyright 2018 Authors of Cilium
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package service

import (
	"testing"

	"github.com/cilium/cilium/common"
	"github.com/cilium/cilium/pkg/kvstore"

	. "gopkg.in/check.v1"
)

// Hook up gocheck into the "go test" runner.
func Test(t *testing.T) {
	TestingT(t)
}

type ServiceTestSuite struct{}

type ServiceEtcdSuite struct {
	ServiceTestSuite
}

var _ = Suite(&ServiceEtcdSuite{})

func (e *ServiceEtcdSuite) SetUpTest(c *C) {
	kvstore.SetupDummy("etcd")
	kvstore.DeletePrefix(common.OperationalPath)
	kvstore.DeletePrefix(kvstore.BaseKeyPrefix)
}

func (e *ServiceEtcdSuite) TearDownTest(c *C) {
	// FIXME: Cleanup test prefix
	kvstore.Close()
}

type ServiceConsulSuite struct {
	ServiceTestSuite
}

var _ = Suite(&ServiceConsulSuite{})

func (e *ServiceConsulSuite) SetUpTest(c *C) {
	kvstore.SetupDummy("consul")
	kvstore.DeletePrefix(common.OperationalPath)
	kvstore.DeletePrefix(kvstore.BaseKeyPrefix)
}

func (e *ServiceConsulSuite) TearDownTest(c *C) {
	// FIXME: Cleanup test prefix
	kvstore.Close()
}

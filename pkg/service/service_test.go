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

// +build !privileged_tests

package service

import (
	"testing"

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
	EnableGlobalServiceID(true)
	kvstore.SetupDummy("etcd")
	kvstore.DeletePrefix(serviceKvstorePrefix)
}

func (e *ServiceEtcdSuite) TearDownTest(c *C) {
	kvstore.DeletePrefix(serviceKvstorePrefix)
	kvstore.Close()
}

type ServiceConsulSuite struct {
	ServiceTestSuite
}

var _ = Suite(&ServiceConsulSuite{})

func (e *ServiceConsulSuite) SetUpTest(c *C) {
	EnableGlobalServiceID(true)
	kvstore.SetupDummy("consul")
	kvstore.DeletePrefix(serviceKvstorePrefix)
}

func (e *ServiceConsulSuite) TearDownTest(c *C) {
	kvstore.DeletePrefix(serviceKvstorePrefix)
	kvstore.Close()
}

type ServiceLocalSuite struct {
	ServiceTestSuite
}

var _ = Suite(&ServiceLocalSuite{})

func (e *ServiceLocalSuite) SetUpTest(c *C) {
	EnableGlobalServiceID(false)
	serviceIDAlloc.resetLocalID()
}

func (e *ServiceLocalSuite) TearDownTest(c *C) {
	serviceIDAlloc.resetLocalID()
}

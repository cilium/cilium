// Copyright 2016-2018 Authors of Cilium
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

package kvstore

import (
	"fmt"
	"io"
	"time"

	etcdAPI "github.com/coreos/etcd/clientv3"
	"golang.org/x/net/context"
	. "gopkg.in/check.v1"
)

type EtcdSuite struct {
	BaseTests
}

var _ = Suite(&EtcdSuite{})

func (e *EtcdSuite) SetUpTest(c *C) {
	SetupDummy("etcd")
}

type MaintenanceMocker struct {
	OnAlarmList   func(ctx context.Context) (*etcdAPI.AlarmResponse, error)
	OnAlarmDisarm func(ctx context.Context, m *etcdAPI.AlarmMember) (*etcdAPI.AlarmResponse, error)
	OnDefragment  func(ctx context.Context, endpoint string) (*etcdAPI.DefragmentResponse, error)
	OnStatus      func(ctx context.Context, endpoint string) (*etcdAPI.StatusResponse, error)
	OnSnapshot    func(ctx context.Context) (io.ReadCloser, error)
}

func (m MaintenanceMocker) AlarmList(ctx context.Context) (*etcdAPI.AlarmResponse, error) {
	if m.OnAlarmList != nil {
		return m.OnAlarmList(ctx)
	}
	return nil, fmt.Errorf("Method AlarmList should not have been called")
}

func (m MaintenanceMocker) AlarmDisarm(ctx context.Context, am *etcdAPI.AlarmMember) (*etcdAPI.AlarmResponse, error) {
	if m.OnAlarmDisarm != nil {
		return m.OnAlarmDisarm(ctx, am)
	}
	return nil, fmt.Errorf("Method AlarmDisarm should not have been called")
}

func (m MaintenanceMocker) Defragment(ctx context.Context, endpoint string) (*etcdAPI.DefragmentResponse, error) {
	if m.OnDefragment != nil {
		return m.OnDefragment(ctx, endpoint)
	}
	return nil, fmt.Errorf("Method Defragment should not have been called")
}

func (m MaintenanceMocker) Status(ctx context.Context, endpoint string) (*etcdAPI.StatusResponse, error) {
	if m.OnStatus != nil {
		return m.OnStatus(ctx, endpoint)
	}
	return nil, fmt.Errorf("Method Status should not have been called")
}

func (m MaintenanceMocker) Snapshot(ctx context.Context) (io.ReadCloser, error) {
	if m.OnSnapshot != nil {
		return m.OnSnapshot(ctx)
	}
	return nil, fmt.Errorf("Method Snapshot should not have been called")
}

func (s *EtcdSuite) TestETCDVersionCheck(c *C) {
	badVersionStr := "3.0.0"
	goodVersion := "3.1.0"
	mm := MaintenanceMocker{
		OnStatus: func(ctx context.Context, endpoint string) (*etcdAPI.StatusResponse, error) {
			switch endpoint {
			case "http://127.0.0.1:4004":
				return &etcdAPI.StatusResponse{
					Version: badVersionStr,
				}, nil
			default:
				return &etcdAPI.StatusResponse{
					Version: goodVersion,
				}, nil
			}
		},
	}
	// Check a good version
	v, err := getEPVersion(mm, "http://127.0.0.1:4003", time.Second)
	c.Assert(err, IsNil)
	c.Assert(v.String(), Equals, goodVersion)

	// Check a bad version
	v, err = getEPVersion(mm, "http://127.0.0.1:4004", time.Second)
	c.Assert(err, IsNil)
	c.Assert(v.String(), Equals, badVersionStr)

	// CheckMinVersion all good
	cfg := etcdAPI.Config{}
	cfg.Endpoints = []string{"http://127.0.0.1:4003", "http://127.0.0.1:4005"}
	cli, err := etcdAPI.New(cfg)
	c.Assert(err, IsNil)
	cli.Maintenance = mm
	client := etcdClient{
		client: cli,
	}
	e := client.checkMinVersion(1 * time.Second)
	c.Assert(e, IsNil)

	// One endpoint has a bad version and should fail
	cfg.Endpoints = []string{"http://127.0.0.1:4003", "http://127.0.0.1:4004", "http://127.0.0.1:4005"}
	cli, err = etcdAPI.New(cfg)
	c.Assert(err, IsNil)
	cli.Maintenance = mm
	client = etcdClient{
		client: cli,
	}

	e = client.checkMinVersion(1 * time.Second)
	c.Assert(e, NotNil)
}

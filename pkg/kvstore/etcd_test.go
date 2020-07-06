// Copyright 2016-2020 Authors of Cilium
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

package kvstore

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"path"
	"testing"
	"time"

	"github.com/cilium/cilium/pkg/checker"

	etcdAPI "go.etcd.io/etcd/clientv3"
	. "gopkg.in/check.v1"
)

type EtcdSuite struct {
	BaseTests
}

var _ = Suite(&EtcdSuite{})

func (e *EtcdSuite) SetUpTest(c *C) {
	SetupDummy("etcd")
}

func (e *EtcdSuite) TearDownTest(c *C) {
	Client().Close()
}

type MaintenanceMocker struct {
	OnAlarmList   func(ctx context.Context) (*etcdAPI.AlarmResponse, error)
	OnAlarmDisarm func(ctx context.Context, m *etcdAPI.AlarmMember) (*etcdAPI.AlarmResponse, error)
	OnDefragment  func(ctx context.Context, endpoint string) (*etcdAPI.DefragmentResponse, error)
	OnStatus      func(ctx context.Context, endpoint string) (*etcdAPI.StatusResponse, error)
	OnSnapshot    func(ctx context.Context) (io.ReadCloser, error)
	OnHashKV      func(ctx context.Context, endpoint string, rev int64) (*etcdAPI.HashKVResponse, error)
	OnMoveLeader  func(ctx context.Context, transfereeID uint64) (*etcdAPI.MoveLeaderResponse, error)
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

func (m MaintenanceMocker) HashKV(ctx context.Context, endpoint string, rev int64) (*etcdAPI.HashKVResponse, error) {
	if m.OnSnapshot != nil {
		return m.OnHashKV(ctx, endpoint, rev)
	}
	return nil, fmt.Errorf("Method HashKV should not have been called")
}

func (m MaintenanceMocker) MoveLeader(ctx context.Context, transfereeID uint64) (*etcdAPI.MoveLeaderResponse, error) {
	if m.OnSnapshot != nil {
		return m.OnMoveLeader(ctx, transfereeID)
	}
	return nil, fmt.Errorf("Method MoveLeader should not have been called")
}

func (s *EtcdSuite) TestHint(c *C) {
	var err error

	c.Assert(Hint(err), IsNil)

	err = errors.New("foo bar")
	c.Assert(Hint(err), ErrorMatches, "foo bar")

	err = fmt.Errorf("ayy lmao")
	c.Assert(Hint(err), ErrorMatches, "ayy lmao")

	err = context.DeadlineExceeded
	c.Assert(Hint(err), ErrorMatches, "etcd client timeout exceeded")

	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Millisecond)
	defer cancel()

	<-ctx.Done()
	err = ctx.Err()

	c.Assert(Hint(err), ErrorMatches, "etcd client timeout exceeded")
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
	v, err := getEPVersion(context.TODO(), mm, "http://127.0.0.1:4003", time.Second)
	c.Assert(err, IsNil)
	c.Assert(v.String(), Equals, goodVersion)

	// Check a bad version
	v, err = getEPVersion(context.TODO(), mm, "http://127.0.0.1:4004", time.Second)
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

	// short timeout for tests
	versionCheckTimeout = time.Second

	c.Assert(client.checkMinVersion(context.TODO()), IsNil)

	// One endpoint has a bad version and should fail
	cfg.Endpoints = []string{"http://127.0.0.1:4003", "http://127.0.0.1:4004", "http://127.0.0.1:4005"}
	cli, err = etcdAPI.New(cfg)
	c.Assert(err, IsNil)
	cli.Maintenance = mm
	client = etcdClient{
		client: cli,
	}

	c.Assert(client.checkMinVersion(context.TODO()), Not(IsNil))
}

type EtcdHelpersSuite struct{}

var _ = Suite(&EtcdHelpersSuite{})

func (s *EtcdHelpersSuite) TestIsEtcdOperator(c *C) {
	temp := c.MkDir()
	etcdConfigByte := []byte(`---
endpoints:
- https://cilium-etcd-client.kube-system.svc:2379
`)
	etcdTempFile := path.Join(temp, "etcd-config.yaml")
	err := ioutil.WriteFile(etcdTempFile, etcdConfigByte, 0600)
	c.Assert(err, IsNil)
	type args struct {
		backend      string
		opts         map[string]string
		k8sNamespace string
	}
	tests := []struct {
		args        args
		wantSvcName string
		wantBool    bool
	}{
		{
			args: args{
				backend: consulName,
			},
			// it is not etcd
			wantBool: false,
		},
		{
			args: args{
				backend: EtcdBackendName,
			},
			// misses configuration
			wantBool: false,
		},
		{
			args: args{
				backend: EtcdBackendName,
				opts: map[string]string{
					"etcd.address": "http://cilium-etcd-client.kube-system.svc",
				},
				k8sNamespace: "kube-system",
			},
			wantSvcName: "http://cilium-etcd-client.kube-system.svc",
			// everything valid
			wantBool: true,
		},
		{
			args: args{
				backend: EtcdBackendName,
				opts: map[string]string{
					"etcd.address": "cilium-etcd-client.kube-system.svc",
				},
				k8sNamespace: "kube-system",
			},
			// domain name misses protocol
			wantBool: false,
		},
		{
			args: args{
				opts: map[string]string{
					"etcd.address": "cilium-etcd-client.kube-system.svc",
				},
				k8sNamespace: "kube-system",
			},
			// backend not specified
			wantBool: false,
		},
		{
			args: args{
				backend: EtcdBackendName,
				opts: map[string]string{
					"etcd.config": etcdTempFile,
				},
				k8sNamespace: "kube-system",
			},
			wantSvcName: "https://cilium-etcd-client.kube-system.svc:2379",
			// config file with everything setup
			wantBool: true,
		},
		{
			args: args{
				backend: EtcdBackendName,
				opts: map[string]string{
					"etcd.address":  "foo-bar.kube-system.svc",
					"etcd.operator": "true",
				},
				k8sNamespace: "kube-system",
			},
			wantSvcName: "foo-bar.kube-system.svc",
			wantBool:    true,
		},
		{
			args: args{
				backend: EtcdBackendName,
				opts: map[string]string{
					"etcd.address":  "foo-bar.kube-system.svc",
					"etcd.operator": "false",
				},
				k8sNamespace: "kube-system",
			},
			wantBool: false,
		},
		{
			args: args{
				backend: EtcdBackendName,
				opts: map[string]string{
					"etcd.address": "foo-bar.kube-system.svc",
				},
				k8sNamespace: "kube-system",
			},
			wantBool: false,
		},
		{
			args: args{
				backend: EtcdBackendName,
				opts: map[string]string{
					"etcd.address":  "foo-bar.kube-system.svc",
					"etcd.operator": "foo-bar",
				},
				k8sNamespace: "kube-system",
			},
			wantBool: false,
		},
		{
			args: args{
				backend: EtcdBackendName,
				opts: map[string]string{
					"etcd.address":  "https://cilium-etcd-client.kube-system.svc",
					"etcd.operator": "foo-bar",
				},
				k8sNamespace: "kube-system",
			},
			wantSvcName: "https://cilium-etcd-client.kube-system.svc",
			wantBool:    true,
		},
		{
			args: args{
				backend: EtcdBackendName,
				opts: map[string]string{
					"etcd.config":   etcdTempFile,
					"etcd.operator": "foo-bar",
				},
				k8sNamespace: "kube-system",
			},
			wantSvcName: "https://cilium-etcd-client.kube-system.svc:2379",
			// config file with everything setup
			wantBool: true,
		},
	}
	for i, tt := range tests {
		gotSvcName, gotBool := IsEtcdOperator(tt.args.backend, tt.args.opts, tt.args.k8sNamespace)
		c.Assert(gotBool, Equals, tt.wantBool, Commentf("Test %d", i))
		c.Assert(gotSvcName, Equals, tt.wantSvcName, Commentf("Test %d", i))
	}
}

type EtcdLockedSuite struct {
	etcdClient *etcdAPI.Client
}

var _ = Suite(&EtcdLockedSuite{})

func (e *EtcdLockedSuite) SetUpSuite(c *C) {
	SetupDummy("etcd")

	// setup client
	cfg := etcdAPI.Config{}
	cfg.Endpoints = []string{etcdDummyAddress}
	cfg.DialTimeout = 0
	cli, err := etcdAPI.New(cfg)
	c.Assert(err, IsNil)
	e.etcdClient = cli
}

func (e *EtcdLockedSuite) TearDownSuite(c *C) {
	err := e.etcdClient.Close()
	c.Assert(err, IsNil)
	Client().Close()
}

func (e *EtcdLockedSuite) TestGetIfLocked(c *C) {
	randomPath := c.MkDir()
	type args struct {
		key  string
		lock KVLocker
	}
	type wanted struct {
		err   error
		value []byte
	}
	tests := []struct {
		name        string
		setupArgs   func() args
		setupWanted func() wanted
		cleanup     func(args args) error
	}{
		{
			name: "getting locked path",
			setupArgs: func() args {
				key := randomPath + "foo"
				kvlocker, err := Client().LockPath(context.Background(), "locks/"+key+"/.lock")
				c.Assert(err, IsNil)
				_, err = e.etcdClient.Put(context.Background(), key, "bar")
				c.Assert(err, IsNil)

				return args{
					key:  key,
					lock: kvlocker,
				}
			},
			setupWanted: func() wanted {
				return wanted{
					err:   nil,
					value: []byte("bar"),
				}
			},
			cleanup: func(args args) error {
				_, err := e.etcdClient.Delete(context.Background(), args.key)
				if err != nil {
					return err
				}
				return args.lock.Unlock(context.TODO())
			},
		},
		{
			name: "getting locked path with no value",
			setupArgs: func() args {
				key := randomPath + "foo"
				kvlocker, err := Client().LockPath(context.Background(), "locks/"+key+"/.lock")
				c.Assert(err, IsNil)
				_, err = e.etcdClient.Delete(context.Background(), key)
				c.Assert(err, IsNil)

				return args{
					key:  key,
					lock: kvlocker,
				}
			},
			setupWanted: func() wanted {
				return wanted{
					err:   nil,
					value: nil,
				}
			},
			cleanup: func(args args) error {
				return args.lock.Unlock(context.TODO())
			},
		},
		{
			name: "getting locked path where lock was lost",
			setupArgs: func() args {
				key := randomPath + "foo"
				kvlocker, err := Client().LockPath(context.Background(), "locks/"+key+"/.lock")
				c.Assert(err, IsNil)
				err = kvlocker.Unlock(context.TODO())
				c.Assert(err, IsNil)

				_, err = e.etcdClient.Put(context.Background(), key, "bar")
				c.Assert(err, IsNil)

				return args{
					key:  key,
					lock: kvlocker,
				}
			},
			setupWanted: func() wanted {
				return wanted{
					err:   ErrLockLeaseExpired,
					value: nil,
				}
			},
			cleanup: func(args args) error {
				_, err := e.etcdClient.Delete(context.Background(), args.key)
				return err
			},
		},
	}
	for _, tt := range tests {
		c.Log(tt.name)
		args := tt.setupArgs()
		want := tt.setupWanted()
		value, err := Client().GetIfLocked(context.TODO(), args.key, args.lock)
		c.Assert(err, Equals, want.err)
		c.Assert(value, checker.DeepEquals, want.value)
		err = tt.cleanup(args)
		c.Assert(err, IsNil)
	}
}

func (e *EtcdLockedSuite) TestGetPrefixIfLocked(c *C) {
	randomPath := c.MkDir()
	type args struct {
		key  string
		lock KVLocker
	}
	type wanted struct {
		err   error
		key   string
		value []byte
	}
	tests := []struct {
		name        string
		setupArgs   func() args
		setupWanted func() wanted
		cleanup     func(args args) error
	}{
		{
			name: "getting locked prefix path",
			setupArgs: func() args {
				key := randomPath + "foo"
				kvlocker, err := Client().LockPath(context.Background(), "locks/"+key+"/.lock")
				c.Assert(err, IsNil)
				_, err = e.etcdClient.Put(context.Background(), key, "bar")
				c.Assert(err, IsNil)

				return args{
					key:  key,
					lock: kvlocker,
				}
			},
			setupWanted: func() wanted {
				return wanted{
					err:   nil,
					key:   randomPath + "foo",
					value: []byte("bar"),
				}
			},
			cleanup: func(args args) error {
				_, err := e.etcdClient.Delete(context.Background(), args.key)
				if err != nil {
					return err
				}
				return args.lock.Unlock(context.TODO())
			},
		},
		{
			name: "getting locked prefix path with no value",
			setupArgs: func() args {
				key := randomPath + "foo"
				kvlocker, err := Client().LockPath(context.Background(), "locks/"+key+"/.lock")
				c.Assert(err, IsNil)

				return args{
					key:  key,
					lock: kvlocker,
				}
			},
			setupWanted: func() wanted {
				return wanted{
					err:   nil,
					value: nil,
				}
			},
			cleanup: func(args args) error {
				return args.lock.Unlock(context.TODO())
			},
		},
		{
			name: "getting locked prefix path where lock was lost",
			setupArgs: func() args {
				key := randomPath + "foo"
				kvlocker, err := Client().LockPath(context.Background(), "locks/"+key+"/.lock")
				c.Assert(err, IsNil)
				err = kvlocker.Unlock(context.TODO())
				c.Assert(err, IsNil)
				_, err = e.etcdClient.Put(context.Background(), key, "bar")
				c.Assert(err, IsNil)

				return args{
					key:  key,
					lock: kvlocker,
				}
			},
			setupWanted: func() wanted {
				return wanted{
					err:   ErrLockLeaseExpired,
					value: nil,
				}
			},
			cleanup: func(args args) error {
				_, err := e.etcdClient.Delete(context.Background(), args.key)
				return err
			},
		},
	}
	for _, tt := range tests {
		c.Log(tt.name)
		args := tt.setupArgs()
		want := tt.setupWanted()
		k, value, err := Client().GetPrefixIfLocked(context.Background(), args.key, args.lock)
		c.Assert(err, Equals, want.err)
		c.Assert(k, Equals, want.key)
		c.Assert(value, checker.DeepEquals, want.value)
		err = tt.cleanup(args)
		c.Assert(err, IsNil)
	}
}

func (e *EtcdLockedSuite) TestDeleteIfLocked(c *C) {
	randomPath := c.MkDir()
	type args struct {
		key  string
		lock KVLocker
	}
	type wanted struct {
		err error
	}
	tests := []struct {
		name        string
		setupArgs   func() args
		setupWanted func() wanted
		cleanup     func(args args) error
	}{
		{
			name: "deleting locked path",
			setupArgs: func() args {
				key := randomPath + "foo"
				kvlocker, err := Client().LockPath(context.Background(), "locks/"+key+"/.lock")
				c.Assert(err, IsNil)
				_, err = e.etcdClient.Put(context.Background(), key, "bar")
				c.Assert(err, IsNil)

				return args{
					key:  key,
					lock: kvlocker,
				}
			},
			setupWanted: func() wanted {
				return wanted{
					err: nil,
				}
			},
			cleanup: func(args args) error {
				key := randomPath + "foo"
				// verify that key was actually deleted
				gr, err := e.etcdClient.Get(context.Background(), key)
				c.Assert(err, IsNil)
				c.Assert(gr.Count, Equals, int64(0))

				return args.lock.Unlock(context.TODO())
			},
		},
		{
			name: "deleting locked path with no value",
			setupArgs: func() args {
				key := randomPath + "foo"
				kvlocker, err := Client().LockPath(context.Background(), "locks/"+key+"/.lock")
				c.Assert(err, IsNil)

				_, err = e.etcdClient.Delete(context.Background(), key)
				c.Assert(err, IsNil)

				return args{
					key:  key,
					lock: kvlocker,
				}
			},
			setupWanted: func() wanted {
				return wanted{
					err: nil,
				}
			},
			cleanup: func(args args) error {
				key := randomPath + "foo"
				// verify that key was actually deleted (this should not matter
				// as the key was never in the kvstore but still)
				gr, err := e.etcdClient.Get(context.Background(), key)
				c.Assert(err, IsNil)
				c.Assert(gr.Count, Equals, int64(0))

				return args.lock.Unlock(context.TODO())
			},
		},
		{
			name: "deleting locked path where lock was lost",
			setupArgs: func() args {
				key := randomPath + "foo"
				kvlocker, err := Client().LockPath(context.Background(), "locks/"+key+"/.lock")
				c.Assert(err, IsNil)
				_, err = e.etcdClient.Put(context.Background(), key, "bar")
				c.Assert(err, IsNil)
				err = kvlocker.Unlock(context.TODO())
				c.Assert(err, IsNil)

				return args{
					key:  key,
					lock: kvlocker,
				}
			},
			setupWanted: func() wanted {
				return wanted{
					err: ErrLockLeaseExpired,
				}
			},
			cleanup: func(args args) error {
				key := randomPath + "foo"
				// If the lock was lost it means the value still exists
				value, err := e.etcdClient.Get(context.Background(), key)
				c.Assert(err, IsNil)
				c.Assert(value.Count, Equals, int64(1))
				c.Assert(value.Kvs[0].Value, checker.DeepEquals, []byte("bar"))
				return nil
			},
		},
	}
	for _, tt := range tests {
		c.Log(tt.name)
		args := tt.setupArgs()
		want := tt.setupWanted()
		err := Client().DeleteIfLocked(context.TODO(), args.key, args.lock)
		c.Assert(err, Equals, want.err)
		err = tt.cleanup(args)
		c.Assert(err, IsNil)
	}
}

func (e *EtcdLockedSuite) TestUpdateIfLocked(c *C) {
	randomPath := c.MkDir()
	type args struct {
		key      string
		lock     KVLocker
		newValue []byte
		lease    bool
	}
	type wanted struct {
		err error
	}
	tests := []struct {
		name        string
		setupArgs   func() args
		setupWanted func() wanted
		cleanup     func(args args) error
	}{
		{
			name: "update locked path without lease",
			setupArgs: func() args {
				key := randomPath + "foo"
				kvlocker, err := Client().LockPath(context.Background(), "locks/"+key+"/.lock")
				c.Assert(err, IsNil)
				_, err = e.etcdClient.Put(context.Background(), key, "bar")
				c.Assert(err, IsNil)

				return args{
					key:      key,
					lock:     kvlocker,
					newValue: []byte("newbar"),
				}
			},
			setupWanted: func() wanted {
				return wanted{
					err: nil,
				}
			},
			cleanup: func(args args) error {
				key := randomPath + "foo"
				// verify that key was actually updated
				gr, err := e.etcdClient.Get(context.Background(), key)
				c.Assert(err, IsNil)
				c.Assert(gr.Count, Equals, int64(1))
				c.Assert(gr.Kvs[0].Value, checker.DeepEquals, []byte("newbar"))

				return args.lock.Unlock(context.TODO())
			},
		},
		{
			name: "update locked path with no value without lease",
			setupArgs: func() args {
				key := randomPath + "foo"
				kvlocker, err := Client().LockPath(context.Background(), "locks/"+key+"/.lock")
				c.Assert(err, IsNil)

				_, err = e.etcdClient.Delete(context.Background(), key)
				c.Assert(err, IsNil)

				return args{
					key:      key,
					lock:     kvlocker,
					newValue: []byte("newbar"),
				}
			},
			setupWanted: func() wanted {
				return wanted{
					err: nil,
				}
			},
			cleanup: func(args args) error {
				key := randomPath + "foo"
				// a key that was updated with no value will create a new value
				gr, err := e.etcdClient.Get(context.Background(), key)
				c.Assert(err, IsNil)
				c.Assert(gr.Count, Equals, int64(1))
				c.Assert(gr.Kvs[0].Value, checker.DeepEquals, []byte("newbar"))

				return args.lock.Unlock(context.TODO())
			},
		},
		{
			name: "update locked path where lock was lost without lease",
			setupArgs: func() args {
				key := randomPath + "foo"
				kvlocker, err := Client().LockPath(context.Background(), "locks/"+key+"/.lock")
				c.Assert(err, IsNil)
				_, err = e.etcdClient.Put(context.Background(), key, "bar")
				c.Assert(err, IsNil)
				err = kvlocker.Unlock(context.TODO())
				c.Assert(err, IsNil)

				return args{
					key:  key,
					lock: kvlocker,
				}
			},
			setupWanted: func() wanted {
				return wanted{
					err: ErrLockLeaseExpired,
				}
			},
			cleanup: func(args args) error {
				key := randomPath + "foo"
				// verify that key was actually updated
				gr, err := e.etcdClient.Get(context.Background(), key)
				c.Assert(err, IsNil)
				c.Assert(gr.Count, Equals, int64(1))
				c.Assert(gr.Kvs[0].Value, checker.DeepEquals, []byte("bar"))
				return nil
			},
		},
		{
			name: "update locked path with lease",
			setupArgs: func() args {
				key := randomPath + "foo"
				kvlocker, err := Client().LockPath(context.Background(), "locks/"+key+"/.lock")
				c.Assert(err, IsNil)
				_, err = e.etcdClient.Put(context.Background(), key, "bar")
				c.Assert(err, IsNil)

				return args{
					key:      key,
					lock:     kvlocker,
					newValue: []byte("newbar"),
					lease:    true,
				}
			},
			setupWanted: func() wanted {
				return wanted{
					err: nil,
				}
			},
			cleanup: func(args args) error {
				key := randomPath + "foo"
				// verify that key was actually updated
				gr, err := e.etcdClient.Get(context.Background(), key)
				c.Assert(err, IsNil)
				c.Assert(gr.Count, Equals, int64(1))
				c.Assert(gr.Kvs[0].Value, checker.DeepEquals, []byte("newbar"))

				return args.lock.Unlock(context.TODO())
			},
		},
		{
			name: "update locked path with no value with lease",
			setupArgs: func() args {
				key := randomPath + "foo"
				kvlocker, err := Client().LockPath(context.Background(), "locks/"+key+"/.lock")
				c.Assert(err, IsNil)

				_, err = e.etcdClient.Delete(context.Background(), key)
				c.Assert(err, IsNil)

				return args{
					key:      key,
					lock:     kvlocker,
					newValue: []byte("newbar"),
					lease:    true,
				}
			},
			setupWanted: func() wanted {
				return wanted{
					err: nil,
				}
			},
			cleanup: func(args args) error {
				key := randomPath + "foo"
				// a key that was updated with no value will create a new value
				gr, err := e.etcdClient.Get(context.Background(), key)
				c.Assert(err, IsNil)
				c.Assert(gr.Count, Equals, int64(1))
				c.Assert(gr.Kvs[0].Value, checker.DeepEquals, []byte("newbar"))

				return args.lock.Unlock(context.TODO())
			},
		},
		{
			name: "update locked path where lock was lost with lease",
			setupArgs: func() args {
				key := randomPath + "foo"
				kvlocker, err := Client().LockPath(context.Background(), "locks/"+key+"/.lock")
				c.Assert(err, IsNil)
				_, err = e.etcdClient.Put(context.Background(), key, "bar")
				c.Assert(err, IsNil)
				err = kvlocker.Unlock(context.TODO())
				c.Assert(err, IsNil)

				return args{
					key:   key,
					lock:  kvlocker,
					lease: true,
				}
			},
			setupWanted: func() wanted {
				return wanted{
					err: ErrLockLeaseExpired,
				}
			},
			cleanup: func(args args) error {
				key := randomPath + "foo"
				// verify that key was actually updated
				gr, err := e.etcdClient.Get(context.Background(), key)
				c.Assert(err, IsNil)
				c.Assert(gr.Count, Equals, int64(1))
				c.Assert(gr.Kvs[0].Value, checker.DeepEquals, []byte("bar"))
				return nil
			},
		},
	}
	for _, tt := range tests {
		c.Log(tt.name)
		args := tt.setupArgs()
		want := tt.setupWanted()
		err := Client().UpdateIfLocked(context.Background(), args.key, args.newValue, args.lease, args.lock)
		c.Assert(err, Equals, want.err)
		err = tt.cleanup(args)
		c.Assert(err, IsNil)
	}
}

func (e *EtcdLockedSuite) TestUpdateIfDifferentIfLocked(c *C) {
	randomPath := c.MkDir()
	type args struct {
		key      string
		lock     KVLocker
		newValue []byte
		lease    bool
	}
	type wanted struct {
		err     error
		updated bool
	}
	tests := []struct {
		name        string
		setupArgs   func() args
		setupWanted func() wanted
		cleanup     func(args args) error
	}{
		{
			name: "update locked path without lease",
			setupArgs: func() args {
				key := randomPath + "foo"
				kvlocker, err := Client().LockPath(context.Background(), "locks/"+key+"/.lock")
				c.Assert(err, IsNil)
				_, err = e.etcdClient.Put(context.Background(), key, "bar")
				c.Assert(err, IsNil)

				return args{
					key:      key,
					lock:     kvlocker,
					newValue: []byte("newbar"),
				}
			},
			setupWanted: func() wanted {
				return wanted{
					err:     nil,
					updated: true,
				}
			},
			cleanup: func(args args) error {
				key := randomPath + "foo"
				// verify that key was actually updated
				gr, err := e.etcdClient.Get(context.Background(), key)
				c.Assert(err, IsNil)
				c.Assert(gr.Count, Equals, int64(1))
				c.Assert(gr.Kvs[0].Value, checker.DeepEquals, []byte("newbar"))
				_, err = e.etcdClient.Delete(context.Background(), key)
				c.Assert(err, IsNil)
				return args.lock.Unlock(context.TODO())
			},
		},
		{
			name: "update locked path without lease and with same value",
			setupArgs: func() args {
				key := randomPath + "foo"
				kvlocker, err := Client().LockPath(context.Background(), "locks/"+key+"/.lock")
				c.Assert(err, IsNil)
				_, err = e.etcdClient.Put(context.Background(), key, "bar")
				c.Assert(err, IsNil)

				return args{
					key:      key,
					lock:     kvlocker,
					newValue: []byte("bar"),
				}
			},
			setupWanted: func() wanted {
				return wanted{
					err: nil,
				}
			},
			cleanup: func(args args) error {
				key := randomPath + "foo"
				// verify that key was actually updated
				gr, err := e.etcdClient.Get(context.Background(), key)
				c.Assert(err, IsNil)
				c.Assert(gr.Count, Equals, int64(1))
				c.Assert(gr.Kvs[0].Value, checker.DeepEquals, []byte("bar"))

				return args.lock.Unlock(context.TODO())
			},
		},
		{
			name: "update locked path with no value without lease",
			setupArgs: func() args {
				key := randomPath + "foo"
				kvlocker, err := Client().LockPath(context.Background(), "locks/"+key+"/.lock")
				c.Assert(err, IsNil)

				_, err = e.etcdClient.Delete(context.Background(), key)
				c.Assert(err, IsNil)

				return args{
					key:      key,
					lock:     kvlocker,
					newValue: []byte("newbar"),
				}
			},
			setupWanted: func() wanted {
				return wanted{
					err:     nil,
					updated: true,
				}
			},
			cleanup: func(args args) error {
				key := randomPath + "foo"
				// a key that was updated with no value will create a new value
				gr, err := e.etcdClient.Get(context.Background(), key)
				c.Assert(err, IsNil)
				c.Assert(gr.Count, Equals, int64(1))
				c.Assert(gr.Kvs[0].Value, checker.DeepEquals, []byte("newbar"))
				_, err = e.etcdClient.Delete(context.Background(), key)
				c.Assert(err, IsNil)
				return args.lock.Unlock(context.TODO())
			},
		},
		{
			name: "update locked path where lock was lost without lease",
			setupArgs: func() args {
				key := randomPath + "foo"
				kvlocker, err := Client().LockPath(context.Background(), "locks/"+key+"/.lock")
				c.Assert(err, IsNil)
				_, err = e.etcdClient.Put(context.Background(), key, "bar")
				c.Assert(err, IsNil)
				err = kvlocker.Unlock(context.TODO())
				c.Assert(err, IsNil)

				return args{
					key:      key,
					newValue: []byte("baz"),
					lock:     kvlocker,
				}
			},
			setupWanted: func() wanted {
				return wanted{
					err: ErrLockLeaseExpired,
				}
			},
			cleanup: func(args args) error {
				key := randomPath + "foo"
				// verify that key was actually updated
				gr, err := e.etcdClient.Get(context.Background(), key)
				c.Assert(err, IsNil)
				c.Assert(gr.Count, Equals, int64(1))
				c.Assert(gr.Kvs[0].Value, checker.DeepEquals, []byte("bar"))
				_, err = e.etcdClient.Delete(context.Background(), key)
				c.Assert(err, IsNil)
				return nil
			},
		},
		{
			name: "update locked path with lease",
			setupArgs: func() args {
				key := randomPath + "foo"
				kvlocker, err := Client().LockPath(context.Background(), "locks/"+key+"/.lock")
				c.Assert(err, IsNil)
				_, err = e.etcdClient.Put(context.Background(), key, "bar")
				c.Assert(err, IsNil)

				return args{
					key:      key,
					lock:     kvlocker,
					newValue: []byte("newbar"),
					lease:    true,
				}
			},
			setupWanted: func() wanted {
				return wanted{
					err:     nil,
					updated: true,
				}
			},
			cleanup: func(args args) error {
				key := randomPath + "foo"
				// verify that key was actually updated
				gr, err := e.etcdClient.Get(context.Background(), key)
				c.Assert(err, IsNil)
				c.Assert(gr.Count, Equals, int64(1))
				c.Assert(gr.Kvs[0].Value, checker.DeepEquals, []byte("newbar"))
				_, err = e.etcdClient.Delete(context.Background(), key)
				c.Assert(err, IsNil)
				return args.lock.Unlock(context.TODO())
			},
		},
		{
			name: "update locked path with no value with lease",
			setupArgs: func() args {
				key := randomPath + "foo"
				kvlocker, err := Client().LockPath(context.Background(), "locks/"+key+"/.lock")
				c.Assert(err, IsNil)

				_, err = e.etcdClient.Delete(context.Background(), key)
				c.Assert(err, IsNil)

				return args{
					key:      key,
					lock:     kvlocker,
					newValue: []byte("newbar"),
					lease:    true,
				}
			},
			setupWanted: func() wanted {
				return wanted{
					err:     nil,
					updated: true,
				}
			},
			cleanup: func(args args) error {
				key := randomPath + "foo"
				// a key that was updated with no value will create a new value
				gr, err := e.etcdClient.Get(context.Background(), key)
				c.Assert(err, IsNil)
				c.Assert(gr.Count, Equals, int64(1))
				c.Assert(gr.Kvs[0].Value, checker.DeepEquals, []byte("newbar"))

				_, err = e.etcdClient.Delete(context.Background(), key)
				c.Assert(err, IsNil)

				return args.lock.Unlock(context.TODO())
			},
		},
		{
			name: "update locked path with lease and with same value",
			setupArgs: func() args {
				key := randomPath + "foo"
				kvlocker, err := Client().LockPath(context.Background(), "locks/"+key+"/.lock")
				c.Assert(err, IsNil)
				created, err := Client().CreateOnly(context.Background(), key, []byte("bar"), true)
				c.Assert(err, IsNil)
				c.Assert(created, Equals, true)

				return args{
					key:      key,
					lock:     kvlocker,
					newValue: []byte("bar"),
					lease:    true,
				}
			},
			setupWanted: func() wanted {
				return wanted{
					err: nil,
				}
			},
			cleanup: func(args args) error {
				key := randomPath + "foo"
				// verify that key was actually updated
				gr, err := e.etcdClient.Get(context.Background(), key)
				c.Assert(err, IsNil)
				c.Assert(gr.Count, Equals, int64(1))
				c.Assert(gr.Kvs[0].Value, checker.DeepEquals, []byte("bar"))
				_, err = e.etcdClient.Delete(context.Background(), key)
				c.Assert(err, IsNil)
				return args.lock.Unlock(context.TODO())
			},
		},
		{
			name: "update locked path where lock was lost with lease",
			setupArgs: func() args {
				key := randomPath + "foo"
				kvlocker, err := Client().LockPath(context.Background(), "locks/"+key+"/.lock")
				c.Assert(err, IsNil)
				_, err = e.etcdClient.Put(context.Background(), key, "bar")
				c.Assert(err, IsNil)
				err = kvlocker.Unlock(context.TODO())
				c.Assert(err, IsNil)

				return args{
					key:   key,
					lock:  kvlocker,
					lease: true,
				}
			},
			setupWanted: func() wanted {
				return wanted{
					err: ErrLockLeaseExpired,
				}
			},
			cleanup: func(args args) error {
				key := randomPath + "foo"
				// verify that key was actually updated
				gr, err := e.etcdClient.Get(context.Background(), key)
				c.Assert(err, IsNil)
				c.Assert(gr.Count, Equals, int64(1))
				c.Assert(gr.Kvs[0].Value, checker.DeepEquals, []byte("bar"))
				return nil
			},
		},
	}
	for _, tt := range tests {
		c.Log(tt.name)
		args := tt.setupArgs()
		want := tt.setupWanted()
		updated, err := Client().UpdateIfDifferentIfLocked(context.Background(), args.key, args.newValue, args.lease, args.lock)
		c.Assert(err, Equals, want.err)
		c.Assert(updated, Equals, want.updated)
		err = tt.cleanup(args)
		c.Assert(err, IsNil)
	}
}

func (e *EtcdLockedSuite) TestCreateOnlyIfLocked(c *C) {
	randomPath := c.MkDir()
	type args struct {
		key      string
		lock     KVLocker
		newValue []byte
		lease    bool
	}
	type wanted struct {
		err     error
		created bool
	}
	tests := []struct {
		name        string
		setupArgs   func() args
		setupWanted func() wanted
		cleanup     func(args args) error
	}{
		{
			name: "create only locked path without lease",
			setupArgs: func() args {
				key := randomPath + "foo"
				kvlocker, err := Client().LockPath(context.Background(), "locks/"+key+"/.lock")
				c.Assert(err, IsNil)

				_, err = e.etcdClient.Delete(context.Background(), key)
				c.Assert(err, IsNil)

				return args{
					key:      key,
					lock:     kvlocker,
					newValue: []byte("newbar"),
				}
			},
			setupWanted: func() wanted {
				return wanted{
					err:     nil,
					created: true,
				}
			},
			cleanup: func(args args) error {
				key := randomPath + "foo"
				// verify that key was actually created
				gr, err := e.etcdClient.Get(context.Background(), key)
				c.Assert(err, IsNil)
				c.Assert(gr.Count, Equals, int64(1))
				c.Assert(gr.Kvs[0].Value, checker.DeepEquals, []byte("newbar"))

				return args.lock.Unlock(context.TODO())
			},
		},
		{
			name: "create only locked path with an existing value without lease",
			setupArgs: func() args {
				key := randomPath + "foo"
				kvlocker, err := Client().LockPath(context.Background(), "locks/"+key+"/.lock")
				c.Assert(err, IsNil)

				_, err = e.etcdClient.Put(context.Background(), key, "bar")
				c.Assert(err, IsNil)

				return args{
					key:      key,
					lock:     kvlocker,
					newValue: []byte("newbar"),
				}
			},
			setupWanted: func() wanted {
				return wanted{
					err: nil,
				}
			},
			cleanup: func(args args) error {
				key := randomPath + "foo"
				// the key should not have been created and therefore the old
				// value is still there
				gr, err := e.etcdClient.Get(context.Background(), key)
				c.Assert(err, IsNil)
				c.Assert(gr.Count, Equals, int64(1))
				c.Assert(gr.Kvs[0].Value, checker.DeepEquals, []byte("bar"))

				return args.lock.Unlock(context.TODO())
			},
		},
		{
			name: "create only locked path where lock was lost without lease",
			setupArgs: func() args {
				key := randomPath + "foo"
				kvlocker, err := Client().LockPath(context.Background(), "locks/"+key+"/.lock")
				c.Assert(err, IsNil)
				_, err = e.etcdClient.Delete(context.Background(), key)
				c.Assert(err, IsNil)
				err = kvlocker.Unlock(context.TODO())
				c.Assert(err, IsNil)

				return args{
					key:      key,
					lock:     kvlocker,
					newValue: []byte("bar"),
				}
			},
			setupWanted: func() wanted {
				return wanted{
					err: ErrLockLeaseExpired,
				}
			},
			cleanup: func(args args) error {
				key := randomPath + "foo"
				// verify that key was not created
				gr, err := e.etcdClient.Get(context.Background(), key)
				c.Assert(err, IsNil)
				c.Assert(gr.Count, Equals, int64(0))
				return nil
			},
		},
		{
			name: "create only locked path with lease",
			setupArgs: func() args {
				key := randomPath + "foo"
				kvlocker, err := Client().LockPath(context.Background(), "locks/"+key+"/.lock")
				c.Assert(err, IsNil)

				_, err = e.etcdClient.Delete(context.Background(), key)
				c.Assert(err, IsNil)

				return args{
					key:      key,
					lock:     kvlocker,
					newValue: []byte("newbar"),
					lease:    true,
				}
			},
			setupWanted: func() wanted {
				return wanted{
					err:     nil,
					created: true,
				}
			},
			cleanup: func(args args) error {
				key := randomPath + "foo"
				// verify that key was actually created
				gr, err := e.etcdClient.Get(context.Background(), key)
				c.Assert(err, IsNil)
				c.Assert(gr.Count, Equals, int64(1))
				c.Assert(gr.Kvs[0].Value, checker.DeepEquals, []byte("newbar"))

				return args.lock.Unlock(context.TODO())
			},
		},
		{
			name: "create only locked path with an existing value with lease",
			setupArgs: func() args {
				key := randomPath + "foo"
				kvlocker, err := Client().LockPath(context.Background(), "locks/"+key+"/.lock")
				c.Assert(err, IsNil)

				_, err = e.etcdClient.Put(context.Background(), key, "bar")
				c.Assert(err, IsNil)

				return args{
					key:      key,
					lock:     kvlocker,
					newValue: []byte("newbar"),
					lease:    true,
				}
			},
			setupWanted: func() wanted {
				return wanted{
					err: nil,
				}
			},
			cleanup: func(args args) error {
				key := randomPath + "foo"
				// the key should not have been created and therefore the old
				// value is still there
				gr, err := e.etcdClient.Get(context.Background(), key)
				c.Assert(err, IsNil)
				c.Assert(gr.Count, Equals, int64(1))
				c.Assert(gr.Kvs[0].Value, checker.DeepEquals, []byte("bar"))

				return args.lock.Unlock(context.TODO())
			},
		},
		{
			name: "create only locked path where lock was lost with lease",
			setupArgs: func() args {
				key := randomPath + "foo"
				kvlocker, err := Client().LockPath(context.Background(), "locks/"+key+"/.lock")
				c.Assert(err, IsNil)
				_, err = e.etcdClient.Delete(context.Background(), key)
				c.Assert(err, IsNil)
				err = kvlocker.Unlock(context.TODO())
				c.Assert(err, IsNil)

				return args{
					key:      key,
					lock:     kvlocker,
					newValue: []byte("bar"),
					lease:    true,
				}
			},
			setupWanted: func() wanted {
				return wanted{
					err: ErrLockLeaseExpired,
				}
			},
			cleanup: func(args args) error {
				key := randomPath + "foo"
				// verify that key was not created
				gr, err := e.etcdClient.Get(context.Background(), key)
				c.Assert(err, IsNil)
				c.Assert(gr.Count, Equals, int64(0))
				return nil
			},
		},
	}
	for _, tt := range tests {
		c.Log(tt.name)
		args := tt.setupArgs()
		want := tt.setupWanted()
		created, err := Client().CreateOnlyIfLocked(context.Background(), args.key, args.newValue, args.lease, args.lock)
		c.Assert(err, Equals, want.err)
		c.Assert(created, Equals, want.created)
		err = tt.cleanup(args)
		c.Assert(err, IsNil)
	}
}

func (e *EtcdLockedSuite) TestListPrefixIfLocked(c *C) {
	randomPath := c.MkDir()
	type args struct {
		key  string
		lock KVLocker
	}
	type wanted struct {
		err     error
		kvPairs KeyValuePairs
	}
	tests := []struct {
		name        string
		setupArgs   func() args
		setupWanted func() wanted
		cleanup     func(args args) error
	}{
		{
			name: "list prefix locked",
			setupArgs: func() args {
				key := randomPath + "foo"
				kvlocker, err := Client().LockPath(context.Background(), "locks/"+key+"/.lock")
				c.Assert(err, IsNil)
				_, err = e.etcdClient.Put(context.Background(), key, "bar")
				c.Assert(err, IsNil)
				_, err = e.etcdClient.Put(context.Background(), key+"1", "bar1")
				c.Assert(err, IsNil)

				return args{
					key:  key,
					lock: kvlocker,
				}
			},
			setupWanted: func() wanted {
				key := randomPath + "foo"
				return wanted{
					err: nil,
					kvPairs: KeyValuePairs{
						key: Value{
							Data: []byte("bar"),
						},
						key + "1": Value{
							Data: []byte("bar1"),
						},
					},
				}
			},
			cleanup: func(args args) error {
				_, err := e.etcdClient.Delete(context.Background(), args.key, etcdAPI.WithPrefix())
				if err != nil {
					return err
				}
				return args.lock.Unlock(context.TODO())
			},
		},
		{
			name: "list prefix locked with no values",
			setupArgs: func() args {
				key := randomPath + "foo"
				kvlocker, err := Client().LockPath(context.Background(), "locks/"+key+"/.lock")
				c.Assert(err, IsNil)
				_, err = e.etcdClient.Delete(context.Background(), key, etcdAPI.WithPrefix())
				c.Assert(err, IsNil)

				return args{
					key:  key,
					lock: kvlocker,
				}
			},
			setupWanted: func() wanted {
				return wanted{
					err: nil,
				}
			},
			cleanup: func(args args) error {
				return args.lock.Unlock(context.TODO())
			},
		},
		{
			name: "list prefix locked where lock was lost",
			setupArgs: func() args {
				key := randomPath + "foo"
				kvlocker, err := Client().LockPath(context.Background(), "locks/"+key+"/.lock")
				c.Assert(err, IsNil)
				_, err = e.etcdClient.Put(context.Background(), key, "bar")
				c.Assert(err, IsNil)
				_, err = e.etcdClient.Put(context.Background(), key+"1", "bar1")
				c.Assert(err, IsNil)
				err = kvlocker.Unlock(context.TODO())
				c.Assert(err, IsNil)

				return args{
					key:  key,
					lock: kvlocker,
				}
			},
			setupWanted: func() wanted {
				return wanted{
					err: ErrLockLeaseExpired,
				}
			},
			cleanup: func(args args) error {
				_, err := e.etcdClient.Delete(context.Background(), args.key)
				return err
			},
		},
	}
	for _, tt := range tests {
		c.Log(tt.name)
		args := tt.setupArgs()
		want := tt.setupWanted()
		kvPairs, err := Client().ListPrefixIfLocked(context.TODO(), args.key, args.lock)
		c.Assert(err, Equals, want.err)
		for k, v := range kvPairs {
			// We don't compare revision of the value because we can't predict
			// its value.
			v1, ok := want.kvPairs[k]
			c.Assert(ok, Equals, true)
			c.Assert(v.Data, checker.DeepEquals, v1.Data)
		}
		err = tt.cleanup(args)
		c.Assert(err, IsNil)
	}
}

func TestGetSvcNamespace(t *testing.T) {
	type args struct {
		address string
	}
	tests := []struct {
		name          string
		args          args
		wantSvcName   string
		wantNamespace string
		wantErr       bool
	}{
		{
			name: "test-1",
			args: args{
				address: "http://foo.bar.something",
			},
			wantSvcName:   "foo",
			wantNamespace: "bar",
			wantErr:       false,
		},
		{
			name: "test-2",
			args: args{
				address: "http://foo.bar",
			},
			wantSvcName:   "foo",
			wantNamespace: "bar",
			wantErr:       false,
		},
		{
			name: "test-3",
			args: args{
				address: "http://foo",
			},
			wantErr: true,
		},
		{
			name: "test-4",
			args: args{
				address: "http://foo.bar:5679/",
			},
			wantSvcName:   "foo",
			wantNamespace: "bar",
			wantErr:       false,
		},
		{
			name: "test-5",
			args: args{
				address: "http://foo:2379",
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, got1, err := SplitK8sServiceURL(tt.args.address)
			if (err != nil) != tt.wantErr {
				t.Errorf("SplitK8sServiceURL() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.wantSvcName {
				t.Errorf("SplitK8sServiceURL() got = %v, want %v", got, tt.wantSvcName)
			}
			if got1 != tt.wantNamespace {
				t.Errorf("SplitK8sServiceURL() got1 = %v, want %v", got1, tt.wantNamespace)
			}
		})
	}
}
func TestShuffleEndpoints(t *testing.T) {
	s1 := []string{"1", "2", "3", "4", "5"}
	s2 := make([]string, len(s1))
	copy(s2, s1)

	var same int
	for retry := 0; retry < 10; retry++ {
		same = 0
		shuffleEndpoints(s2)
		for i := range s1 {
			if s1[i] == s2[i] {
				same++
			}
		}
		if same != len(s1) {
			break
		}
	}
	if same == len(s1) {
		t.Errorf("Shuffle() did not modify s2 in 10 retries")
	}
}

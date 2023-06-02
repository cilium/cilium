// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package kvstore

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"sync"
	"testing"
	"time"

	. "github.com/cilium/checkmate"
	etcdAPI "go.etcd.io/etcd/client/v3"

	"github.com/cilium/cilium/pkg/checker"
	"github.com/cilium/cilium/pkg/testutils"
)

type EtcdSuite struct {
	BaseTests
}

var _ = Suite(&EtcdSuite{})

func (e *EtcdSuite) SetUpSuite(c *C) {
	testutils.IntegrationCheck(c)
}

func (e *EtcdSuite) SetUpTest(c *C) {
	SetupDummy("etcd")
}

func (e *EtcdSuite) TearDownTest(c *C) {
	Client().Close(context.TODO())
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
	timeout := time.Second

	c.Assert(client.checkMinVersion(context.TODO(), timeout), IsNil)

	// One endpoint has a bad version and should fail
	cfg.Endpoints = []string{"http://127.0.0.1:4003", "http://127.0.0.1:4004", "http://127.0.0.1:4005"}
	cli, err = etcdAPI.New(cfg)
	c.Assert(err, IsNil)
	cli.Maintenance = mm
	client = etcdClient{
		client: cli,
	}

	c.Assert(client.checkMinVersion(context.TODO(), timeout), Not(IsNil))
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
	err := os.WriteFile(etcdTempFile, etcdConfigByte, 0600)
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
	testutils.IntegrationCheck(c)

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
	testutils.IntegrationCheck(c)

	err := e.etcdClient.Close()
	c.Assert(err, IsNil)
	Client().Close(context.TODO())
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

type EtcdRateLimiterSuite struct {
	etcdClient *etcdAPI.Client
	maxQPS     int
	txnCount   int

	// minTime should be calculated as floor(txnCount / rateLimit) - 1
	minTime time.Duration
}

var _ = Suite(&EtcdRateLimiterSuite{})

func (e *EtcdRateLimiterSuite) setupWithRateLimiter() {
	// The rate limiter is configured with max QPS and burst both
	// configured to the provided value for rate limit option.
	setupDummyWithConfigOpts("etcd", map[string]string{
		EtcdRateLimitOption: fmt.Sprintf("%d", e.maxQPS),
	})

	ctx, cancel := context.WithTimeout(context.Background(), time.Second*30)
	defer cancel()
	<-Client().Connected(ctx)
}

func (e *EtcdRateLimiterSuite) setupWithoutRateLimiter() {
	SetupDummy("etcd")
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*30)
	defer cancel()
	<-Client().Connected(ctx)
}

func (e *EtcdRateLimiterSuite) SetUpSuite(c *C) {
	testutils.IntegrationCheck(c)

	e.maxQPS = 3
	e.txnCount = e.maxQPS*2 + 2
	e.minTime = time.Second

	// setup client
	cfg := etcdAPI.Config{}
	cfg.Endpoints = []string{etcdDummyAddress}
	cfg.DialTimeout = 0
	cli, err := etcdAPI.New(cfg)
	c.Assert(err, IsNil)
	e.etcdClient = cli
}

func (e *EtcdRateLimiterSuite) TearDownSuite(c *C) {
	testutils.IntegrationCheck(c)

	err := e.etcdClient.Close()
	c.Assert(err, IsNil)
}

func (e *EtcdRateLimiterSuite) getKey(prefix string, c int) string {
	if prefix != "" {
		return fmt.Sprintf("%s-%d", prefix, c)
	}

	return fmt.Sprintf("foobar-%d", c)
}

func (e *EtcdRateLimiterSuite) populateKVPairs(c *C, prefix string, count int) {
	for i := 0; i < count; i++ {
		key := e.getKey(prefix, i)

		_, err := e.etcdClient.Put(context.Background(), key, "bar")
		c.Assert(err, IsNil)
	}
}

func (e *EtcdRateLimiterSuite) cleanKVPairs(c *C, prefix string, count int) {
	for i := 0; i < count; i++ {
		key := e.getKey(prefix, i)

		_, err := e.etcdClient.Delete(context.Background(), key)
		c.Assert(err, IsNil)
	}
}

func (e *EtcdRateLimiterSuite) TestRateLimiter(c *C) {
	randomPath := c.MkDir()
	kvstoreVal := []byte("bar")
	key := randomPath + "foo"
	condKey := key + "-cond-key"

	opsFuncList := []struct {
		fn              func(*C, string, int, KVLocker)
		name            string
		useKVLocker     bool
		needCondKey     bool
		populateKVPairs bool
		cleanKVPairs    bool
	}{
		{
			fn: func(c *C, key string, k int, locker KVLocker) {
				value, err := Client().GetIfLocked(context.TODO(), e.getKey(key, k), locker)
				c.Assert(err, IsNil)
				c.Assert(value, checker.DeepEquals, kvstoreVal)
			},
			name:            "GetIfLocked",
			useKVLocker:     true,
			populateKVPairs: true,
			cleanKVPairs:    true,
		},
		{
			fn: func(c *C, key string, k int, _ KVLocker) {
				value, err := Client().Get(context.TODO(), e.getKey(key, k))
				c.Assert(err, IsNil)
				c.Assert(value, checker.DeepEquals, kvstoreVal)
			},
			name:            "Get",
			populateKVPairs: true,
			cleanKVPairs:    true,
		},
		{
			fn: func(c *C, key string, k int, _ KVLocker) {
				retKey, value, err := Client().GetPrefix(context.TODO(), e.getKey(key, k))
				c.Assert(err, IsNil)
				c.Assert(retKey, Equals, e.getKey(key, k))
				c.Assert(value, checker.DeepEquals, kvstoreVal)
			},
			name:            "GetPrefix",
			populateKVPairs: true,
			cleanKVPairs:    true,
		},
		{
			fn: func(c *C, key string, k int, locker KVLocker) {
				retKey, value, err := Client().GetPrefixIfLocked(context.TODO(), e.getKey(key, k), locker)
				c.Assert(err, IsNil)
				c.Assert(retKey, Equals, e.getKey(key, k))
				c.Assert(value, checker.DeepEquals, kvstoreVal)
			},
			name:            "GetPrefixIfLocked",
			useKVLocker:     true,
			populateKVPairs: true,
			cleanKVPairs:    true,
		},
		{
			fn: func(c *C, key string, k int, _ KVLocker) {
				kvPairs, err := Client().ListPrefix(context.TODO(), e.getKey(key, k))
				c.Assert(err, IsNil)
				c.Assert(len(kvPairs), Equals, 1)
				value, ok := kvPairs[e.getKey(key, k)]
				c.Assert(ok, Equals, true)
				c.Assert(value.Data, checker.DeepEquals, kvstoreVal)
			},
			name:            "ListPrefix",
			populateKVPairs: true,
			cleanKVPairs:    true,
		},
		{
			fn: func(c *C, key string, k int, locker KVLocker) {
				kvPairs, err := Client().ListPrefixIfLocked(context.TODO(), e.getKey(key, k), locker)
				c.Assert(err, IsNil)
				c.Assert(len(kvPairs), Equals, 1)
				value, ok := kvPairs[e.getKey(key, k)]
				c.Assert(ok, Equals, true)
				c.Assert(value.Data, checker.DeepEquals, kvstoreVal)
			},
			name:            "ListPrefixIfLocked",
			useKVLocker:     true,
			populateKVPairs: true,
			cleanKVPairs:    true,
		},
		{
			fn: func(c *C, key string, k int, _ KVLocker) {
				newVal := []byte("bar-new")
				updated, err := Client().UpdateIfDifferent(context.TODO(), e.getKey(key, k), newVal, true)
				c.Assert(err, IsNil)
				c.Assert(updated, Equals, true)
			},
			name:            "UpdateIfDifferent",
			populateKVPairs: true,
			cleanKVPairs:    true,
		},
		{
			fn: func(c *C, key string, k int, locker KVLocker) {
				newVal := []byte("bar-new")
				updated, err := Client().UpdateIfDifferentIfLocked(context.TODO(), e.getKey(key, k), newVal, true, locker)
				c.Assert(err, IsNil)
				c.Assert(updated, Equals, true)
			},
			name:            "UpdateIfDifferentIfLocked",
			useKVLocker:     true,
			populateKVPairs: true,
			cleanKVPairs:    true,
		},
		{
			fn: func(c *C, key string, k int, _ KVLocker) {
				err := Client().Set(context.TODO(), e.getKey(key, k), kvstoreVal)
				c.Assert(err, IsNil)
			},
			name:         "Set",
			cleanKVPairs: true,
		},
		{
			fn: func(c *C, key string, k int, _ KVLocker) {
				err := Client().Update(context.TODO(), e.getKey(key, k), []byte(kvstoreVal), true)
				c.Assert(err, IsNil)
			},
			name:         "Update",
			cleanKVPairs: true,
		},
		{
			fn: func(c *C, key string, k int, locker KVLocker) {
				err := Client().UpdateIfLocked(context.TODO(), e.getKey(key, k), []byte(kvstoreVal), true, locker)
				c.Assert(err, IsNil)
			},
			name:         "UpdateIfLocked",
			useKVLocker:  true,
			cleanKVPairs: true,
		},
		{
			fn: func(c *C, key string, k int, _ KVLocker) {
				created, err := Client().CreateOnly(context.TODO(), e.getKey(key, k), []byte(kvstoreVal), true)
				c.Assert(err, IsNil)
				c.Assert(created, Equals, true)
			},
			name:         "CreateOnly",
			cleanKVPairs: true,
		},
		{
			fn: func(c *C, key string, k int, locker KVLocker) {
				created, err := Client().CreateOnlyIfLocked(context.TODO(), e.getKey(key, k), []byte(kvstoreVal), true, locker)
				c.Assert(err, IsNil)
				c.Assert(created, Equals, true)
			},
			name:         "CreateOnlyIfLocked",
			useKVLocker:  true,
			cleanKVPairs: true,
		},
		{
			fn: func(c *C, key string, k int, _ KVLocker) {
				err := Client().CreateIfExists(context.TODO(), condKey, e.getKey(key, k), []byte(kvstoreVal), true)
				c.Assert(err, IsNil)
			},
			name:         "CreateIfExists",
			useKVLocker:  true,
			needCondKey:  true,
			cleanKVPairs: true,
		},
		{
			fn: func(c *C, key string, k int, _ KVLocker) {
				err := Client().Delete(context.TODO(), e.getKey(key, k))
				c.Assert(err, IsNil)
			},
			name:            "Delete",
			populateKVPairs: true,
		},
		{
			fn: func(c *C, key string, k int, locker KVLocker) {
				err := Client().DeleteIfLocked(context.TODO(), e.getKey(key, k), locker)
				c.Assert(err, IsNil)
			},
			name:            "DeleteIfLocked",
			useKVLocker:     true,
			populateKVPairs: true,
		},
		{
			fn: func(c *C, key string, k int, _ KVLocker) {
				err := Client().DeletePrefix(context.TODO(), e.getKey(key, k))
				c.Assert(err, IsNil)
			},
			name:            "DeletePrefix",
			useKVLocker:     true,
			populateKVPairs: true,
		},
	}

	for _, op := range opsFuncList {
		c.Logf("Validating operation: %s\n", op.name)
		var (
			kvlocker KVLocker
			err      error
		)

		if op.populateKVPairs {
			e.populateKVPairs(c, key, e.txnCount)
		}
		if op.needCondKey {
			_, err = e.etcdClient.Put(context.Background(), condKey, string(kvstoreVal))
			c.Assert(err, IsNil)
		}

		// Run test without rate limiter configured for etcd client.
		e.setupWithoutRateLimiter()

		if op.useKVLocker {
			kvlocker, err = Client().LockPath(context.Background(), "locks/"+key+"/.lock")
			c.Assert(err, IsNil)
		}

		start := time.Now()
		wg := sync.WaitGroup{}
		for i := 0; i < e.txnCount; i++ {
			wg.Add(1)
			go func(wg *sync.WaitGroup, i int) {
				defer wg.Done()
				op.fn(c, key, i, kvlocker)
			}(&wg, i)
		}
		wg.Wait()
		c.Assert(time.Since(start) < e.minTime, Equals, true)

		if op.useKVLocker {
			err = kvlocker.Unlock(context.TODO())
			c.Assert(err, IsNil)
		}
		Client().Close(context.TODO())

		// Clean created KV Pairs if populateKVPairs is disabled and cleanKVPairs is enabled.
		if !op.populateKVPairs && op.cleanKVPairs {
			e.cleanKVPairs(c, key, e.txnCount)
		}

		// Populate KV Pairs again if populateKVPairs is enabled and cleanKVPairs is disabled.
		if op.populateKVPairs && !op.cleanKVPairs {
			e.populateKVPairs(c, key, e.txnCount)
		}

		// Run tests with rate limiter configured for etcd client.
		e.setupWithRateLimiter()
		if op.useKVLocker {
			kvlocker, err = Client().LockPath(context.Background(), "locks/"+key+"/.lock")
			c.Assert(err, IsNil)
		}

		start = time.Now()
		wg = sync.WaitGroup{}
		for i := 0; i < e.txnCount; i++ {
			wg.Add(1)
			go func(wg *sync.WaitGroup, i int) {
				defer wg.Done()
				op.fn(c, key, i, kvlocker)
			}(&wg, i)
		}
		wg.Wait()
		c.Assert(time.Since(start) > e.minTime, Equals, true)

		if op.useKVLocker {
			err = kvlocker.Unlock(context.TODO())
			c.Assert(err, IsNil)
		}
		Client().Close(context.TODO())

		if op.needCondKey {
			_, err = e.etcdClient.Delete(context.Background(), condKey)
			c.Assert(err, IsNil)
		}
		if op.cleanKVPairs {
			e.cleanKVPairs(c, key, e.txnCount)
		}
	}
}

func (e *EtcdSuite) TestPaginatedList(c *C) {
	const prefix = "list/paginated"
	ctx := context.Background()

	run := func(batch int) {
		keys := map[string]struct{}{
			path.Join(prefix, "immortal-finch"):   {},
			path.Join(prefix, "rare-goshawk"):     {},
			path.Join(prefix, "cunning-bison"):    {},
			path.Join(prefix, "amusing-tick"):     {},
			path.Join(prefix, "prepared-shark"):   {},
			path.Join(prefix, "exciting-mustang"): {},
			path.Join(prefix, "ethical-ibex"):     {},
			path.Join(prefix, "accepted-kite"):    {},
			path.Join(prefix, "model-javelin"):    {},
			path.Join(prefix, "inviting-hog"):     {},
		}

		defer func(previous int) {
			Client().(*etcdClient).listBatchSize = previous
			c.Assert(Client().DeletePrefix(ctx, prefix), IsNil)
		}(Client().(*etcdClient).listBatchSize)
		Client().(*etcdClient).listBatchSize = batch

		var expected int64
		for key := range keys {
			res, err := Client().(*etcdClient).client.Put(ctx, key, "value")
			expected = res.Header.Revision
			c.Assert(err, IsNil)
		}

		kvs, found, err := Client().(*etcdClient).paginatedList(ctx, log, prefix)
		c.Assert(err, IsNil)

		for _, kv := range kvs {
			key := string(kv.Key)
			if _, ok := keys[key]; !ok {
				c.Fatalf("Retrieved unexpected key, key: %s", key)
			}
			delete(keys, key)
		}

		c.Assert(keys, HasLen, 0)

		// There is no guarantee that found == expected, because new operations might have occurred in parallel.
		if found < expected {
			c.Fatalf("Next revision (%d) is lower than the one of the last update (%d)", found, expected)
		}
	}

	// Batch size = 1
	run(1)

	// Batch size = 4
	run(4)

	// Batch size = 11
	run(11)
}

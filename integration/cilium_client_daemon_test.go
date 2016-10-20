//
// Copyright 2016 Authors of Cilium
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
//
package integration

import (
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"

	"github.com/cilium/cilium/common/addressing"
	"github.com/cilium/cilium/common/backend"
	cnc "github.com/cilium/cilium/common/client"
	"github.com/cilium/cilium/common/types"
	cnd "github.com/cilium/cilium/daemon/daemon"
	cns "github.com/cilium/cilium/daemon/server"

	. "gopkg.in/check.v1"
)

func Test(t *testing.T) { TestingT(t) }

type CiliumClientSuite struct {
	cli    backend.CiliumBackend
	server cns.Server
}

var _ = Suite(&CiliumClientSuite{})

func (s *CiliumClientSuite) SetUpSuite(c *C) {
	socketDir := os.Getenv("SOCKET_DIR")
	socketPath := filepath.Join(socketDir, "cilium.sock")
	tempLibDir, err := ioutil.TempDir("", "cilium-test")
	c.Assert(err, IsNil)
	tempRunDir, err := ioutil.TempDir("", "cilium-test-run")
	c.Assert(err, IsNil)
	err = os.Mkdir(filepath.Join(tempRunDir, "globals"), 0777)
	c.Assert(err, IsNil)

	nodeAddress, err := addressing.NewNodeAddress("beef:beef:beef:beef:aaaa:aaaa:1111:0", "10.1.0.1", "")
	c.Assert(err, IsNil)

	daemonConf := cnd.NewConfig()
	daemonConf.LibDir = tempLibDir
	daemonConf.RunDir = tempRunDir
	daemonConf.DryMode = true
	daemonConf.LXCMap = nil
	daemonConf.NodeAddress = nodeAddress
	daemonConf.DockerEndpoint = "tcp://127.0.0.1"
	daemonConf.K8sEndpoint = "tcp://127.0.0.1"
	daemonConf.ValidLabelPrefixes = nil
	daemonConf.OptsMU.Lock()
	daemonConf.Opts.Set(types.OptionDropNotify, true)
	daemonConf.OptsMU.Unlock()
	daemonConf.Device = "undefined"

	err = daemonConf.SetKVBackend()
	c.Assert(err, IsNil)

	d1 := []byte("#!/usr/bin/env bash\necho \"OK\"\n")
	err = ioutil.WriteFile(filepath.Join(daemonConf.LibDir, "join_ep.sh"), d1, 0755)
	c.Assert(err, IsNil)
	err = ioutil.WriteFile(filepath.Join(daemonConf.LibDir, "init.sh"), d1, 0755)
	c.Assert(err, IsNil)

	d, err := cnd.NewDaemon(daemonConf)
	if err != nil {
		c.Fatalf("Failed while creating new cilium-net test server: %+v", err)
	}
	server, err := cns.NewServer(socketPath, d)
	if err != nil {
		c.Fatalf("Failed while creating new cilium-net test server: %+v", err)
	}

	cli, err := cnc.NewClient("unix://"+socketPath, nil)
	if err != nil {
		c.Fatalf("Failed while creating new client: %+v", err)
	}
	s.cli = cli
	s.server = server

	go func() {
		if err := s.server.Start(); err != nil {
			c.Fatalf("Error while starting cilium-net test server: %s", err)
			s.server.Stop()
		}
	}()
}

func (s *CiliumClientSuite) TearDownSuite(c *C) {
	socketDir := os.Getenv("SOCKET_DIR")
	socketPath := filepath.Join(socketDir, "cilium.sock")
	defer func() {
		if err := os.RemoveAll(socketPath); err != nil {
			c.Errorf("Failed while removing cilium-net test server socket: %s", err)
		}
	}()

	if err := s.server.Stop(); err != nil {
		c.Errorf("Error while stopping cilium-net test server %s", err)
	}
}

func (s *CiliumClientSuite) TestGetPing(c *C) {
	_, err := s.cli.Ping()
	c.Assert(err, Equals, nil, Commentf("Error while Pinging server: %s", err))
}

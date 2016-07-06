package integration

import (
	"io/ioutil"
	"net"
	"os"
	"path/filepath"
	"testing"

	"github.com/noironetworks/cilium-net/common/backend"
	cnc "github.com/noironetworks/cilium-net/common/client"
	"github.com/noironetworks/cilium-net/common/types"
	cnd "github.com/noironetworks/cilium-net/daemon/daemon"
	cns "github.com/noironetworks/cilium-net/daemon/server"

	consulAPI "github.com/hashicorp/consul/api"
	. "gopkg.in/check.v1"
)

var (
	EpAddr = net.IP{0xbe, 0xef, 0xbe, 0xef, 0xbe, 0xef, 0xbe, 0xef, 0xaa, 0xaa, 0xaa, 0xaa, 0x11, 0x11, 0x11, 0x12}
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
	_, ipv4range, err := net.ParseCIDR("10.1.2.0/16")
	c.Assert(err, IsNil)
	tempLibDir, err := ioutil.TempDir("", "cilium-test")
	c.Assert(err, IsNil)
	tempRunDir, err := ioutil.TempDir("", "cilium-test-run")
	c.Assert(err, IsNil)
	err = os.Mkdir(filepath.Join(tempRunDir, "globals"), 0777)
	c.Assert(err, IsNil)

	daemonConf := cnd.NewConfig()
	daemonConf.LibDir = tempLibDir
	daemonConf.RunDir = tempRunDir
	daemonConf.DryMode = true
	daemonConf.LXCMap = nil
	daemonConf.NodeAddress = EpAddr
	daemonConf.ConsulConfig = consulAPI.DefaultConfig()
	daemonConf.DockerEndpoint = "tcp://127.0.0.1"
	daemonConf.K8sEndpoint = "tcp://127.0.0.1"
	daemonConf.ValidLabelPrefixes = nil
	daemonConf.IPv4Range = ipv4range
	daemonConf.Opts.Set(types.OptionDropNotify, true)
	daemonConf.Device = "undefined"

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

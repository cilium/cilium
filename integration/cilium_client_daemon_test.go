package integration

import (
	"net"
	"os"
	"path/filepath"
	"testing"

	cnd "github.com/noironetworks/cilium-net/cilium-net-daemon/daemon"
	cns "github.com/noironetworks/cilium-net/cilium-net-daemon/server"
	"github.com/noironetworks/cilium-net/common/backend"
	cnc "github.com/noironetworks/cilium-net/common/client"

	consulAPI "github.com/noironetworks/cilium-net/Godeps/_workspace/src/github.com/hashicorp/consul/api"
	. "github.com/noironetworks/cilium-net/Godeps/_workspace/src/gopkg.in/check.v1"
)

var (
	EpAddr = net.IP{0xbe, 0xef, 0xbe, 0xef, 0xbe, 0xef, 0xbe, 0xef, 0xaa, 0xaa, 0xaa, 0xaa, 0x11, 0x11, 0x11, 0x12}
)

func Test(t *testing.T) { TestingT(t) }

type CiliumClientSuite struct {
	cli    backend.CiliumBackend
	server *cns.Server
}

var _ = Suite(&CiliumClientSuite{})

func (s *CiliumClientSuite) SetUpSuite(c *C) {
	socketDir := os.Getenv("SOCKET_DIR")
	socketPath := filepath.Join(socketDir, "cilium.sock")

	daemonConf := cnd.Config{
		LibDir:             "",
		LXCMap:             nil,
		NodeAddress:        EpAddr,
		ConsulConfig:       consulAPI.DefaultConfig(),
		DockerEndpoint:     "tcp://127.0.0.1",
		K8sEndpoint:        "tcp://127.0.0.1",
		ValidLabelPrefixes: nil,
	}

	d, err := cnd.NewDaemon(&daemonConf)
	if err != nil {
		c.Fatalf("Failed while creating new cilium-net test server: %+v", err)
	}
	server, err := cns.NewServer(socketPath, d)
	if err != nil {
		c.Fatalf("Failed while creating new cilium-net test server: %+v", err)
	}

	cli, err := cnc.NewClient("unix://"+socketPath, nil, nil, nil)
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
	str, err := s.cli.Ping()
	c.Assert(err, Equals, nil, Commentf("Error while Pinging server: %s", err))
	c.Assert(str, Equals, "Pong")
}

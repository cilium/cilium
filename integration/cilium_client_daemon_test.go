package integration

import (
	"os"
	"path/filepath"
	"testing"

	cnd "github.com/noironetworks/cilium-net/cilium-net-daemon/daemon"
	cnc "github.com/noironetworks/cilium-net/common/cilium-net-client"

	. "github.com/noironetworks/cilium-net/Godeps/_workspace/src/gopkg.in/check.v1"
)

func Test(t *testing.T) { TestingT(t) }

type CiliumClientSuite struct {
	cli    *cnc.Client
	daemon *cnd.Daemon
}

var _ = Suite(&CiliumClientSuite{})

func (s *CiliumClientSuite) SetUpSuite(c *C) {
	socketDir := os.Getenv("SOCKET_DIR")
	socketPath := filepath.Join(socketDir, "cilium.sock")

	daemon, err := cnd.NewDaemon(socketPath)
	if err != nil {
		c.Fatalf("Failed while creating new test daemon: %+v", err)
	}

	cli, err := cnc.NewClient("unix://"+socketPath, nil, nil)
	if err != nil {
		c.Fatalf("Failed while creating new client: %+v", err)
	}
	s.cli = cli
	s.daemon = daemon

	go func() {
		if err := s.daemon.Start(); err != nil {
			c.Fatalf("Error while starting cilium-net daemon %s", err)
			s.daemon.Stop()
		}
	}()
}

func (s *CiliumClientSuite) TearDownSuite(c *C) {
	socketDir := os.Getenv("SOCKET_DIR")
	socketPath := filepath.Join(socketDir, "cilium.sock")
	defer func() {
		if err := os.RemoveAll(socketPath); err != nil {
			c.Errorf("Failed while removing daemon socket: %s", err)
		}
	}()

	if err := s.daemon.Stop(); err != nil {
		c.Fatalf("Error while starting cilium-net daemon %s", err)
	}
}

func (s *CiliumClientSuite) TestGetPing(c *C) {
	err := s.cli.Ping()
	c.Assert(err, Equals, nil, Commentf("Error while Pinging daemon: %s", err))
}

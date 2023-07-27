package responder

import (
	"testing"

	. "github.com/cilium/checkmate"
)

type ResponderTestSuite struct{}

var _ = Suite(&ResponderTestSuite{})

func Test(t *testing.T) {
	TestingT(t)
}

func (r *ResponderTestSuite) TestNewServer(c *C) {
	tests := []struct {
		name           string
		address        []string
		expectedServer int
	}{
		{
			name:           "Initialize http server listening on all ports",
			address:        []string{""},
			expectedServer: 1,
		},
		{
			name:           "Initialize http server listening on ipv4 address",
			address:        []string{"192.168.1.4"},
			expectedServer: 1,
		},
		{
			name:           "Initialize http server listening on ipv4 and ipv6 address",
			address:        []string{"[fc00:c111::2]", "192.168.1.4"},
			expectedServer: 2,
		},
		{
			name:           "Pass invalid input as nil to address",
			address:        nil,
			expectedServer: 1,
		},
	}

	for _, tt := range tests {
		c.Log("Test :", tt.name)
		s := NewServer(tt.address, 4240)
		c.Assert(s, NotNil)
		c.Assert(len(s.httpServer), Equals, tt.expectedServer)
	}
}

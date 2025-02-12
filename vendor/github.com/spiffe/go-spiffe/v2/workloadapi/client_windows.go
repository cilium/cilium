//go:build windows
// +build windows

package workloadapi

import (
	"errors"
	"path/filepath"
	"strings"

	"github.com/Microsoft/go-winio"
	"google.golang.org/grpc"
)

// appendDialOptionsOS appends OS specific dial options
func (c *Client) appendDialOptionsOS() {
	if c.config.namedPipeName != "" {
		// Use the dialer to connect to named pipes only if a named pipe
		// is defined (i.e. WithNamedPipeName is used).
		c.config.dialOptions = append(c.config.dialOptions, grpc.WithContextDialer(winio.DialPipeContext))
	}
}

func (c *Client) setAddress() error {
	var err error
	if c.config.namedPipeName != "" {
		if c.config.address != "" {
			return errors.New("only one of WithAddr or WithNamedPipeName options can be used, not both")
		}
		c.config.address = namedPipeTarget(c.config.namedPipeName)
		return nil
	}

	if c.config.address == "" {
		var ok bool
		c.config.address, ok = GetDefaultAddress()
		if !ok {
			return errors.New("workload endpoint socket address is not configured")
		}
	}

	if strings.HasPrefix(c.config.address, "npipe:") {
		// Use the dialer to connect to named pipes only if the gRPC target
		// string has the "npipe" scheme
		c.config.dialOptions = append(c.config.dialOptions, grpc.WithContextDialer(winio.DialPipeContext))
	}

	c.config.address, err = TargetFromAddress(c.config.address)
	return err
}

// namedPipeTarget returns a target string suitable for
// dialing the endpoint address based on the provided
// pipe name.
func namedPipeTarget(pipeName string) string {
	return `\\.\` + filepath.Join("pipe", pipeName)
}

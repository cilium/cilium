package external

import (
	"fmt"
	"net"
	"net/url"

	"github.com/aws/aws-sdk-go-v2/aws"
)

var lookupHostFn = net.LookupHost

func isLoopbackHost(host string) (bool, error) {
	ip := net.ParseIP(host)
	if ip != nil {
		return ip.IsLoopback(), nil
	}

	// Host is not an ip, perform lookup
	addrs, err := lookupHostFn(host)
	if err != nil {
		return false, err
	}
	for _, addr := range addrs {
		if !net.ParseIP(addr).IsLoopback() {
			return false, nil
		}
	}

	return true, nil
}

func validateLocalURL(v string) error {
	u, err := url.Parse(v)
	if err != nil {
		return err
	}

	host := aws.URLHostname(u)
	if len(host) == 0 {
		return fmt.Errorf("unable to parse host from local HTTP cred provider URL")
	} else if isLoopback, err := isLoopbackHost(host); err != nil {
		return fmt.Errorf("failed to resolve host %q, %v", host, err)
	} else if !isLoopback {
		return fmt.Errorf("invalid endpoint host, %q, only host resolving to loopback addresses are allowed", host)
	}

	return nil
}

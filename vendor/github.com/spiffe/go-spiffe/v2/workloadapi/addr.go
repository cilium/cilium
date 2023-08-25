package workloadapi

import (
	"errors"
	"net"
	"net/url"
	"os"
)

const (
	// SocketEnv is the environment variable holding the default Workload API
	// address.
	SocketEnv = "SPIFFE_ENDPOINT_SOCKET"
)

func GetDefaultAddress() (string, bool) {
	return os.LookupEnv(SocketEnv)
}

// ValidateAddress validates that the provided address
// can be parsed to a gRPC target string for dialing
// a Workload API endpoint exposed as either a Unix
// Domain Socket or TCP socket.
func ValidateAddress(addr string) error {
	_, err := parseTargetFromStringAddr(addr)
	return err
}

// parseTargetFromStringAddr parses the endpoint address and returns a gRPC target
// string for dialing.
func parseTargetFromStringAddr(addr string) (string, error) {
	u, err := url.Parse(addr)
	if err != nil {
		return "", errors.New("workload endpoint socket is not a valid URI: " + err.Error())
	}
	return parseTargetFromURLAddr(u)
}

func parseTargetFromURLAddr(u *url.URL) (string, error) {
	if u.Scheme == "tcp" {
		switch {
		case u.Opaque != "":
			return "", errors.New("workload endpoint tcp socket URI must not be opaque")
		case u.User != nil:
			return "", errors.New("workload endpoint tcp socket URI must not include user info")
		case u.Host == "":
			return "", errors.New("workload endpoint tcp socket URI must include a host")
		case u.Path != "":
			return "", errors.New("workload endpoint tcp socket URI must not include a path")
		case u.RawQuery != "":
			return "", errors.New("workload endpoint tcp socket URI must not include query values")
		case u.Fragment != "":
			return "", errors.New("workload endpoint tcp socket URI must not include a fragment")
		}

		ip := net.ParseIP(u.Hostname())
		if ip == nil {
			return "", errors.New("workload endpoint tcp socket URI host component must be an IP:port")
		}
		port := u.Port()
		if port == "" {
			return "", errors.New("workload endpoint tcp socket URI host component must include a port")
		}

		return net.JoinHostPort(ip.String(), port), nil
	}

	return parseTargetFromURLAddrOS(u)
}

//go:build !windows
// +build !windows

package workloadapi

import (
	"errors"
	"net/url"
)

var (
	ErrInvalidEndpointScheme = errors.New("workload endpoint socket URI must have a \"tcp\" or \"unix\" scheme")
)

func parseTargetFromURLAddrOS(u *url.URL) (string, error) {
	switch u.Scheme {
	case "unix":
		switch {
		case u.Opaque != "":
			return "", errors.New("workload endpoint unix socket URI must not be opaque")
		case u.User != nil:
			return "", errors.New("workload endpoint unix socket URI must not include user info")
		case u.Host == "" && u.Path == "":
			return "", errors.New("workload endpoint unix socket URI must include a path")
		case u.RawQuery != "":
			return "", errors.New("workload endpoint unix socket URI must not include query values")
		case u.Fragment != "":
			return "", errors.New("workload endpoint unix socket URI must not include a fragment")
		}
		return u.String(), nil
	default:
		return "", ErrInvalidEndpointScheme
	}
}

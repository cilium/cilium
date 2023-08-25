//go:build windows
// +build windows

package workloadapi

import (
	"errors"
	"net/url"
)

var (
	ErrInvalidEndpointScheme = errors.New("workload endpoint socket URI must have a \"tcp\" or \"npipe\" scheme")
)

func parseTargetFromURLAddrOS(u *url.URL) (string, error) {
	switch u.Scheme {
	case "npipe":
		switch {
		case u.Opaque == "" && u.Host != "":
			return "", errors.New("workload endpoint named pipe URI must be opaque")
		case u.Opaque == "":
			return "", errors.New("workload endpoint named pipe URI must include an opaque part")
		case u.RawQuery != "":
			return "", errors.New("workload endpoint named pipe URI must not include query values")
		case u.Fragment != "":
			return "", errors.New("workload endpoint named pipe URI must not include a fragment")
		}

		return namedPipeTarget(u.Opaque), nil
	default:
		return "", ErrInvalidEndpointScheme
	}
}

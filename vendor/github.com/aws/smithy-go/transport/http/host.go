package http

import (
	"fmt"
	"strings"
)

// ValidateEndpointHost validates that the host string passed in is a valid RFC
// 3986 host. Returns error if the host is not valid.
func ValidateEndpointHost(host string) error {
	var errors strings.Builder
	labels := strings.Split(host, ".")

	for i, label := range labels {
		if i == len(labels)-1 && len(label) == 0 {
			// Allow trailing dot for FQDN hosts.
			continue
		}

		if !ValidHostLabel(label) {
			errors.WriteString("\nendpoint host domain labels must match \"[a-zA-Z0-9-]{1,63}\", but found: ")
			errors.WriteString(label)
		}
	}

	if len(host) > 255 {
		errors.WriteString(fmt.Sprintf("\nendpoint host must be less than 255 characters, but was %d", len(host)))
	}

	if len(errors.String()) > 0 {
		return fmt.Errorf("invalid endpoint host%s", errors.String())
	}
	return nil
}

// ValidHostLabel returns if the label is a valid RFC 3986 host label.
func ValidHostLabel(label string) bool {
	if l := len(label); l == 0 || l > 63 {
		return false
	}
	for _, r := range label {
		switch {
		case r >= '0' && r <= '9':
		case r >= 'A' && r <= 'Z':
		case r >= 'a' && r <= 'z':
		case r == '-':
		default:
			return false
		}
	}

	return true
}

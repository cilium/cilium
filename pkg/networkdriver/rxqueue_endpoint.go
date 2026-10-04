// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package networkdriver

import (
	"fmt"
	"strconv"
	"strings"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/util/validation"

	"github.com/cilium/cilium/pkg/networkdriver/types"
)

type portReference struct {
	number uint16
	name   string
}

func validateRXQueueConfig(config *types.RXQueueConfig) error {
	if config == nil {
		return fmt.Errorf("%w: RX queue endpoint is required", errUnexpectedInput)
	}

	switch {
	case config.PodEndpoint == nil && config.ServiceEndpoint == nil:
		return fmt.Errorf("%w: exactly one of podEndpoint or serviceEndpoint is required", errUnexpectedInput)
	case config.PodEndpoint != nil && config.ServiceEndpoint != nil:
		return fmt.Errorf("%w: podEndpoint and serviceEndpoint are mutually exclusive", errUnexpectedInput)
	case config.PodEndpoint != nil:
		if _, err := parsePortReference(config.PodEndpoint.Port); err != nil {
			return fmt.Errorf("%w: invalid podEndpoint port: %w", errUnexpectedInput, err)
		}
		if err := validateRXQueueProtocol(config.PodEndpoint.Protocol); err != nil {
			return fmt.Errorf("%w: invalid podEndpoint protocol: %w", errUnexpectedInput, err)
		}
	case config.ServiceEndpoint.ServiceName == "":
		return fmt.Errorf("%w: serviceEndpoint serviceName is required", errUnexpectedInput)
	default:
		if _, err := parsePortReference(config.ServiceEndpoint.Port); err != nil {
			return fmt.Errorf("%w: invalid serviceEndpoint port: %w", errUnexpectedInput, err)
		}
	}

	return nil
}

func validateRXQueueProtocol(protocol corev1.Protocol) error {
	switch protocol {
	case corev1.ProtocolTCP, corev1.ProtocolUDP:
		return nil
	default:
		return fmt.Errorf("protocol must be TCP or UDP, got %q", protocol)
	}
}

func parsePortReference(value string) (portReference, error) {
	if value == "" {
		return portReference{}, fmt.Errorf("port is required")
	}

	if strings.IndexFunc(value, func(r rune) bool { return r < '0' || r > '9' }) == -1 {
		port, err := strconv.ParseUint(value, 10, 16)
		if err != nil || port == 0 {
			return portReference{}, fmt.Errorf("port number %q must be between 1 and 65535", value)
		}
		return portReference{number: uint16(port)}, nil
	}

	if errs := validation.IsValidPortName(value); len(errs) != 0 {
		return portReference{}, fmt.Errorf("invalid port name %q: %s", value, strings.Join(errs, "; "))
	}
	return portReference{name: value}, nil
}

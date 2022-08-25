// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package tests

import (
	"fmt"
	"net"

	"github.com/cilium/cilium-cli/connectivity/check"
)

type labelsContainer interface {
	HasLabel(key, value string) bool
}

type Option func(*labelsOption)

type labelsOption struct {
	sourceLabels      map[string]string
	destinationLabels map[string]string
}

func WithSourceLabelsOption(sourceLabels map[string]string) Option {
	return func(option *labelsOption) {
		option.sourceLabels = sourceLabels
	}
}

func WithDestinationLabelsOption(destinationLabels map[string]string) Option {
	return func(option *labelsOption) {
		option.destinationLabels = destinationLabels
	}
}

func hasAllLabels(labelsContainer labelsContainer, filters map[string]string) bool {
	for k, v := range filters {
		if !labelsContainer.HasLabel(k, v) {
			return false
		}
	}
	return true
}

func curl(peer check.TestPeer, opts ...string) []string {
	cmd := []string{"curl",
		"-w", "%{local_ip}:%{local_port} -> %{remote_ip}:%{remote_port} = %{response_code}",
		"--silent", "--fail", "--show-error",
		"--connect-timeout", "5",
		"--output", "/dev/null",
	}
	cmd = append(cmd, opts...)
	cmd = append(cmd, fmt.Sprintf("%s://%s%s",
		peer.Scheme(),
		net.JoinHostPort(peer.Address(), fmt.Sprint(peer.Port())),
		peer.Path()))
	return cmd
}

func ping(peer check.TestPeer) []string {
	return []string{"ping", "-w", "3", "-c", "1", peer.Address()}
}

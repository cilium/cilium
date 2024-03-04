// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package tests

import (
	check2 "github.com/cilium/cilium/cilium-cli/connectivity/check"
	"strconv"

	"github.com/cilium/cilium-cli/utils/features"
)

type labelsContainer interface {
	HasLabel(key, value string) bool
}

type Option func(*labelsOption)

type labelsOption struct {
	sourceLabels      map[string]string
	destinationLabels map[string]string
	method            string
	path              string
}

func WithMethod(method string) Option {
	return func(option *labelsOption) {
		option.method = method
	}
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

func WithPath(path string) Option {
	return func(option *labelsOption) {
		option.path = path
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

type retryCondition struct {
	podLabels map[string]string
	all       bool
	destPort  uint32
	destIP    string
}

// CurlOptions returns curl retry option or empty slice depending on retry conditions
func (rc *retryCondition) CurlOptions(peer check2.TestPeer, ipFam features.IPFamily, pod check2.Pod, params check2.Parameters) []string {
	if params.Retry == 0 {
		return []string{}
	}
	if !rc.all && rc.destIP == "" && rc.destPort == 0 {
		return []string{}
	}

	opts := []string{
		"--retry", strconv.FormatInt(int64(params.Retry), 10),
		"--retry-all-errors", // add --retry-all-errors to retry on all possible errors
	}

	if retryDelay := params.RetryDelay.Seconds(); retryDelay > 0.0 {
		opts = append(opts, "--retry-delay", strconv.FormatFloat(retryDelay, 'f', -1, 64))
	}

	if rc.all {
		return opts
	}
	if rc.destIP != "" && peer.Address(ipFam) != rc.destIP {
		return []string{}
	}
	if rc.destPort != 0 && peer.Port() != rc.destPort {
		return []string{}
	}
	for n, v := range rc.podLabels {
		if !pod.HasLabel(n, v) {
			return []string{}
		}
	}

	return opts
}

type RetryOption func(*retryCondition)

// WithRetryAll sets all condition, returns retry options in every case
func WithRetryAll() RetryOption {
	return func(rc *retryCondition) {
		rc.all = true
	}
}

// WithRetryDestIP sets ip address condition
func WithRetryDestIP(ip string) RetryOption {
	return func(rc *retryCondition) {
		rc.destIP = ip
	}
}

// WithRetryDestPort sets port condition
func WithRetryDestPort(port uint32) RetryOption {
	return func(rc *retryCondition) {
		rc.destPort = port
	}
}

// WithRetryPodLabel sets pod label condition
func WithRetryPodLabel(name, val string) RetryOption {
	return func(rc *retryCondition) {
		if rc.podLabels == nil {
			rc.podLabels = map[string]string{}
		}
		rc.podLabels[name] = val
	}
}

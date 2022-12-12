// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package tests

type labelsContainer interface {
	HasLabel(key, value string) bool
}

type Option func(*labelsOption)

type labelsOption struct {
	sourceLabels      map[string]string
	destinationLabels map[string]string
	method            string
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

func hasAllLabels(labelsContainer labelsContainer, filters map[string]string) bool {
	for k, v := range filters {
		if !labelsContainer.HasLabel(k, v) {
			return false
		}
	}
	return true
}

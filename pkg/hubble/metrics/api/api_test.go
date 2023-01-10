// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Hubble

package api

import (
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/assert"
)

func TestDefaultRegistry(t *testing.T) {
	prometheusRegistry := prometheus.NewPedanticRegistry()
	registry := DefaultRegistry()

	assert.NotNil(t, registry)

	registry.ConfigureHandlers(prometheusRegistry, Map{"drop": Options{}})
}

func TestParseMetricOptions(t *testing.T) {
	assert.EqualValues(t, ParseMetricList([]string{"a", "b"}), Map{"a": Options{}, "b": Options{}})
	assert.EqualValues(t, ParseMetricList([]string{"a:1;2", "b"}), Map{"a": Options{"1": "", "2": ""}, "b": Options{}})
	assert.EqualValues(t, ParseMetricList([]string{"a:1;2", "b:3;4"}), Map{"a": Options{"1": "", "2": ""}, "b": Options{"3": "", "4": ""}})
}

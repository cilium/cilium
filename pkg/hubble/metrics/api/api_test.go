// Copyright 2019 Authors of Hubble
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// +build !privileged_tests

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

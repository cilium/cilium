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

	pb "github.com/cilium/cilium/api/v1/flow"

	"github.com/stretchr/testify/assert"
)

func TestParseContextOptions(t *testing.T) {
	opts, err := ParseContextOptions(Options{"unknown": ""})
	assert.Nil(t, err)
	assert.NotNil(t, opts)

	opts, err = ParseContextOptions(Options{"sourceContext": "invalid"})
	assert.NotNil(t, err)
	assert.Nil(t, opts)

	opts, err = ParseContextOptions(Options{"destinationContext": "invalid"})
	assert.NotNil(t, err)
	assert.Nil(t, opts)

	opts, err = ParseContextOptions(Options{"sourceContext": "namespace"})
	assert.Nil(t, err)
	assert.EqualValues(t, opts.Status(), "source=namespace")
	assert.EqualValues(t, opts.GetLabelNames(), []string{"source"})

	opts, err = ParseContextOptions(Options{"sourceContext": "namespace", "destinationContext": "identity"})
	assert.Nil(t, err)
	assert.EqualValues(t, opts.Status(), "destination=identity,source=namespace")
	assert.EqualValues(t, opts.GetLabelNames(), []string{"source", "destination"})

	opts, err = ParseContextOptions(Options{"sourceContext": "identity", "destinationContext": "identity"})
	assert.Nil(t, err)
	assert.EqualValues(t, opts.Status(), "destination=identity,source=identity")
	assert.EqualValues(t, opts.GetLabelNames(), []string{"source", "destination"})

	opts, err = ParseContextOptions(Options{"sourceContext": "pod"})
	assert.Nil(t, err)
	assert.EqualValues(t, opts.Status(), "source=pod")
	assert.EqualValues(t, opts.GetLabelNames(), []string{"source"})
}

func TestParseGetLabelValues(t *testing.T) {
	opts, err := ParseContextOptions(Options{"sourceContext": "namespace"})
	assert.Nil(t, err)
	assert.EqualValues(t, opts.GetLabelValues(&pb.Flow{Source: &pb.Endpoint{Namespace: "foo"}}), []string{"foo"})

	opts, err = ParseContextOptions(Options{"destinationContext": "namespace"})
	assert.Nil(t, err)
	assert.EqualValues(t, opts.GetLabelValues(&pb.Flow{Destination: &pb.Endpoint{Namespace: "foo"}}), []string{"foo"})

	opts, err = ParseContextOptions(Options{"sourceContext": "namespace", "destinationContext": "identity"})
	assert.Nil(t, err)
	assert.EqualValues(t, opts.GetLabelValues(&pb.Flow{
		Source:      &pb.Endpoint{Namespace: "foo"},
		Destination: &pb.Endpoint{Labels: []string{"a", "b"}},
	}), []string{"foo", "a,b"})

	opts, err = ParseContextOptions(Options{"sourceContext": "pod"})
	assert.Nil(t, err)
	assert.EqualValues(t, opts.GetLabelValues(&pb.Flow{Source: &pb.Endpoint{Namespace: "foo", PodName: "foo"}}), []string{"foo/foo"})

	opts, err = ParseContextOptions(Options{"destinationContext": "pod"})
	assert.Nil(t, err)
	assert.EqualValues(t, opts.GetLabelValues(&pb.Flow{Destination: &pb.Endpoint{Namespace: "foo", PodName: "bar"}}), []string{"foo/bar"})

	opts, err = ParseContextOptions(Options{"sourceContext": "pod-short"})
	assert.Nil(t, err)
	assert.EqualValues(t, opts.GetLabelValues(&pb.Flow{Source: &pb.Endpoint{Namespace: "foo", PodName: "foo-123"}}), []string{"foo/foo"})

	opts, err = ParseContextOptions(Options{"destinationContext": "pod-short"})
	assert.Nil(t, err)
	assert.EqualValues(t, opts.GetLabelValues(&pb.Flow{Destination: &pb.Endpoint{Namespace: "foo", PodName: "bar-bar-123-123"}}), []string{"foo/bar-bar"})
}

func TestShortenPodName(t *testing.T) {
	assert.EqualValues(t, shortenPodName("pod-x-123-1123123"), "pod-x")
	assert.EqualValues(t, shortenPodName("pod-0000"), "pod")
	assert.EqualValues(t, shortenPodName("pod-pod-pod-1-1"), "pod-pod-pod")
}

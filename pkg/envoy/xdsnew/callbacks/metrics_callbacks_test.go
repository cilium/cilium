// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package xdsnew

import (
	"testing"

	discovery "github.com/envoyproxy/go-control-plane/envoy/service/discovery/v3"
	"github.com/stretchr/testify/assert"
	"google.golang.org/genproto/googleapis/rpc/status"
)

type fakeXDSMetrics struct {
	acks    map[string]int
	nacks   map[string]int
	cancels map[string]int
}

func newFakeXDSMetrics() *fakeXDSMetrics {
	return &fakeXDSMetrics{
		acks:    map[string]int{},
		nacks:   map[string]int{},
		cancels: map[string]int{},
	}
}

func (f *fakeXDSMetrics) IncreaseACK(typeURL string)    { f.acks[typeURL]++ }
func (f *fakeXDSMetrics) IncreaseNACK(typeURL string)   { f.nacks[typeURL]++ }
func (f *fakeXDSMetrics) IncreaseCancel(typeURL string) { f.cancels[typeURL]++ }

const testTypeURL = "type.googleapis.com/envoy.config.listener.v3.Listener"

func TestMetricsCallbacksCountsACKAndNACK(t *testing.T) {
	m := newFakeXDSMetrics()
	cb := MetricsCallbacks{Metrics: m}

	// The initial subscription carries no version and is not an acknowledgement.
	assert.NoError(t, cb.OnStreamRequest(1, &discovery.DiscoveryRequest{TypeUrl: testTypeURL}))
	assert.Empty(t, m.acks)
	assert.Empty(t, m.nacks)

	// A request with a version and no error detail acknowledges the last response.
	assert.NoError(t, cb.OnStreamRequest(1, &discovery.DiscoveryRequest{
		TypeUrl:     testTypeURL,
		VersionInfo: "1",
	}))
	assert.Equal(t, 1, m.acks[testTypeURL])
	assert.Equal(t, 0, m.nacks[testTypeURL])

	// A request with an error detail rejects it.
	assert.NoError(t, cb.OnStreamRequest(1, &discovery.DiscoveryRequest{
		TypeUrl:     testTypeURL,
		VersionInfo: "2",
		ErrorDetail: &status.Status{Message: "rejected"},
	}))
	assert.Equal(t, 1, m.acks[testTypeURL])
	assert.Equal(t, 1, m.nacks[testTypeURL])
}

func TestMetricsCallbacksNilMetrics(t *testing.T) {
	cb := MetricsCallbacks{}
	assert.NoError(t, cb.OnStreamRequest(1, &discovery.DiscoveryRequest{
		TypeUrl:     testTypeURL,
		VersionInfo: "1",
	}))
}

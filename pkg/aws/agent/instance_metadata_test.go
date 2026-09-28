// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package agent

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	awsMetadata "github.com/cilium/cilium/pkg/aws/metadata"
)

// stubMetadata counts the fetches of a metadataClient and can be told to fail
// them.
type stubMetadata struct {
	info     awsMetadata.MetaDataInfo
	err      error
	fetches  atomic.Int32
	newCalls atomic.Int32
}

func (s *stubMetadata) GetInstanceMetadata(context.Context) (awsMetadata.MetaDataInfo, error) {
	s.fetches.Add(1)
	return s.info, s.err
}

func (s *stubMetadata) instanceMetadata() *instanceMetadata {
	return &instanceMetadata{newFn: func(context.Context) (metadataClient, error) {
		s.newCalls.Add(1)
		return s, nil
	}}
}

func TestInstanceMetadataFetchesOnce(t *testing.T) {
	stub := &stubMetadata{info: awsMetadata.MetaDataInfo{InstanceID: "i-instance"}}
	m := stub.instanceMetadata()

	var wg sync.WaitGroup
	for range 10 {
		wg.Go(func() {
			info, err := m.get(context.Background())
			assert.NoError(t, err)
			assert.Equal(t, "i-instance", info.InstanceID)
		})
	}
	wg.Wait()

	require.Equal(t, int32(1), stub.fetches.Load())
	require.Equal(t, int32(1), stub.newCalls.Load())
}

// TestInstanceMetadataRetriesFailures asserts that a failed fetch is not cached,
// so that the CiliumNode update retried by pkg/nodediscovery can succeed, and
// that the retry reuses the IMDS client.
func TestInstanceMetadataRetriesFailures(t *testing.T) {
	tests := map[string]struct {
		info awsMetadata.MetaDataInfo
		err  error
	}{
		"fetch error":       {err: errors.New("i/o timeout")},
		"empty instance ID": {info: awsMetadata.MetaDataInfo{}},
	}

	for name, failure := range tests {
		t.Run(name, func(t *testing.T) {
			stub := &stubMetadata{info: failure.info, err: failure.err}
			m := stub.instanceMetadata()

			_, err := m.get(context.Background())
			require.Error(t, err)

			stub.info, stub.err = awsMetadata.MetaDataInfo{InstanceID: "i-instance"}, nil
			info, err := m.get(context.Background())
			require.NoError(t, err)
			require.Equal(t, "i-instance", info.InstanceID)

			require.Equal(t, int32(2), stub.fetches.Load())
			require.Equal(t, int32(1), stub.newCalls.Load())
		})
	}
}

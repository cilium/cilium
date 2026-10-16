// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ipamapi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-openapi/runtime"
	"github.com/go-openapi/swag"
	"github.com/stretchr/testify/require"

	ipamapi "github.com/cilium/cilium/api/v1/server/restapi/ipam"
	"github.com/cilium/cilium/pkg/ipam"
	"github.com/cilium/cilium/pkg/ipam/metadata"
	ipamOption "github.com/cilium/cilium/pkg/ipam/option"
	"github.com/cilium/cilium/pkg/ipam/service/ipallocator"
	"github.com/cilium/cilium/pkg/logging/logfields"
	fakenode "github.com/cilium/cilium/pkg/node/fake"
	"github.com/cilium/cilium/pkg/option"
)

type failingMetadata struct {
	err error
}

func (m failingMetadata) GetIPPoolForPod(string, ipam.Family) (string, error) {
	return "", m.err
}

func newTestHandler(t *testing.T, metadataErr error) (*IpamPostIpamHandler, *bytes.Buffer) {
	var logs bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	config := &option.DaemonConfig{EnableIPv4: true, IPAM: ipamOption.IPAMClusterPool}
	allocator := ipam.NewIPAM(ipam.NewIPAMParams{
		Logger:         logger,
		NodeAddressing: fakenode.NewAddressing(),
		AgentConfig:    config,
		Metadata:       failingMetadata{err: metadataErr},
	})
	require.NoError(t, allocator.ConfigureAllocator(context.Background()))
	return &IpamPostIpamHandler{Logger: logger, IPAM: allocator, DaemonConfig: config}, &logs
}

func handleAllocation(t *testing.T, handler *IpamPostIpamHandler, logs *bytes.Buffer, pool *string, wantErr error) map[string]any {
	logs.Reset()
	response := handler.Handle(ipamapi.PostIpamParams{
		HTTPRequest: httptest.NewRequest(http.MethodPost, "/ipam", nil),
		Family:      swag.String("IPv4"),
		Owner:       swag.String("default/pod"),
		Pool:        pool,
	})
	recorder := httptest.NewRecorder()
	response.WriteResponse(recorder, runtime.JSONProducer())
	require.Equal(t, http.StatusBadGateway, recorder.Code)
	var responseError string
	require.NoError(t, json.Unmarshal(recorder.Body.Bytes(), &responseError))
	require.Contains(t, responseError, wantErr.Error())

	var record map[string]any
	require.NoError(t, json.Unmarshal(logs.Bytes(), &record))
	require.Equal(t, "Failed to allocate IP", record["msg"])
	require.Equal(t, "ipv4", record[logfields.Family])
	require.Equal(t, "default/pod", record[logfields.Owner])
	require.Contains(t, record[logfields.Error], wantErr.Error())
	return record
}

func TestIpamPostIpamHandlerAllocationErrorLogs(t *testing.T) {
	for _, tt := range []struct {
		name  string
		err   error
		level string
	}{
		{"pools not synced", metadata.ErrManagerPoolsNotSynced, "DEBUG"},
		{"pod not found", &metadata.ResourceNotFound{Resource: "Pod", Namespace: "default", Name: "pod"}, "DEBUG"},
		{"namespace not found", &metadata.ResourceNotFound{Resource: "Namespace", Name: "default"}, "DEBUG"},
		{"pool not ready", &ipam.ErrPoolNotReadyYet{}, "DEBUG"},
		{"node CIDRs exhausted", ipam.ErrAllCIDRsExhausted, "DEBUG"},
		{"wrapped cloud exhaustion", fmt.Errorf("%w: allocation will be retried once Cilium Operator allocates more IPs", ipam.ErrAllCIDRsExhausted), "DEBUG"},
		{"pool table not synced", &ipam.ErrPoolNotFound{Pool: "blue"}, "DEBUG"},
		{"pool missing after sync", &ipam.ErrPoolNotFound{Pool: "blue", Synced: true}, "WARN"},
		{"wrapped expected error", fmt.Errorf("allocation: %w", metadata.ErrManagerPoolsNotSynced), "DEBUG"},
		{"unknown error", errors.New("allocation failed"), "WARN"},
		{"metadata manager stopped", &metadata.ManagerStoppedError{}, "WARN"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			handler, logs := newTestHandler(t, tt.err)
			record := handleAllocation(t, handler, logs, nil, tt.err)
			require.Equal(t, tt.level, record["level"])
			require.NotContains(t, record, logfields.PoolName)
		})
	}
}

func TestIpamPostIpamHandlerPoolFullLogs(t *testing.T) {
	handler, logs := newTestHandler(t, nil)
	for {
		_, err := handler.IPAM.AllocateNextFamily(ipam.IPv4, "fill", ipam.PoolDefault())
		if err != nil {
			require.ErrorIs(t, err, ipallocator.ErrFull)
			break
		}
	}
	record := handleAllocation(t, handler, logs, swag.String(ipam.PoolDefault().String()), ipallocator.ErrFull)
	require.Equal(t, "WARN", record["level"])
	require.Equal(t, ipam.PoolDefault().String(), record[logfields.PoolName])
}

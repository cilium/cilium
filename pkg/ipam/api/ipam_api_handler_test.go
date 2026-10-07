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

func TestIpamPostIpamHandlerAllocationErrorLogs(t *testing.T) {
	joined := errors.Join(metadata.ErrManagerPoolsNotSynced, errors.New("rollback failed"))
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
		{"Alibaba pool depleted", &ipam.ErrNoAvailableIPs{IPAMMode: ipamOption.IPAMAlibabaCloud}, "DEBUG"},
		{"manual CRD pool exhausted", &ipam.ErrNoAvailableIPs{IPAMMode: ipamOption.IPAMCRD}, "WARN"},
		{"unknown mode depleted", &ipam.ErrNoAvailableIPs{IPAMMode: "unknown"}, "WARN"},
		{"unknown metadata resource", &metadata.ResourceNotFound{Resource: "Other"}, "WARN"},
		{"wrapped expected error", fmt.Errorf("allocation: %w", metadata.ErrManagerPoolsNotSynced), "DEBUG"},
		{"unknown error", errors.New("allocation failed"), "WARN"},
		{"exhausted pool", ipallocator.ErrFull, "WARN"},
		{"metadata manager stopped", &metadata.ManagerStoppedError{}, "WARN"},
		{"expected error with rollback failure", joined, "WARN"},
		{"wrapped expected error with rollback failure", fmt.Errorf("allocation: %w", joined), "WARN"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			var logs bytes.Buffer
			logger := slog.New(slog.NewJSONHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
			config := &option.DaemonConfig{EnableIPv4: true, IPAM: ipamOption.IPAMClusterPool}
			allocator := ipam.NewIPAM(ipam.NewIPAMParams{
				Logger:         logger,
				NodeAddressing: fakenode.NewAddressing(),
				AgentConfig:    config,
				Metadata:       failingMetadata{err: tt.err},
			})
			require.NoError(t, allocator.ConfigureAllocator(context.Background()))
			handler := &IpamPostIpamHandler{Logger: logger, IPAM: allocator, DaemonConfig: config}
			params := ipamapi.PostIpamParams{
				HTTPRequest: httptest.NewRequest(http.MethodPost, "/ipam", nil),
				Family:      swag.String("IPv4"),
				Owner:       swag.String("default/pod"),
			}
			if errors.Is(tt.err, ipallocator.ErrFull) {
				for {
					_, err := allocator.AllocateNextFamily(ipam.IPv4, "fill", ipam.PoolDefault())
					if err != nil {
						require.ErrorIs(t, err, ipallocator.ErrFull)
						break
					}
				}
				params.Pool = swag.String(ipam.PoolDefault().String())
			}
			logs.Reset()
			response := handler.Handle(params)
			recorder := httptest.NewRecorder()
			response.WriteResponse(recorder, runtime.JSONProducer())
			require.Equal(t, http.StatusBadGateway, recorder.Code)
			var responseError string
			require.NoError(t, json.Unmarshal(recorder.Body.Bytes(), &responseError))
			require.Contains(t, responseError, tt.err.Error())

			var record map[string]any
			require.NoError(t, json.Unmarshal(logs.Bytes(), &record))
			require.Equal(t, tt.level, record["level"])
			require.Equal(t, "Failed to allocate IP", record["msg"])
			require.Equal(t, "ipv4", record[logfields.Family])
			require.Equal(t, "default/pod", record[logfields.Owner])
			require.Equal(t, swag.StringValue(params.Pool), record[logfields.PoolName])
			require.Contains(t, record[logfields.Error], tt.err.Error())
		})
	}
}

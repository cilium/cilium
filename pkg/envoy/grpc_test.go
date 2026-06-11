// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package envoy

import (
	"context"
	"errors"
	"fmt"
	"io"
	"testing"
	"time"

	"github.com/cilium/hive/hivetest"
	envoy_config_core "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	envoy_config_tls "github.com/envoyproxy/go-control-plane/envoy/extensions/transport_sockets/tls/v3"
	envoy_service_discovery "github.com/envoyproxy/go-control-plane/envoy/service/discovery/v3"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/metadata"
	"google.golang.org/protobuf/proto"

	"github.com/cilium/cilium/pkg/envoy/xds"
)

type secretDeltaStream struct {
	ctx     context.Context
	recv    chan *envoy_service_discovery.DeltaDiscoveryRequest
	sent    chan *envoy_service_discovery.DeltaDiscoveryResponse
	timeout time.Duration
}

func newSecretDeltaStream(ctx context.Context) *secretDeltaStream {
	return &secretDeltaStream{
		ctx:     ctx,
		recv:    make(chan *envoy_service_discovery.DeltaDiscoveryRequest, 10),
		sent:    make(chan *envoy_service_discovery.DeltaDiscoveryResponse, 10),
		timeout: time.Second,
	}
}

func (s *secretDeltaStream) SetHeader(metadata.MD) error  { return nil }
func (s *secretDeltaStream) SendHeader(metadata.MD) error { return nil }
func (s *secretDeltaStream) SetTrailer(metadata.MD)       {}
func (s *secretDeltaStream) Context() context.Context     { return s.ctx }

func (s *secretDeltaStream) Send(resp *envoy_service_discovery.DeltaDiscoveryResponse) error {
	ctx, cancel := context.WithTimeout(s.ctx, s.timeout)
	defer cancel()

	select {
	case <-ctx.Done():
		if errors.Is(ctx.Err(), context.Canceled) {
			return io.EOF
		}
		return ctx.Err()
	case s.sent <- resp:
		return nil
	}
}

func (s *secretDeltaStream) Recv() (*envoy_service_discovery.DeltaDiscoveryRequest, error) {
	ctx, cancel := context.WithTimeout(s.ctx, s.timeout)
	defer cancel()

	select {
	case <-ctx.Done():
		if errors.Is(ctx.Err(), context.Canceled) {
			return nil, io.EOF
		}
		return nil, ctx.Err()
	case req := <-s.recv:
		if req == nil {
			return nil, io.EOF
		}
		return req, nil
	}
}

func (s *secretDeltaStream) SendMsg(msg any) error {
	resp, ok := msg.(*envoy_service_discovery.DeltaDiscoveryResponse)
	if !ok {
		return fmt.Errorf("unexpected response type %T", msg)
	}
	return s.Send(resp)
}

func (s *secretDeltaStream) RecvMsg(msg any) error {
	req, err := s.Recv()
	if err != nil {
		return err
	}
	dst, ok := msg.(*envoy_service_discovery.DeltaDiscoveryRequest)
	if !ok {
		return fmt.Errorf("unexpected request type %T", msg)
	}
	proto.Reset(dst)
	proto.Merge(dst, req)
	return nil
}

func (s *secretDeltaStream) SendRequest(req *envoy_service_discovery.DeltaDiscoveryRequest) error {
	ctx, cancel := context.WithTimeout(s.ctx, s.timeout)
	defer cancel()

	select {
	case <-ctx.Done():
		if errors.Is(ctx.Err(), context.Canceled) {
			return io.EOF
		}
		return ctx.Err()
	case s.recv <- req:
		return nil
	}
}

func (s *secretDeltaStream) RecvResponse() (*envoy_service_discovery.DeltaDiscoveryResponse, error) {
	ctx, cancel := context.WithTimeout(s.ctx, s.timeout)
	defer cancel()

	select {
	case <-ctx.Done():
		if errors.Is(ctx.Err(), context.Canceled) {
			return nil, io.EOF
		}
		return nil, ctx.Err()
	case resp := <-s.sent:
		return resp, nil
	}
}

func TestDeltaSecretsServesSecretUpdatesAndDeletes(t *testing.T) {
	logger := hivetest.Logger(t)
	cache := xds.NewCache(logger)
	_, updated, _ := cache.Upsert(SecretTypeURL, "secret-a", &envoy_config_tls.Secret{
		Name: "secret-a",
		Type: &envoy_config_tls.Secret_GenericSecret{
			GenericSecret: &envoy_config_tls.GenericSecret{
				Secret: &envoy_config_core.DataSource{
					Specifier: &envoy_config_core.DataSource_InlineString{
						InlineString: "token",
					},
				},
			},
		},
	})
	require.True(t, updated)

	server := &xdsGRPCServer{
		Server: xds.NewServer(logger, map[string]*xds.ResourceTypeConfiguration{
			SecretTypeURL: {
				Source: cache,
			},
		}, nil, xds.NewXDSMetric()),
	}

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	stream := newSecretDeltaStream(ctx)
	errCh := make(chan error, 1)
	go func() {
		errCh <- server.DeltaSecrets(stream)
	}()

	require.NoError(t, stream.SendRequest(&envoy_service_discovery.DeltaDiscoveryRequest{
		Node: &envoy_config_core.Node{
			Id: "host~127.0.0.1~no-id~localdomain",
		},
		TypeUrl:                SecretTypeURL,
		ResourceNamesSubscribe: []string{"secret-a"},
	}))

	resp, err := stream.RecvResponse()
	require.NoError(t, err)
	require.Equal(t, SecretTypeURL, resp.GetTypeUrl())
	require.Equal(t, "2", resp.GetNonce())
	require.Len(t, resp.GetResources(), 1)
	require.Equal(t, "secret-a", resp.GetResources()[0].GetName())
	require.Equal(t, "2", resp.GetResources()[0].GetVersion())
	require.Equal(t, SecretTypeURL, resp.GetResources()[0].GetResource().GetTypeUrl())
	require.Empty(t, resp.GetRemovedResources())

	require.NoError(t, stream.SendRequest(&envoy_service_discovery.DeltaDiscoveryRequest{
		TypeUrl:       SecretTypeURL,
		ResponseNonce: resp.GetNonce(),
	}))

	_, updated, _ = cache.Delete(SecretTypeURL, "secret-a")
	require.True(t, updated)

	resp, err = stream.RecvResponse()
	require.NoError(t, err)
	require.Equal(t, SecretTypeURL, resp.GetTypeUrl())
	require.Equal(t, "3", resp.GetNonce())
	require.Empty(t, resp.GetResources())
	require.Equal(t, []string{"secret-a"}, resp.GetRemovedResources())

	require.NoError(t, stream.SendRequest(&envoy_service_discovery.DeltaDiscoveryRequest{
		TypeUrl:       SecretTypeURL,
		ResponseNonce: resp.GetNonce(),
	}))
	require.NoError(t, stream.SendRequest(nil))

	select {
	case err := <-errCh:
		require.True(t, err == nil || errors.Is(err, io.EOF), "unexpected stream error: %v", err)
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for DeltaSecrets stream to exit")
	}
}

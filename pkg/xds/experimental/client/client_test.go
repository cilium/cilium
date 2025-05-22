// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package xdsclient

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"slices"
	"sort"
	"strings"
	"testing"
	"time"

	clusterpb "github.com/envoyproxy/go-control-plane/envoy/config/cluster/v3"
	corepb "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	endpointpb "github.com/envoyproxy/go-control-plane/envoy/config/endpoint/v3"
	listenerpb "github.com/envoyproxy/go-control-plane/envoy/config/listener/v3"
	routepb "github.com/envoyproxy/go-control-plane/envoy/config/route/v3"
	discoverypb "github.com/envoyproxy/go-control-plane/envoy/service/discovery/v3"
	"github.com/google/go-cmp/cmp"
	"go.uber.org/goleak"
	grpcStatus "google.golang.org/genproto/googleapis/rpc/status"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/types/known/anypb"
	durationpb "google.golang.org/protobuf/types/known/durationpb"

	"github.com/cilium/cilium/pkg/envoy"
	"github.com/cilium/cilium/pkg/envoy/xds"
)

const useSOTW = true

var sotw2str = map[bool]string{true: "sotw", false: "delta"}

func testNode() *corepb.Node {
	return new(corepb.Node)
}

func TestHandleResponse_StoresInCache(t *testing.T) {
	testCases := []struct {
		name             string
		initialListeners []*listenerpb.Listener
		finalListeners   []*listenerpb.Listener
		initialClusters  []*clusterpb.Cluster
		finalClusters    []*clusterpb.Cluster
		initialEndpoints []*endpointpb.ClusterLoadAssignment
		finalEndpoints   []*endpointpb.ClusterLoadAssignment
		initialRoutes    []*routepb.RouteConfiguration
		finalRoutes      []*routepb.RouteConfiguration
	}{
		{
			name: "One_Listener",
			finalListeners: []*listenerpb.Listener{
				{
					Name: "example listener",
				},
			},
		},
		{
			name: "Two_Listeners",
			finalListeners: []*listenerpb.Listener{
				{
					Name: "example listener 1",
				},
				{
					Name: "example listener 2",
				},
			},
		},
		{
			name: "Updated_Listener",
			initialListeners: []*listenerpb.Listener{
				{
					Name: "example listener",
				},
			},
			finalListeners: []*listenerpb.Listener{
				{
					Name: "example listener",
					Address: &corepb.Address{
						Address: &corepb.Address_SocketAddress{
							SocketAddress: &corepb.SocketAddress{
								Protocol: *corepb.SocketAddress_TCP.Enum(),
								Address:  "123.234.0.1",
							},
						},
					},
				},
			},
		},
		{
			name: "One_Cluster",
			finalClusters: []*clusterpb.Cluster{
				{
					Name: "example cluster",
				},
			},
		},
		{
			name: "Two_Clusters",
			finalClusters: []*clusterpb.Cluster{
				{
					Name: "example cluster 1",
				},
				{
					Name: "example cluster 2",
				},
			},
		},
		{
			name: "Updated_Cluster",
			initialClusters: []*clusterpb.Cluster{
				{
					Name: "example cluster",
				},
			},
			finalClusters: []*clusterpb.Cluster{
				{
					Name:           "example cluster",
					ConnectTimeout: durationpb.New(time.Second),
				},
			},
		},
		{
			name: "One_Endpoint",
			finalEndpoints: []*endpointpb.ClusterLoadAssignment{
				{
					ClusterName: "example endpoint",
				},
			},
		},
		{
			name: "Two_Endpoints",
			finalEndpoints: []*endpointpb.ClusterLoadAssignment{
				{
					ClusterName: "example endpoint 1",
				},
				{
					ClusterName: "example endpoint 2",
				},
			},
		},
		{
			name: "Updated_Endpoint",
			initialEndpoints: []*endpointpb.ClusterLoadAssignment{
				{
					ClusterName: "example endpoint",
				},
			},
			finalEndpoints: []*endpointpb.ClusterLoadAssignment{
				{
					ClusterName: "example endpoint",
					Policy: &endpointpb.ClusterLoadAssignment_Policy{
						EndpointStaleAfter: durationpb.New(time.Minute),
					},
				},
			},
		},
		{
			name: "One_Route",
			finalRoutes: []*routepb.RouteConfiguration{
				{Name: "example route"},
			},
		},
		{
			name: "Two_Routes",
			finalRoutes: []*routepb.RouteConfiguration{
				{Name: "example route 1"},
				{Name: "example route 2"},
			},
		},
		{
			name: "Updated_Route",
			initialRoutes: []*routepb.RouteConfiguration{
				{Name: "example route"},
			},
			finalRoutes: []*routepb.RouteConfiguration{
				{
					Name:                   "example route 1",
					RequestHeadersToRemove: []string{"X-Remove"},
				},
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			opts := Defaults
			c := NewClient(slog.Default(), useSOTW, &opts).(*XDSClient[*discoverypb.DiscoveryRequest, *discoverypb.DiscoveryResponse])
			c.node = testNode()
			resp := new(discoverypb.DiscoveryResponse)
			appendResource := func(src proto.Message) {
				res, err := anypb.New(src)
				if err != nil {
					t.Fatalf("unexpected marshal err: %v", err)
				}
				resp.Resources = append(resp.Resources, res)
			}
			for _, l := range append(tc.initialListeners, tc.finalListeners...) {
				appendResource(l)
				resp.TypeUrl = envoy.ListenerTypeURL
			}
			for _, c := range append(tc.initialClusters, tc.finalClusters...) {
				appendResource(c)
				resp.TypeUrl = envoy.ClusterTypeURL
			}
			for _, e := range append(tc.initialEndpoints, tc.finalEndpoints...) {
				appendResource(e)
				resp.TypeUrl = envoy.EndpointTypeURL
			}

			err := c.handleResponse(new(fakeStream), resp)
			if err != nil {
				t.Fatalf("unexpected handleResponse err: %v", err)
			}

			checkResource := func(typeUrl, resName string) protoreflect.ProtoMessage {
				verRes, err := c.cache.GetResources(typeUrl, 0, "", []string{resName})
				if err != nil {
					t.Fatalf("unexpected GetResources err: %v", err)
				}
				if len(verRes.Resources) != 1 {
					t.Fatalf("len(resources) = %d, want = %d", len(verRes.Resources), 1)
				}
				if len(verRes.ResourceNames) != 1 {
					t.Fatalf("len(resourceNames) = %d, want = %d", len(verRes.ResourceNames), 1)
				}
				if name := verRes.ResourceNames[0]; name != resName {
					t.Errorf("resourceName = %q, want = %q", name, resName)
				}
				return verRes.Resources[0]
			}

			for _, res := range tc.finalListeners {
				cacheRes := checkResource(envoy.ListenerTypeURL, res.Name)
				wantAddr := res.GetAddress().GetSocketAddress().String()
				gotAddr := cacheRes.(*listenerpb.Listener).GetAddress().GetSocketAddress().String()
				if gotAddr != wantAddr {
					t.Errorf("addr = %q, want = %q", gotAddr, wantAddr)
				}
			}

			for _, res := range tc.finalClusters {
				cacheRes := checkResource(envoy.ClusterTypeURL, res.Name)
				wantConnectTimeout := res.ConnectTimeout.String()
				gotConnectTimeout := cacheRes.(*clusterpb.Cluster).GetConnectTimeout().String()
				if gotConnectTimeout != wantConnectTimeout {
					t.Errorf("connectTimeout = %s, want = %s", gotConnectTimeout, wantConnectTimeout)
				}
			}

			for _, res := range tc.finalEndpoints {
				cacheRes := checkResource(envoy.EndpointTypeURL, res.ClusterName)
				wantPolicy := res.GetPolicy().String()
				gotPolicy := cacheRes.(*endpointpb.ClusterLoadAssignment).GetPolicy().String()
				if gotPolicy != wantPolicy {
					t.Errorf("policy = %s, want = %s", gotPolicy, wantPolicy)
				}
			}
		})
	}
}

func TestUpsertAndDeleteMissing_Listeners(t *testing.T) {
	testCases := []struct {
		name    string
		initial []*listenerpb.Listener
		updated []*listenerpb.Listener
	}{
		{
			name: "no_changes",
			initial: []*listenerpb.Listener{
				{Name: "example listener"},
			},
			updated: []*listenerpb.Listener{
				{Name: "example listener"},
			},
		},
		{
			name: "add_only",
			initial: []*listenerpb.Listener{
				{Name: "example listener"},
			},
			updated: []*listenerpb.Listener{
				{Name: "example listener"},
				{Name: "added listener"},
			},
		},
		{
			name: "remove_only",
			initial: []*listenerpb.Listener{
				{Name: "first listener"},
				{Name: "second listener"},
			},
			updated: []*listenerpb.Listener{
				{Name: "second listener"},
			},
		},
		{
			name: "add_and_remove",
			initial: []*listenerpb.Listener{
				{Name: "removed listener"},
				{Name: "same listener"},
			},
			updated: []*listenerpb.Listener{
				{Name: "same listener"},
				{Name: "added listener"},
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			opts := Defaults
			c := NewClient(slog.Default(), useSOTW, &opts).(*XDSClient[*discoverypb.DiscoveryRequest, *discoverypb.DiscoveryResponse])
			c.node = testNode()
			handleListenerResponse := func(listeners []*listenerpb.Listener) {
				resp := new(discoverypb.DiscoveryResponse)
				for _, l := range listeners {
					res, err := anypb.New(l)
					if err != nil {
						t.Fatalf("unexpected marshal err: %v", err)
					}
					resp.Resources = append(resp.Resources, res)
				}
				resp.TypeUrl = envoy.ListenerTypeURL

				err := c.handleResponse(new(fakeStream), resp)
				if err != nil {
					t.Fatalf("unexpected handleResponse err: %v", err)
				}
			}

			handleListenerResponse(tc.initial)
			handleListenerResponse(tc.updated)

			wantNames := make([]string, len(tc.updated))
			for i, l := range tc.updated {
				wantNames[i] = l.Name
			}

			verRes, err := c.cache.GetResources(envoy.ListenerTypeURL, 0, "", nil)
			if err != nil {
				t.Fatalf("unexpected GetResources err: %v", err)
			}
			sort.Strings(wantNames)
			sort.Strings(verRes.ResourceNames)
			if diff := cmp.Diff(wantNames, verRes.ResourceNames); diff != "" {
				t.Errorf("-got, +want: %s", diff)
			}
		})
	}
}

func TestUpsertAndDeleteMissing_Endpoints(t *testing.T) {
	testCases := []struct {
		name             string
		initialClusters  []*clusterpb.Cluster
		initialEndpoints []*endpointpb.ClusterLoadAssignment
		updatedClusters  []*clusterpb.Cluster
		updatedEndpoints []*endpointpb.ClusterLoadAssignment
		wantEndpoints    []string
	}{
		{
			name: "no_changes",
			initialClusters: []*clusterpb.Cluster{
				{Name: "example"},
			},
			initialEndpoints: []*endpointpb.ClusterLoadAssignment{
				{ClusterName: "example"},
			},
			updatedClusters: []*clusterpb.Cluster{
				{Name: "example"},
			},
			updatedEndpoints: []*endpointpb.ClusterLoadAssignment{
				{ClusterName: "example"},
			},
			wantEndpoints: []string{
				"example",
			},
		},
		{
			name: "missing_cluster_deletes_endpoint",
			initialClusters: []*clusterpb.Cluster{
				{Name: "present"},
				{Name: "missing"},
			},
			initialEndpoints: []*endpointpb.ClusterLoadAssignment{
				{ClusterName: "present"},
				{ClusterName: "missing"},
			},
			updatedClusters: []*clusterpb.Cluster{
				{Name: "present"},
			},
			wantEndpoints: []string{
				"present",
			},
		},
		{
			name: "missing_endpoint_has_no_effect",
			initialClusters: []*clusterpb.Cluster{
				{Name: "present"},
				{Name: "missing"},
			},
			initialEndpoints: []*endpointpb.ClusterLoadAssignment{
				{ClusterName: "present"},
				{ClusterName: "missing"},
			},
			updatedClusters: []*clusterpb.Cluster{
				{Name: "present"},
				{Name: "missing"},
			},
			updatedEndpoints: []*endpointpb.ClusterLoadAssignment{
				{ClusterName: "present"},
			},
			wantEndpoints: []string{
				"present",
				"missing",
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			opts := Defaults
			c := NewClient(slog.Default(), useSOTW, &opts).(*XDSClient[*discoverypb.DiscoveryRequest, *discoverypb.DiscoveryResponse])
			c.node = testNode()
			handleResponse := func(typeUrl string, clusters []*clusterpb.Cluster, endpoints []*endpointpb.ClusterLoadAssignment) {
				if clusters == nil && endpoints == nil {
					return
				}
				resp := new(discoverypb.DiscoveryResponse)
				for _, l := range clusters {
					res, err := anypb.New(l)
					if err != nil {
						t.Fatalf("unexpected marshal err: %v", err)
					}
					resp.Resources = append(resp.Resources, res)
				}
				for _, e := range endpoints {
					res, err := anypb.New(e)
					if err != nil {
						t.Fatalf("unexpected marshal err: %v", err)
					}
					resp.Resources = append(resp.Resources, res)
				}
				resp.TypeUrl = typeUrl

				err := c.handleResponse(new(fakeStream), resp)
				if err != nil {
					t.Fatalf("unexpected handleResponse err: %v", err)
				}
			}

			handleResponse(envoy.ClusterTypeURL, tc.initialClusters, nil)
			handleResponse(envoy.EndpointTypeURL, nil, tc.initialEndpoints)
			handleResponse(envoy.ClusterTypeURL, tc.updatedClusters, nil)
			handleResponse(envoy.EndpointTypeURL, nil, tc.updatedEndpoints)

			verRes, err := c.cache.GetResources(envoy.EndpointTypeURL, 0, "", nil)
			if err != nil {
				t.Fatalf("unexpected GetResources err: %v", err)
			}
			sort.Strings(tc.wantEndpoints)
			sort.Strings(verRes.ResourceNames)
			if diff := cmp.Diff(tc.wantEndpoints, verRes.ResourceNames); diff != "" {
				t.Errorf("+got, -want: %s", diff)
			}
		})
	}
}

func TestHandleResponse_RejectsMismatchedTypes(t *testing.T) {
	testCases := []struct {
		name            string
		res             *anypb.Any
		overrideResType string
		wantErr         string
	}{
		{
			name:            "unknown",
			res:             mustMarshalAny(&listenerpb.Listener{Name: "ok"}),
			overrideResType: "wrong-type-url",
			wantErr:         "mismatched typeUrls",
		},
		{
			name: "listener_ok",
			res:  mustMarshalAny(&listenerpb.Listener{Name: "ok"}),
		},
		{
			name:    "listener_missing_name",
			res:     mustMarshalAny(&listenerpb.Listener{StatPrefix: "stat_prefix"}),
			wantErr: "missing name for ",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			opts := Defaults
			c := NewClient(slog.Default(), useSOTW, &opts).(*XDSClient[*discoverypb.DiscoveryRequest, *discoverypb.DiscoveryResponse])
			c.node = testNode()
			resp := &discoverypb.DiscoveryResponse{
				Resources: []*anypb.Any{tc.res},
				TypeUrl:   envoy.ListenerTypeURL,
			}
			if tc.overrideResType != "" {
				resp.Resources[0].TypeUrl = tc.overrideResType
			}

			err := c.handleResponse(new(fakeStream), resp)
			if err != nil {
				if tc.wantErr == "" {
					t.Errorf("error occurred when none was expected")
				} else if gotErr := err.Error(); !strings.Contains(gotErr, tc.wantErr) {
					t.Errorf("error = %q, want = %q", gotErr, tc.wantErr)
				}
			} else if tc.wantErr != "" {
				t.Errorf("expected an error to occur, want = %s", tc.wantErr)
			}
		})
	}
}

func TestRunReturnsNonRetriableErrors(t *testing.T) {
	testCases := []struct {
		name    string
		sendErr error
		recvErr error
		wantErr string
		retries bool
	}{
		{
			name:    "Returns_Loop_EOF",
			sendErr: io.EOF,
			wantErr: "process loop: send: EOF",
		},
		{
			name:    "Returns_Loop_Aborted",
			sendErr: status.New(codes.Aborted, "").Err(),
			wantErr: "process loop: send: rpc error: code = Aborted",
		},
		{
			name:    "Returns_Recv_EOF",
			recvErr: io.EOF,
			wantErr: "process responses: recv: EOF",
		},
		{
			name:    "Returns_Recv_Aborted",
			recvErr: status.New(codes.Aborted, "").Err(),
			wantErr: "process responses: recv: rpc error: code = Aborted",
		},
		{
			name:    "Retries_Send_Unknown",
			sendErr: status.New(codes.Unknown, "").Err(),
			retries: true,
		},
		{
			name:    "Retries_Recv_Unknown",
			recvErr: status.New(codes.Unknown, "").Err(),
			retries: true,
		},
	}

	for sotw, name := range sotw2str {
		t.Run(name, func(t *testing.T) {
			for _, tc := range testCases {
				t.Run(tc.name, func(t *testing.T) {
					defer goleak.VerifyNone(t)

					opts := Defaults
					opts.RetryBackoff.Min = time.Microsecond
					opts.RetryBackoff.Max = time.Microsecond
					c := NewClient(slog.Default(), sotw, &opts)
					if sotw {
						c.(*XDSClient[*discoverypb.DiscoveryRequest, *discoverypb.DiscoveryResponse]).node = testNode()
					} else {
						c.(*XDSClient[*discoverypb.DeltaDiscoveryRequest, *discoverypb.DeltaDiscoveryResponse]).node = testNode()
					}
					ctx, cancel := context.WithCancel(context.TODO())

					f := newFakeClient()

					var gotErr error
					done := make(chan bool)
					go func() {
						defer close(done)
						defer cancel()
						if sotw {
							gotErr = c.(*XDSClient[*discoverypb.DiscoveryRequest, *discoverypb.DiscoveryResponse]).process(ctx, f)
						} else {
							gotErr = c.(*XDSClient[*discoverypb.DeltaDiscoveryRequest, *discoverypb.DeltaDiscoveryResponse]).process(ctx, f)
						}
					}()

					if tc.sendErr != nil {
						err := c.Observe(ctx, "", nil)
						if err != nil {
							t.Fatalf("unexpected observe err: %v", err)
						}
						f.sendErrCh <- tc.sendErr
					}
					if tc.recvErr != nil {
						f.recvCh <- tc.recvErr
					}
					if tc.retries {
						// Send non-retriable error to confirm
						if tc.sendErr != nil {
							if sotw {
								c.(*XDSClient[*discoverypb.DiscoveryRequest, *discoverypb.DiscoveryResponse]).observeQueue <- &observeRequest{}
							} else {
								c.(*XDSClient[*discoverypb.DeltaDiscoveryRequest, *discoverypb.DeltaDiscoveryResponse]).observeQueue <- &observeRequest{}
							}
							select {
							case f.sendErrCh <- io.EOF:
							case <-done:
								t.Fatalf("error was not retried")
							}
						}
						if tc.recvErr != nil {
							select {
							case f.recvCh <- io.EOF:
							case <-done:
								t.Fatalf("error was not retried")
							}
						}
					}

					select {
					case <-time.NewTimer(10 * time.Second).C:
						t.Fatalf("test timeout: expected error to occur")
					case <-done:
					}

					if tc.retries {
						if !strings.Contains(gotErr.Error(), "EOF") {
							t.Errorf("error = %v, want = %v (retry marker)", gotErr, io.EOF)
						}
					} else if !strings.Contains(gotErr.Error(), tc.wantErr) {
						t.Errorf("error = %v, want = %v", gotErr, tc.wantErr)
					}
				})
			}
		})
	}
}

func TestObserve(t *testing.T) {
	testCases := []struct {
		name              string
		resourceNames     []string
		currResourceNames []string
	}{
		{
			name: "empty_cache_empty_req",
		},
		{
			name:          "empty_cache_two_listeners_req",
			resourceNames: []string{"listener_one", "listener_two"},
		},
		{
			name:              "req_same_as_cache",
			resourceNames:     []string{"listener_one", "listener_two"},
			currResourceNames: []string{"listener_one", "listener_two"},
		},
		{
			name:              "new_listener",
			resourceNames:     []string{"listener_three"},
			currResourceNames: []string{"listener_one", "listener_two"},
		},
		{
			name:              "listener_already_in_cache",
			resourceNames:     []string{"listener_one"},
			currResourceNames: []string{"listener_one", "listener_two"},
		},
	}

	for sotw, name := range sotw2str {
		t.Run(name, func(t *testing.T) {
			for _, tc := range testCases {
				t.Run(tc.name, func(t *testing.T) {
					defer goleak.VerifyNone(t)

					opts := Defaults
					c := NewClient(slog.Default(), sotw, &opts)
					ctx, cancel := context.WithCancel(context.TODO())

					typeUrl := envoy.ListenerTypeURL
					var cache *xds.Cache
					if sotw {
						sotwCl := c.(*XDSClient[*discoverypb.DiscoveryRequest, *discoverypb.DiscoveryResponse])
						sotwCl.node = testNode()
						cache = sotwCl.cache
					} else {
						deltaCl := c.(*XDSClient[*discoverypb.DeltaDiscoveryRequest, *discoverypb.DeltaDiscoveryResponse])
						deltaCl.node = testNode()
						cache = deltaCl.cache
					}
					for _, rn := range tc.currResourceNames {
						cache.Upsert(typeUrl, rn, &listenerpb.Listener{Name: rn})
					}

					f := newFakeClient()

					done := make(chan bool)
					go func() {
						defer close(done)
						if sotw {
							c.(*XDSClient[*discoverypb.DiscoveryRequest, *discoverypb.DiscoveryResponse]).process(ctx, f)
						} else {
							c.(*XDSClient[*discoverypb.DeltaDiscoveryRequest, *discoverypb.DeltaDiscoveryResponse]).process(ctx, f)
						}
					}()

					err := c.Observe(ctx, typeUrl, tc.resourceNames)
					if err != nil {
						t.Fatalf("unexpected err: %v", err)
					}

					var gotResourceNames []string
					var gotTypeUrl string
					if sotw {
						got := <-f.sendStreamCh
						gotResourceNames = got.GetResourceNames()
						gotTypeUrl = got.GetTypeUrl()
					} else {
						got := <-f.sendDeltaCh
						gotResourceNames = got.GetResourceNamesSubscribe()
						gotTypeUrl = got.GetTypeUrl()
					}

					cancel()
					<-done

					var wantResourceNames []string
					if sotw {
						wantResourceNames = append(tc.resourceNames, tc.currResourceNames...)
						sort.Strings(wantResourceNames)
						wantResourceNames = slices.Compact(wantResourceNames)
					} else {
						wantResourceNames = tc.resourceNames
					}
					sort.Strings(gotResourceNames)

					if diff := cmp.Diff(wantResourceNames, gotResourceNames); diff != "" {
						t.Errorf("mismatched resource names: +got, -want: %s", diff)
					}
					if typeUrl != gotTypeUrl {
						t.Errorf("typeUrl = %s, want = %s", gotTypeUrl, typeUrl)
					}
				})
			}
		})
	}
}

type FakeClientConn struct {
	OnInvoke    func(ctx context.Context, method string, args any, reply any, opts ...grpc.CallOption) error
	OnNewStream func(ctx context.Context, desc *grpc.StreamDesc, method string, opts ...grpc.CallOption) (grpc.ClientStream, error)
}

func (f *FakeClientConn) Invoke(ctx context.Context, method string, args any, reply any, opts ...grpc.CallOption) error {
	return f.OnInvoke(ctx, method, args, reply, opts...)
}

func (f *FakeClientConn) NewStream(ctx context.Context, desc *grpc.StreamDesc, method string, opts ...grpc.CallOption) (grpc.ClientStream, error) {
	return f.OnNewStream(ctx, desc, method, opts...)
}

var _ grpc.ClientConnInterface = (*FakeClientConn)(nil)

func TestClientConnectionRetry(t *testing.T) {
	for _, retry := range []bool{true, false} {
		t.Run(fmt.Sprintf("retry=%v", retry), func(t *testing.T) {
			defer goleak.VerifyNone(t)

			opts := Defaults
			opts.RetryBackoff.Min = time.Hour
			opts.RetryBackoff.Max = time.Hour
			opts.RetryConnection = retry
			c := NewClient(slog.Default(), true, &opts)
			c.(*XDSClient[*discoverypb.DiscoveryRequest, *discoverypb.DiscoveryResponse]).node = testNode()
			ctx, cancel := context.WithCancel(context.TODO())
			defer cancel()

			wantErr := fmt.Errorf("test err")
			newStreamCh := make(chan bool)
			defer close(newStreamCh)
			fakeConn := &FakeClientConn{
				OnNewStream: func(ctx context.Context, desc *grpc.StreamDesc, method string, opts ...grpc.CallOption) (grpc.ClientStream, error) {
					newStreamCh <- true
					return nil, wantErr
				},
			}

			done := make(chan bool)
			var gotError error
			go func() {
				defer close(done)
				gotError = c.Run(ctx, testNode(), fakeConn)
			}()
			<-newStreamCh
			if retry {
				cancel()
				<-done
			} else {
				<-done
				cancel()
			}

			if retry {
				wantErr = context.Canceled
			}
			if !errors.Is(gotError, wantErr) {
				t.Errorf("error = %v, want = %v", gotError, wantErr)
			}
		})
	}
}

func TestAckAndNack(t *testing.T) {
	testCases := []struct {
		name string
		ack  bool
	}{
		{
			name: "ACK",
			ack:  true,
		},
		{
			name: "NACK",
			ack:  false,
		},
	}

	for sotw, name := range sotw2str {
		t.Run(name, func(t *testing.T) {
			for _, tc := range testCases {
				t.Run(tc.name, func(t *testing.T) {
					defer goleak.VerifyNone(t)

					opts := Defaults
					c := NewClient(slog.Default(), sotw, &opts)
					if sotw {
						c.(*XDSClient[*discoverypb.DiscoveryRequest, *discoverypb.DiscoveryResponse]).node = testNode()
					} else {
						c.(*XDSClient[*discoverypb.DeltaDiscoveryRequest, *discoverypb.DeltaDiscoveryResponse]).node = testNode()
					}
					ctx, cancel := context.WithCancel(context.TODO())

					typeUrl := envoy.ListenerTypeURL
					nonce := "just-a-test"

					lName := "listener-with-name-only"
					if !tc.ack {
						lName = ""
					}
					l, err := anypb.New(&listenerpb.Listener{Name: lName})
					if err != nil {
						t.Fatalf("unexpected anypb.New error = %v", err)
					}
					f := newFakeClient()

					var gotErr error
					done := make(chan bool)
					go func() {
						defer close(done)
						if sotw {
							gotErr = c.(*XDSClient[*discoverypb.DiscoveryRequest, *discoverypb.DiscoveryResponse]).process(ctx, f)
						} else {
							gotErr = c.(*XDSClient[*discoverypb.DeltaDiscoveryRequest, *discoverypb.DeltaDiscoveryResponse]).process(ctx, f)
						}
					}()

					if sotw {
						f.recvStreamCh <- &discoverypb.DiscoveryResponse{
							TypeUrl:   typeUrl,
							Resources: []*anypb.Any{l},
							Nonce:     nonce,
						}
					} else {
						f.recvDeltaCh <- &discoverypb.DeltaDiscoveryResponse{
							TypeUrl: typeUrl,
							Resources: []*discoverypb.Resource{
								{
									Name:     lName,
									Resource: l,
								},
							},
							Nonce: nonce,
						}
					}

					var req interface {
						GetResponseNonce() string
						GetTypeUrl() string
						GetErrorDetail() *grpcStatus.Status
					}
					if sotw {
						req = <-f.sendStreamCh
					} else {
						req = <-f.sendDeltaCh
					}

					cancel()
					<-done

					if !errors.Is(gotErr, context.Canceled) && !strings.Contains(gotErr.Error(), "terminated") {
						t.Errorf("unexpected error = %v", gotErr)
					}

					gotNonce := req.GetResponseNonce()
					if gotNonce != nonce {
						t.Errorf("nonce = %s, want = %s", gotNonce, nonce)
					}
					gotTypeUrl := req.GetTypeUrl()
					if gotTypeUrl != typeUrl {
						t.Errorf("typeUrl = %s, want = %s", gotTypeUrl, typeUrl)
					}

					errDetail := req.GetErrorDetail()
					if tc.ack {
						if errDetail != nil {
							t.Errorf("error detail = %v, want = empty", errDetail)
						}
					} else {
						if errDetail == nil {
							t.Error("expected non-empty error detail")
						}
					}
				})
			}
		})
	}
}

// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Hubble

// Copyright Authors of Cilium

package testutils

import (
	"context"
	"net"
	"net/netip"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/connectivity"

	flowpb "github.com/cilium/cilium/api/v1/flow"
	"github.com/cilium/cilium/api/v1/models"
	observerpb "github.com/cilium/cilium/api/v1/observer"
	peerpb "github.com/cilium/cilium/api/v1/peer"
	cgroupManager "github.com/cilium/cilium/pkg/cgroups/manager"
	v1 "github.com/cilium/cilium/pkg/hubble/api/v1"
	peerTypes "github.com/cilium/cilium/pkg/hubble/peer/types"
	poolTypes "github.com/cilium/cilium/pkg/hubble/relay/pool/types"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/ipcache"
	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/policy"
)

// FakeGetFlowsServer is used for unit tests and implements the
// observerpb.Observer_GetFlowsServer interface.
type FakeGetFlowsServer struct {
	OnSend func(response *observerpb.GetFlowsResponse) error
	*FakeGRPCServerStream
}

// Send implements observerpb.Observer_GetFlowsServer.Send.
func (s *FakeGetFlowsServer) Send(response *observerpb.GetFlowsResponse) error {
	if s.OnSend != nil {
		// TODO: completely convert this into using flowpb.Flow
		return s.OnSend(response)
	}
	panic("OnSend not set")
}

// FakeGetAgentEventsServer is used for unit tests and implements the
// observerpb.Observer_GetAgentEventsServer interface.
type FakeGetAgentEventsServer struct {
	OnSend func(response *observerpb.GetAgentEventsResponse) error
	*FakeGRPCServerStream
}

// Send implements observerpb.Observer_GetAgentEventsServer.Send.
func (s *FakeGetAgentEventsServer) Send(response *observerpb.GetAgentEventsResponse) error {
	if s.OnSend != nil {
		return s.OnSend(response)
	}
	panic("OnSend not set")
}

// FakeObserverClient is used for unit tests and implements the
// observerpb.ObserverClient interface.
type FakeObserverClient struct {
	OnGetFlows       func(ctx context.Context, in *observerpb.GetFlowsRequest, opts ...grpc.CallOption) (observerpb.Observer_GetFlowsClient, error)
	OnGetAgentEvents func(ctx context.Context, in *observerpb.GetAgentEventsRequest, opts ...grpc.CallOption) (observerpb.Observer_GetAgentEventsClient, error)
	OnGetDebugEvents func(ctx context.Context, in *observerpb.GetDebugEventsRequest, opts ...grpc.CallOption) (observerpb.Observer_GetDebugEventsClient, error)
	OnGetNodes       func(ctx context.Context, in *observerpb.GetNodesRequest, opts ...grpc.CallOption) (*observerpb.GetNodesResponse, error)
	OnServerStatus   func(ctx context.Context, in *observerpb.ServerStatusRequest, opts ...grpc.CallOption) (*observerpb.ServerStatusResponse, error)
}

// GetFlows implements observerpb.ObserverClient.GetFlows.
func (c *FakeObserverClient) GetFlows(ctx context.Context, in *observerpb.GetFlowsRequest, opts ...grpc.CallOption) (observerpb.Observer_GetFlowsClient, error) {
	if c.OnGetFlows != nil {
		return c.OnGetFlows(ctx, in, opts...)
	}
	panic("OnGetFlows not set")
}

// GetAgentEvents implements observerpb.ObserverClient.GetAgentEvents.
func (c *FakeObserverClient) GetAgentEvents(ctx context.Context, in *observerpb.GetAgentEventsRequest, opts ...grpc.CallOption) (observerpb.Observer_GetAgentEventsClient, error) {
	if c.OnGetAgentEvents != nil {
		return c.OnGetAgentEvents(ctx, in, opts...)
	}
	panic("OnGetAgentEvents not set")
}

// GetDebugEvents implements observerpb.ObserverClient.GetDebugEvents.
func (c *FakeObserverClient) GetDebugEvents(ctx context.Context, in *observerpb.GetDebugEventsRequest, opts ...grpc.CallOption) (observerpb.Observer_GetDebugEventsClient, error) {
	if c.OnGetDebugEvents != nil {
		return c.OnGetDebugEvents(ctx, in, opts...)
	}
	panic("OnGetDebugEvents not set")
}

// GetNodes implements observerpb.ObserverClient.GetNodes.
func (c *FakeObserverClient) GetNodes(ctx context.Context, in *observerpb.GetNodesRequest, opts ...grpc.CallOption) (*observerpb.GetNodesResponse, error) {
	if c.OnGetNodes != nil {
		return c.OnGetNodes(ctx, in, opts...)
	}
	panic("OnGetNodes not set")
}

// ServerStatus implements observerpb.ObserverClient.ServerStatus.
func (c *FakeObserverClient) ServerStatus(ctx context.Context, in *observerpb.ServerStatusRequest, opts ...grpc.CallOption) (*observerpb.ServerStatusResponse, error) {
	if c.OnServerStatus != nil {
		return c.OnServerStatus(ctx, in, opts...)
	}
	panic("OnServerStatus not set")
}

// FakeGetFlowsClient is used for unit tests and implements the
// observerpb.Observer_GetFlowsClient interface.
type FakeGetFlowsClient struct {
	OnRecv func() (*observerpb.GetFlowsResponse, error)
	*FakeGRPCClientStream
}

// Recv implements observerpb.Observer_GetFlowsClient.Recv.
func (c *FakeGetFlowsClient) Recv() (*observerpb.GetFlowsResponse, error) {
	if c.OnRecv != nil {
		return c.OnRecv()
	}
	panic("OnRecv not set")
}

// FakePeerNotifyServer is used for unit tests and implements the
// peerpb.Peer_NotifyServer interface.
type FakePeerNotifyServer struct {
	OnSend func(response *peerpb.ChangeNotification) error
	*FakeGRPCServerStream
}

// Send implements peerpb.Peer_NotifyServer.Send.
func (s *FakePeerNotifyServer) Send(response *peerpb.ChangeNotification) error {
	if s.OnSend != nil {
		return s.OnSend(response)
	}
	panic("OnSend not set")
}

// FakePeerNotifyClient is used for unit tests and implements the
// peerpb.Peer_NotifyClient interface.
type FakePeerNotifyClient struct {
	OnRecv func() (*peerpb.ChangeNotification, error)
	*FakeGRPCClientStream
}

// Recv implements peerpb.Peer_NotifyClient.Recv.
func (c *FakePeerNotifyClient) Recv() (*peerpb.ChangeNotification, error) {
	if c.OnRecv != nil {
		return c.OnRecv()
	}
	panic("OnRecv not set")
}

// FakePeerClient is used for unit tests and implements the peerTypes.Client
// interface.
type FakePeerClient struct {
	OnNotify func(ctx context.Context, in *peerpb.NotifyRequest, opts ...grpc.CallOption) (peerpb.Peer_NotifyClient, error)
	OnClose  func() error
}

// Notify implements peerTypes.Client.Notify.
func (c *FakePeerClient) Notify(ctx context.Context, in *peerpb.NotifyRequest, opts ...grpc.CallOption) (peerpb.Peer_NotifyClient, error) {
	if c.OnNotify != nil {
		return c.OnNotify(ctx, in, opts...)
	}
	panic("OnNotify not set")
}

// Close implements peerTypes.Client.Close.
func (c *FakePeerClient) Close() error {
	if c.OnClose != nil {
		return c.OnClose()
	}
	panic("OnClose not set")
}

// FakePeerClientBuilder is used for unit tests and implements the
// peerTypes.ClientBuilder interface.
type FakePeerClientBuilder struct {
	OnClient func(target string) (peerTypes.Client, error)
}

// Client implements peerTypes.ClientBuilder.Client.
func (b FakePeerClientBuilder) Client(target string) (peerTypes.Client, error) {
	if b.OnClient != nil {
		return b.OnClient(target)
	}
	panic("OnClient not set")
}

// FakePeerListReporter is used for unit tests and implements the
// relay/observer.PeerListReporter interface.
type FakePeerListReporter struct {
	OnList          func() []poolTypes.Peer
	OnReportOffline func(name string)
}

// List implements relay/observer.PeerListReporter.List.
func (r *FakePeerListReporter) List() []poolTypes.Peer {
	if r.OnList != nil {
		return r.OnList()
	}
	panic("OnList not set")
}

// ReportOffline implements relay/observer.PeerListReporter.ReportOffline.
func (r *FakePeerListReporter) ReportOffline(name string) {
	if r.OnReportOffline != nil {
		r.OnReportOffline(name)
		return
	}
	panic("OnReportOffline not set")
}

// FakeClientConn is used for unit tests and implements the
// poolTypes.ClientConn interface.
type FakeClientConn struct {
	OnGetState  func() connectivity.State
	OnClose     func() error
	OnInvoke    func(ctx context.Context, method string, args interface{}, reply interface{}, opts ...grpc.CallOption) error
	OnNewStream func(ctx context.Context, desc *grpc.StreamDesc, method string, opts ...grpc.CallOption) (grpc.ClientStream, error)
}

// GetState implements poolTypes.ClientConn.GetState.
func (c FakeClientConn) GetState() connectivity.State {
	if c.OnGetState != nil {
		return c.OnGetState()
	}
	panic("OnGetState not set")
}

// Close implements poolTypes.ClientConn.Close.
func (c FakeClientConn) Close() error {
	if c.OnClose != nil {
		return c.OnClose()
	}
	panic("OnClose not set")
}

// Invoke implements poolTypes.ClientConn.Invoke.
func (c FakeClientConn) Invoke(ctx context.Context, method string, args interface{}, reply interface{}, opts ...grpc.CallOption) error {
	if c.OnInvoke != nil {
		return c.OnInvoke(ctx, method, args, reply, opts...)
	}
	panic("OnInvoke not set")
}

// NewStream implements poolTypes.ClientConn.NewStream.
func (c FakeClientConn) NewStream(ctx context.Context, desc *grpc.StreamDesc, method string, opts ...grpc.CallOption) (grpc.ClientStream, error) {
	if c.OnNewStream != nil {
		return c.OnNewStream(ctx, desc, method, opts...)
	}
	panic("OnNewStream not set")
}

// FakeFQDNCache is used for unit tests that needs FQDNCache and/or DNSGetter.
type FakeFQDNCache struct {
	OnInitializeFrom func(entries []*models.DNSLookup)
	OnAddDNSLookup   func(epID uint32, lookupTime time.Time, domainName string, ips []net.IP, ttl uint32)
	OnGetNamesOf     func(epID uint32, ip netip.Addr) []string
}

// InitializeFrom implements FQDNCache.InitializeFrom.
func (f *FakeFQDNCache) InitializeFrom(entries []*models.DNSLookup) {
	if f.OnInitializeFrom != nil {
		f.OnInitializeFrom(entries)
		return
	}
	panic("InitializeFrom([]*models.DNSLookup) should not have been called since it was not defined")
}

// AddDNSLookup implements FQDNCache.AddDNSLookup.
func (f *FakeFQDNCache) AddDNSLookup(epID uint32, lookupTime time.Time, domainName string, ips []net.IP, ttl uint32) {
	if f.OnAddDNSLookup != nil {
		f.OnAddDNSLookup(epID, lookupTime, domainName, ips, ttl)
		return
	}
	panic("AddDNSLookup(uint32, time.Time, string, []net.IP, uint32) should not have been called since it was not defined")
}

// GetNamesOf implements FQDNCache.GetNameOf.
func (f *FakeFQDNCache) GetNamesOf(epID uint32, ip netip.Addr) []string {
	if f.OnGetNamesOf != nil {
		return f.OnGetNamesOf(epID, ip)
	}
	panic("GetNamesOf(uint32, netip.Addr) should not have been called since it was not defined")
}

// NoopDNSGetter always returns an empty response.
var NoopDNSGetter = FakeFQDNCache{
	OnGetNamesOf: func(sourceEpID uint32, ip netip.Addr) (fqdns []string) {
		return nil
	},
}

// FakeEndpointGetter is used for unit tests that needs EndpointGetter.
type FakeEndpointGetter struct {
	OnGetEndpointInfo     func(ip netip.Addr) (endpoint v1.EndpointInfo, ok bool)
	OnGetEndpointInfoByID func(id uint16) (endpoint v1.EndpointInfo, ok bool)
}

// GetEndpointInfo implements EndpointGetter.GetEndpointInfo.
func (f *FakeEndpointGetter) GetEndpointInfo(ip netip.Addr) (endpoint v1.EndpointInfo, ok bool) {
	if f.OnGetEndpointInfo != nil {
		return f.OnGetEndpointInfo(ip)
	}
	panic("OnGetEndpointInfo not set")
}

// GetEndpointInfoByID implements EndpointGetter.GetEndpointInfoByID.
func (f *FakeEndpointGetter) GetEndpointInfoByID(id uint16) (endpoint v1.EndpointInfo, ok bool) {
	if f.OnGetEndpointInfoByID != nil {
		return f.OnGetEndpointInfoByID(id)
	}
	panic("GetEndpointInfoByID not set")
}

// NoopEndpointGetter always returns an empty response.
var NoopEndpointGetter = FakeEndpointGetter{
	OnGetEndpointInfo: func(ip netip.Addr) (endpoint v1.EndpointInfo, ok bool) {
		return nil, false
	},
	OnGetEndpointInfoByID: func(id uint16) (endpoint v1.EndpointInfo, ok bool) {
		return nil, false
	},
}

type FakeLinkGetter struct{}

func (e *FakeLinkGetter) Name(ifindex uint32) string {
	return "lo"
}

func (e *FakeLinkGetter) GetIfNameCached(ifindex int) (string, bool) {
	return e.Name(uint32(ifindex)), true
}

var NoopLinkGetter = FakeLinkGetter{}

// FakeIPGetter is used for unit tests that needs IPGetter.
type FakeIPGetter struct {
	OnGetK8sMetadata  func(ip netip.Addr) *ipcache.K8sMetadata
	OnLookupSecIDByIP func(ip netip.Addr) (ipcache.Identity, bool)
}

// GetK8sMetadata implements FakeIPGetter.GetK8sMetadata.
func (f *FakeIPGetter) GetK8sMetadata(ip netip.Addr) *ipcache.K8sMetadata {
	if f.OnGetK8sMetadata != nil {
		return f.OnGetK8sMetadata(ip)
	}
	panic("OnGetK8sMetadata not set")
}

// LookupSecIDByIP implements FakeIPGetter.LookupSecIDByIP.
func (f *FakeIPGetter) LookupSecIDByIP(ip netip.Addr) (ipcache.Identity, bool) {
	if f.OnLookupSecIDByIP != nil {
		return f.OnLookupSecIDByIP(ip)
	}
	panic("OnLookupByIP not set")
}

// NoopIPGetter always returns an empty response.
var NoopIPGetter = FakeIPGetter{
	OnGetK8sMetadata: func(ip netip.Addr) *ipcache.K8sMetadata {
		return nil
	},
	OnLookupSecIDByIP: func(ip netip.Addr) (ipcache.Identity, bool) {
		return ipcache.Identity{}, false
	},
}

// FakeServiceGetter is used for unit tests that need ServiceGetter.
type FakeServiceGetter struct {
	OnGetServiceByAddr func(ip netip.Addr, port uint16) *flowpb.Service
}

// GetServiceByAddr implements FakeServiceGetter.GetServiceByAddr.
func (f *FakeServiceGetter) GetServiceByAddr(ip netip.Addr, port uint16) *flowpb.Service {
	if f.OnGetServiceByAddr != nil {
		return f.OnGetServiceByAddr(ip, port)
	}
	panic("OnGetServiceByAddr not set")
}

// NoopServiceGetter always returns an empty response.
var NoopServiceGetter = FakeServiceGetter{
	OnGetServiceByAddr: func(ip netip.Addr, port uint16) *flowpb.Service {
		return nil
	},
}

// FakeIdentityGetter is used for unit tests that need IdentityGetter.
type FakeIdentityGetter struct {
	OnGetIdentity func(securityIdentity uint32) (*identity.Identity, error)
}

// GetIdentity implements IdentityGetter.GetIPIdentity.
func (f *FakeIdentityGetter) GetIdentity(securityIdentity uint32) (*identity.Identity, error) {
	if f.OnGetIdentity != nil {
		return f.OnGetIdentity(securityIdentity)
	}
	panic("OnGetIdentity not set")
}

// NoopIdentityGetter always returns an empty response.
var NoopIdentityGetter = FakeIdentityGetter{
	OnGetIdentity: func(securityIdentity uint32) (*identity.Identity, error) {
		return &identity.Identity{}, nil
	},
}

// FakeEndpointInfo implements v1.EndpointInfo for unit tests. All interface
// methods return values exposed in the fields.
type FakeEndpointInfo struct {
	ContainerIDs []string
	ID           uint64
	Identity     identity.NumericIdentity
	IPv4         net.IP
	IPv6         net.IP
	PodName      string
	PodNamespace string
	Labels       []string
	Pod          *slim_corev1.Pod

	PolicyMap      map[policy.Key]labels.LabelArrayList
	PolicyRevision uint64
}

// GetID returns the ID of the endpoint.
func (e *FakeEndpointInfo) GetID() uint64 {
	return e.ID
}

// GetIdentity returns the numerical security identity of the endpoint.
func (e *FakeEndpointInfo) GetIdentity() identity.NumericIdentity {
	return e.Identity
}

// GetK8sPodName returns the pod name of the endpoint.
func (e *FakeEndpointInfo) GetK8sPodName() string {
	return e.PodName
}

// GetK8sNamespace returns the pod namespace of the endpoint.
func (e *FakeEndpointInfo) GetK8sNamespace() string {
	return e.PodNamespace
}

// GetLabels returns the labels of the endpoint.
func (e *FakeEndpointInfo) GetLabels() []string {
	return e.Labels
}

// GetPod return the pod object of the endpoint.
func (e *FakeEndpointInfo) GetPod() *slim_corev1.Pod {
	return e.Pod
}

func (e *FakeEndpointInfo) GetRealizedPolicyRuleLabelsForKey(key policy.Key) (
	derivedFrom labels.LabelArrayList,
	revision uint64,
	ok bool,
) {
	derivedFrom, ok = e.PolicyMap[key]
	return derivedFrom, e.PolicyRevision, ok
}

// FakePodMetadataGetter is used for unit tests that need a PodMetadataGetter.
type FakePodMetadataGetter struct {
	OnGetPodMetadataForContainer func(cgroupId uint64) *cgroupManager.PodMetadata
}

// GetPodMetadataForContainer implements PodMetadataGetter.GetPodMetadataForContainer.
func (f *FakePodMetadataGetter) GetPodMetadataForContainer(cgroupId uint64) *cgroupManager.PodMetadata {
	if f.OnGetPodMetadataForContainer != nil {
		return f.OnGetPodMetadataForContainer(cgroupId)
	}
	panic("GetPodMetadataForContainer not set")
}

// NoopPodMetadataGetter always returns an empty response.
var NoopPodMetadataGetter = FakePodMetadataGetter{
	OnGetPodMetadataForContainer: func(cgroupId uint64) *cgroupManager.PodMetadata {
		return nil
	},
}

// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Hubble

package common

import (
	"net/netip"

	"github.com/sirupsen/logrus"

	pb "github.com/cilium/cilium/api/v1/flow"
	"github.com/cilium/cilium/pkg/hubble/parser/getters"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/k8s/utils"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/time"
)

type DatapathContext struct {
	SrcIP                 netip.Addr
	SrcLabelID            uint32
	DstIP                 netip.Addr
	DstLabelID            uint32
	TraceObservationPoint pb.TraceObservationPoint
}

type EndpointResolver struct {
	log            logrus.FieldLogger
	logLimiter     logging.Limiter
	endpointGetter getters.EndpointGetter
	identityGetter getters.IdentityGetter
	ipGetter       getters.IPGetter
}

func NewEndpointResolver(
	log logrus.FieldLogger,
	endpointGetter getters.EndpointGetter,
	identityGetter getters.IdentityGetter,
	ipGetter getters.IPGetter,
) *EndpointResolver {
	return &EndpointResolver{
		log:            log,
		logLimiter:     logging.NewLimiter(30*time.Second, 1),
		endpointGetter: endpointGetter,
		identityGetter: identityGetter,
		ipGetter:       ipGetter,
	}
}

func (r *EndpointResolver) ResolveEndpoint(ip netip.Addr, datapathSecurityIdentity uint32, context DatapathContext) *pb.Endpoint {
	// The datapathSecurityIdentity parameter is the numeric security identity
	// obtained from the datapath.
	// The numeric identity from the datapath can differ from the one we obtain
	// from user-space (e.g. the endpoint manager or the IP cache), because
	// the identity could have changed between the time the datapath event was
	// created and the time the event reaches the Hubble parser.
	// To aid in troubleshooting, we want to preserve what the datapath observed
	// when it made the policy decision.
	resolveIdentityConflict := func(userspaceID identity.NumericIdentity, isLocalEndpoint bool) uint32 {
		// if the datapath did not provide an identity (e.g. FROM_LXC trace
		// points), use what we have in the user-space cache
		datapathID := identity.NumericIdentity(datapathSecurityIdentity)
		if datapathID == identity.IdentityUnknown {
			return userspaceID.Uint32()
		}

		// Log any identity discrepancies, unless or this is a known case where
		// Hubble does not have the full picture (see inline comments below each case)
		// or we've hit the log rate limit
		if datapathID != userspaceID {
			if context.TraceObservationPoint == pb.TraceObservationPoint_TO_OVERLAY &&
				ip == context.SrcIP && datapathID.Uint32() == context.SrcLabelID &&
				datapathID == identity.ReservedIdentityRemoteNode &&
				userspaceID == identity.ReservedIdentityHost {
				// Ignore
				//
				// When encapsulating a packet for sending via the overlay network, if the source
				// seclabel = HOST_ID, then we reassign seclabel with LOCAL_NODE_ID and then send
				// a trace notify.
			} else if context.TraceObservationPoint == pb.TraceObservationPoint_TO_OVERLAY &&
				ip == context.SrcIP && datapathID.Uint32() == context.SrcLabelID &&
				!datapathID.IsReservedIdentity() && userspaceID == identity.ReservedIdentityHost {
				// Ignore
				//
				// An IPSec encrypted packet will have the local cilium_host IP as the source
				// address, but the datapath seclabel will be the one of the source pod.
			} else if context.TraceObservationPoint == pb.TraceObservationPoint_FROM_ENDPOINT &&
				ip == context.SrcIP && datapathID.Uint32() == context.SrcLabelID &&
				(datapathID == identity.ReservedIdentityHealth || !datapathID.IsReservedIdentity()) &&
				userspaceID.IsWorld() {
				// Ignore
				//
				// Sometimes packets from endpoint link-local addresses are intercepted by
				// cil_from_container. Because link-local addresses are not stored in the IP cache,
				// Hubble assigns them WORLD_ID.
			} else if context.TraceObservationPoint == pb.TraceObservationPoint_FROM_HOST &&
				ip == context.SrcIP && datapathID.Uint32() == context.SrcLabelID &&
				datapathID.IsWorld() && userspaceID == identity.ReservedIdentityKubeAPIServer {
				// Ignore
				//
				// When a pod sends a packet to the Kubernetes API, its IP is masqueraded and then
				// when it receives a response and the masquerade is reversed, cil_from_host
				// determines that the source ID is WORLD_ID because there is no packet mark.
			} else if (context.TraceObservationPoint == pb.TraceObservationPoint_FROM_HOST ||
				context.TraceObservationPoint == pb.TraceObservationPoint_TO_OVERLAY) &&
				ip == context.SrcIP && datapathID.Uint32() == context.SrcLabelID &&
				isLocalEndpoint && userspaceID == identity.ReservedIdentityHost {
				// Ignore
				//
				// When proxied packets (via Cilium DNS proxy) are sent from the host their source
				// IP is that of the host, yet their security identity is retained from the
				// original source pod.
			} else if context.TraceObservationPoint == pb.TraceObservationPoint_TO_ENDPOINT &&
				ip == context.SrcIP && datapathID.Uint32() == context.SrcLabelID &&
				!datapathID.IsReservedIdentity() &&
				(userspaceID == identity.ReservedIdentityHost || userspaceID == identity.ReservedIdentityRemoteNode) {
				// Ignore
				//
				// When proxied packets (via Cilium DNS proxy) are received by the destination
				// host their source IP is that of the proxy, yet their security identity is
				// retained from the original source pod. This is a similar case to #4, but on the
				// receiving side.
			} else if r.logLimiter.Allow() {
				r.log.WithFields(logrus.Fields{
					"datapath-identity":  datapathID.Uint32(),
					"userspace-identity": userspaceID.Uint32(),
					"context":            logfields.Repr(context),
					logfields.IPAddr:     ip,
				}).Debugf("stale identity observed")
			}
		}

		return datapathID.Uint32()
	}

	// for local endpoints, use the available endpoint information
	if r.endpointGetter != nil {
		if ep, ok := r.endpointGetter.GetEndpointInfo(ip); ok {
			epIdentity := resolveIdentityConflict(ep.GetIdentity(), true)
			e := &pb.Endpoint{
				ID:        uint32(ep.GetID()),
				Identity:  epIdentity,
				Namespace: ep.GetK8sNamespace(),
				Labels:    SortAndFilterLabels(r.log, ep.GetLabels(), identity.NumericIdentity(epIdentity)),
				PodName:   ep.GetK8sPodName(),
			}
			if pod := ep.GetPod(); pod != nil {
				workload, workloadTypeMeta, ok := utils.GetWorkloadMetaFromPod(pod)
				if ok {
					e.Workloads = []*pb.Workload{{Kind: workloadTypeMeta.Kind, Name: workload.Name}}
				}
			}
			return e
		}
	}

	// for remote endpoints, assemble the information via ip and identity
	numericIdentity := datapathSecurityIdentity
	var namespace, podName string
	if r.ipGetter != nil {
		if ipIdentity, ok := r.ipGetter.LookupSecIDByIP(ip); ok {
			numericIdentity = resolveIdentityConflict(ipIdentity.ID, false)
		}
		if meta := r.ipGetter.GetK8sMetadata(ip); meta != nil {
			namespace, podName = meta.Namespace, meta.PodName
		}
	}
	var labels []string
	if r.identityGetter != nil {
		if id, err := r.identityGetter.GetIdentity(numericIdentity); err != nil {
			r.log.WithError(err).WithField("identity", numericIdentity).
				Debug("failed to resolve identity")
		} else {
			labels = SortAndFilterLabels(r.log, id.Labels.GetModel(), identity.NumericIdentity(numericIdentity))
		}
	}

	return &pb.Endpoint{
		Identity:  numericIdentity,
		Namespace: namespace,
		Labels:    labels,
		PodName:   podName,
	}
}

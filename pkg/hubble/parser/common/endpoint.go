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
	"github.com/cilium/cilium/pkg/logging/logfields"
)

type EndpointResolver struct {
	log            logrus.FieldLogger
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
		endpointGetter: endpointGetter,
		identityGetter: identityGetter,
		ipGetter:       ipGetter,
	}
}

func (r *EndpointResolver) ResolveEndpoint(ip netip.Addr, datapathSecurityIdentity uint32) *pb.Endpoint {
	// The datapathSecurityIdentity parameter is the numeric security identity
	// obtained from the datapath.
	// The numeric identity from the datapath can differ from the one we obtain
	// from user-space (e.g. the endpoint manager or the IP cache), because
	// the identity could have changed between the time the datapath event was
	// created and the time the event reaches the Hubble parser.
	// To aid in troubleshooting, we want to preserve what the datapath observed
	// when it made the policy decision.
	resolveIdentityConflict := func(identity identity.NumericIdentity) uint32 {
		// if the datapath did not provide an identity (e.g. FROM_LXC trace
		// points), use what we have in the user-space cache
		userspaceSecurityIdentity := identity.Uint32()
		if datapathSecurityIdentity == 0 {
			return userspaceSecurityIdentity
		}

		if datapathSecurityIdentity != userspaceSecurityIdentity {
			r.log.WithFields(logrus.Fields{
				logfields.Identity:    datapathSecurityIdentity,
				logfields.OldIdentity: userspaceSecurityIdentity,
				logfields.IPAddr:      ip,
			}).Debugf("stale identity observed")
		}

		return datapathSecurityIdentity
	}

	// for local endpoints, use the available endpoint information
	if r.endpointGetter != nil {
		if ep, ok := r.endpointGetter.GetEndpointInfo(ip); ok {
			epIdentity := resolveIdentityConflict(ep.GetIdentity())
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
			numericIdentity = resolveIdentityConflict(ipIdentity.ID)
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

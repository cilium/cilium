package cloudproviderpolicy

import (
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/policy/api"
)

var log = logging.DefaultLogger.WithField(logfields.LogSubsys, "cloudproviderpolicy")

var EgressDenyList []*api.Rule

func InitCloudProviderPolicies() []*api.Rule {
	portDenyRules := []api.PortDenyRule{
		{
			Ports: []api.PortProtocol{
				{
					Port:     "8000",
					Protocol: api.ProtoTCP,
				},
			},
		},
	}

	egressDenyRule := &api.Rule{
		EndpointSelector: api.WildcardEndpointSelector,
		EgressDeny: []api.EgressDenyRule{
			{
				EgressCommonRule: api.EgressCommonRule{
					ToCIDR: []api.CIDR{"10.0.0.5/32"},
				},
				ToPorts: portDenyRules,
			},
		},
		Labels: []labels.Label{
			{
				Source: labels.LabelSourceAdmin,
			},
		},
	}

	if err := egressDenyRule.Sanitize(); err != nil {
		log.WithField("error", err).Error("sanitize rule failed da")
	}

	//egressDenyCiliumRule := k8sCiliumUtils.ParseToCiliumRule("", "CloudProviderPolicy", "CloudProviderPolicyUid", egressDenyRule)
	EgressDenyList = append(EgressDenyList, egressDenyRule)

	log.Info("[tamilmani] Cloud provider deny list prepared")
	return EgressDenyList
}

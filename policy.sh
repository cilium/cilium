#!/bin/bash

set -x

# // doing this as andrema
# kubectl pod create -f ngnix.yaml
# -> tying to environment: Lizards with uid andrema
#    LABELS: io.cilium.Lizards
#            io.cilium.Lizards.user=andrema
#            io.cilium.Lizards.ngnix
#
#   cilium-daemon:
#     JoinEndpoint()
#          bpf_lxc
#          bpf_policy [empty]
#
#   Notification of new local container: ngnix
#     1. cilium_endpoint := daemon.endpoints[dockerID]
#     2. Get Docker Labels
#     3. Get k8s labels [metadata]
#     4. Check valid prefixes based valid_labels.json
#     5. endpoint.SecLabel = GetLabelsID("[...]") -> ???
#
#  Next TODO:
# AM  0. Retrieve labels in func (d Daemon) EndpointJoin(ep types.Endpoint) error {
# AM  1. Add mutex to policy tree
# TG  2. Compute allowed consumers for all endpoints
# TG  3. Convert []ConsumableDecision into BPF map
# TG  4. Write bpf_policy program
#          BPF MAP:
#	   HT: allowedConsumers[] {
#	      __u64 packets
#	      __u64 bytes
#   	}
#
#	lookup(__u16) {
#   	}
# AM  5. Notification in case of policy ID change
#        -> pool of background threads
#           -> updates all BPF maps
#        -> consul agent watch, calling shell, calling curl -> Cilium Daemon
#           REST API: NewID(id)
#                     DeleteID(id)
# AM  6. Retire security labels
#
#  Cases for consumer map regeneration:
#    Join endpoint: (1st case to solve)
#    - map not available yet (generate on the fly)
#    Events:
#    - policy update
#    - list of policy IDs changes
#      CASE: New ID:
#          Algo:
#            1. walk all local endpoints
#            2. check policy for new ID as consumer
#            3. Add map entry for new ID if policy result == ACCEPT
#       1. Consumer: New ID cannot access until producers have upated map
#       2. Producer: Nobody can consume until map is created
#      CASE: Del ID:
#          Algo:
#            1. Walk all local endpoints
#            2. remove map entry for deleted ID
#       1. Consumer: All maps must be updated before ID can be reused (!IMPORTANT!)
#       2. Producer: Doesn't matter
#
#  cilium-daemon:
#      AddPolicy() <- policy.JSON
#
#      -> Triggers generation of SecLabel and Consumers:
#
#     endpoint.SecLabel = GetLabelsID(["io.cilium.Lizards", "io.cilium.Lizards.user=andrema", ...]) -> 50
#
#     foreach endpoint {
#       foreach seclabel {
#         if canConsume(seclabel, endpoint) {
#            endpoint.Consumers = append(endpoint.Consumers, label)
#         updateBPFMAP(endpoint.Conumsers)
#       }
#     }
#
#     func canConsume(seclabel, endpoint) {
#        src_labels := GetLabels(seclabel)
#        dst_labels := GetLabels(endpoint)
#
#        // walk through policy
#        return true or false
#     }
# SecLabel
#     SRC:                        DST:
# 11  # io.cilium.Lizards.Web  => io.cilium.Lizards.DB    33
#     # io.cilium.Lizards.QA   => io.cilium.Lizards.Prod
#
# 22  # io.cilium.Lizards.Web  => io.cilium.Lizards.DB    33
#     # io.cilium.Lizards.Prod => io.cilium.Lizards.Prod
#
#     33: [22]
#     22: [33]
#
#     TODO: Thomas: Ask John about conntrack in BPF

#LABELS=$(cat <<EOF
#[{
#	"Name": "io.cilium",
#	"Type": "cilium",
#},{
#	"Name": "io.kuberentes.pod.uid",
#	"Type": "kubernetes"
#}
#EOF

#		"k8s": {
#			"Name": "k8s",
#			"Rules": [{
#				"Coverage": ["PodSelector", "PodSelector2"],
#				"Allow": [{"type": "pod", "label": "tier=database"}, {"type": "namespace", ...}],
#				"Ports": { "to": [{"tcp", 80},{"udp", 50}], "from": null },
#			}]
#		}

POLICY=$(cat <<EOF
{
        "Name": "io.cilium",
        "Children": {
		"Lizards": {
			"Rules": [{
				"Coverage": ["QA"],
				"Requires": ["QA"]
			},{
				"Coverage": ["Prod"],
				"Requires": ["Prod"]
			}],
			"Children": {
				"Web": { },
				"DB": {
					"Rules": [{
						"Allow": ["Web", {"action": "deny", "source": "kubernetes", "key": "foo"}]
					}]
				}
			}
		},
		"Birds": {
			"Children": {
				"DB": { }
			}
		}

	}
}
EOF
)

curl $FLAGS -XPOST http://localhost:9000/policy/io.cilium -d "$POLICY"
curl $FLAGS -XGET http://localhost:9000/policy/io.cilium


POLICY=$(cat <<EOF
{
        "Name": "DB",
	"Rules": [{
		"Allow": ["Web2"]
	}]
}
EOF
)

curl $FLAGS -XPOST http://localhost:9000/policy/io.cilium.Lizards -d "$POLICY"
curl $FLAGS -XGET http://localhost:9000/policy/io.cilium.Lizards

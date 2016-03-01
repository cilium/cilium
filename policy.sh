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

LABELS=$(cat <<EOF
[{
	"Name": "io.cilium",
	"Type": "cilium",
},{
	"Name": "io.kuberentes.pod.uid",
	"Type": "kubernetes"
}
EOF

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
						"Allow": ["Web"]
						"Allow": [{"com.coke.flavour", "blah"}, "Web", {"io.kubernetes.pod.uid", "3224234"}],
					}]
				},
				"Ngnix": {
					"Rules": [{
						"Allow": ["World"]
					}]
				}
			}
		},
		"Birds": {
			"Name": "Birds",
			"Children": {
				"DB": { }
			}
		},
		"k8s": {
			"Name": "k8s",
			"Rules": [{
				"Coverage": ["PodSelector", "PodSelector2"],
				"Allow": [{"type": "pod", "label": "tier=database"}, {"type": "namespace", ...}],
				"Ports": { "to": [{"tcp", 80},{"udp", 50}], "from": null },
				"Drop-Privileges": "Ports",
			}]
		}

	}
}
EOF
)

curl $FLAGS -XPOST http://localhost:9000/policy/io.cilium -d "$POLICY"
curl $FLAGS -XGET http://localhost:9000/policy/io.cilium.Lizards


POLICY=$(cat <<EOF
{
        "Name": "DB",
	"Rules": [{
		"Allow": ["Web"]
	}]
}
EOF
)

curl $FLAGS -XPOST http://localhost:9000/policy/io.cilium.Lizards -d "$POLICY"

#!/bin/bash

set -x

POLICY=$(cat <<EOF
{
        "Name": "io.cilium",
        "Rules": null,
        "Childs": [{
                "Name": "Lizards",
		"Rules": [{
			"Coverage": "QA",
			"Requires": "QA"
		}],
                "Childs": [{
                        "Name": "Web"
                },{
                        "Name": "DB",
                        "Rules": [{
				"Allow": "Web"
			}]
                }]
        },{
                "Name": "Birds",
                "Rules": null,
                "Childs": [{
                        "Name": "DB",
                        "Rules": null
                }]
        }]
}
EOF
)

curl $FLAGS -XPOST http://localhost:9000/policy/foo -d "$POLICY"
curl $FLAGS -XGET http://localhost:9000/policy/io.cilium.Lizards


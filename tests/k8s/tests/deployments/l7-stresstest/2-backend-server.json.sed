{
    "kind":"ReplicationController",
    "apiVersion":"v1",
    "metadata":{
        "name":"backend",
        "namespace": "development",
        "labels":{
            "id":"server"
        }
    },
    "spec":{
        "replicas":1,
        "selector":{
            "id":"server"
        },
        "template":{
            "metadata":{
                "labels":{
                    "id":"server"
                }
            },
            "spec":{
                "containers":[{
                    "name":"server",
                    "image":"httpd",
                    "ports":[{
                        "name":"http",
                        "containerPort":80
                    }]
                }],
                "nodeSelector": {
                    "kubernetes.io/hostname": "$kube_node_selector"
                }
            }
        }
    }
}

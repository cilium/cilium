{
  "kind":"ReplicationController",
  "apiVersion":"v1",
  "metadata":{
    "name":"CLIENT_NAME",
    "labels":{
      "CLIENT_LABEL":""
    }
  },
  "spec":{
    "replicas":1,
    "selector":{
      "CLIENT_LABEL": ""
    },
    "template":{
      "metadata":{
        "labels":{
          "CLIENT_LABEL": ""
        }
      },
      "spec": {
        "containers":[{
          "name":"CLIENT_NAME",
          "image":"NETPERF_IMAGE",
          "command": [
            "/usr/bin/netserver"
          ],
          "args": [
            "-D"
          ]
        }],
        "nodeSelector": {
          "kubernetes.io/hostname": "worker0"
        }
      }
    }
  }
}

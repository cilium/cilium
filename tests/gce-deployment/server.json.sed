{
  "kind":"ReplicationController",
  "apiVersion":"v1",
  "metadata":{
    "name":"SERVER_NAME",
    "labels":{
      "SERVER_LABEL":""
    }
  },
  "spec":{
    "replicas":1,
    "selector":{
      "SERVER_LABEL": ""
    },
    "template":{
      "metadata":{
        "labels":{
          "SERVER_LABEL": ""
        }
      },
      "spec": {
        "containers":[{
          "name":"SERVER_NAME",
          "image":"NETPERF_IMAGE",
          "command": [
            "/usr/bin/netserver"
          ],
          "args": [
            "-D"
          ]
        }],
        "nodeSelector": {
          "kubernetes.io/hostname": "worker1"
        }
      }
    }
  }
}

local deploy = import "cilium_ds.template";

deploy {
    image: "k8s1:5000/cilium/cilium-dev:latest",
    etcdEndpoint: "k8s1:9732",
    ciliumArgs: [
        "--debug=$(CILIUM_DEBUG)",
        "-t=vxlan",
        "--kvstore=etcd",
        "--kvstore-opt=etcd.config=/var/lib/etcd-config/etcd.config",
        "--disable-ipv4=$(DISABLE_IPV4)",
        "--debug-verbose=flow"
    ]
}

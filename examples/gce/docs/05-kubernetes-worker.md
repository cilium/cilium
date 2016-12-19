# Bootstrapping Kubernetes Workers

(Differences from original: IP addresses, removed kube-proxy, add `--make-iptables-util-chains=false`
flag to kubelet, changed network-plugin to `cni` and removed `--configure-cbr0`.)

In this lab you will bootstrap 3 Kubernetes worker nodes. The following virtual machines will be used:

* worker0
* worker1
* worker2

## Why

Kubernetes worker nodes are responsible for running your containers. All Kubernetes clusters need one or more worker nodes. We are running the worker nodes on dedicated machines for the following reasons:

* Ease of deployment and configuration
* Avoid mixing arbitrary workloads with critical cluster components. We are building machine with just enough resources so we don't have to worry about wasting resources.

Some people would like to run workers and cluster services anywhere in the cluster. This is totally possible, and you'll have to decide what's best for your environment.


## Provision the Kubernetes Worker Nodes

Run the following commands on `worker0`, `worker1`, `worker2`:

#### Move the TLS certificates in place

```
sudo mkdir -p /var/lib/kubernetes
```

```
sudo cp ca.pem kubernetes-key.pem kubernetes.pem /var/lib/kubernetes/
```

#### Create cilium etcd configuration file

```
sudo mkdir -p /var/lib/cilium
```

```
sudo sh -c 'echo "---
endpoints:
- https://172.16.0.10:2379
- https://172.16.0.11:2379
- https://172.16.0.12:2379
ca-file: \"/var/lib/kubernetes/ca.pem\"
" > /var/lib/cilium/etcd-config.yml'
```

#### Create cni configuration file

```
sudo mkdir -p /etc/cni/net.d
```

```
sudo sh -c 'echo "{
    "name": "cilium",
    "type": "cilium-cni",
    "mtu": 1450
}
" > /etc/cni/net.d/10-cilium-cni.conf'
```


#### Docker

Kubernetes should be compatible with the Docker 1.9.x - 1.12.x:

```
wget https://get.docker.com/builds/Linux/x86_64/docker-1.12.5.tgz
```

```
tar -xvf docker-1.12.5.tgz
```

```
sudo cp docker/docker* /usr/bin/
```

Create the Docker systemd unit file:


```
sudo sh -c 'echo "[Unit]
Description=Docker Application Container Engine
Documentation=http://docs.docker.io

[Service]
ExecStart=/usr/bin/docker daemon \\
  --iptables=false \\
  --ip-masq=false \\
  --host=unix:///var/run/docker.sock \\
  --log-level=error \\
  --storage-driver=overlay
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target" > /etc/systemd/system/docker.service'
```

```
sudo systemctl daemon-reload
sudo systemctl enable docker
sudo systemctl start docker
```

```
sudo docker version
```


#### kubelet

The Kubernetes kubelet no longer relies on docker networking for pods! The Kubelet can now use [CNI - the Container Network Interface](https://github.com/containernetworking/cni) to manage machine level networking requirements.

Download and install CNI plugins

```
sudo mkdir -p /opt/cni
```

```
wget https://storage.googleapis.com/kubernetes-release/network-plugins/cni-07a8a28637e97b22eb8dfe710eeae1344f69d16e.tar.gz
```

```
sudo tar -xvf cni-07a8a28637e97b22eb8dfe710eeae1344f69d16e.tar.gz -C /opt/cni
```


Download and install the Kubernetes worker binaries:

```
wget https://storage.googleapis.com/kubernetes-release/release/v1.5.1/bin/linux/amd64/kubectl
```
```
wget https://storage.googleapis.com/kubernetes-release/release/v1.5.1/bin/linux/amd64/kubelet
```

```
chmod +x kubectl kubelet
```

```
sudo mv kubectl kubelet /usr/bin/
```

```
sudo mkdir -p /var/lib/kubelet/
```

```
sudo sh -c 'echo "apiVersion: v1
kind: Config
clusters:
- cluster:
    certificate-authority: /var/lib/kubernetes/ca.pem
    server: https://172.16.0.10:6443
  name: kubernetes
contexts:
- context:
    cluster: kubernetes
    user: kubelet
  name: kubelet
current-context: kubelet
users:
- name: kubelet
  user:
    token: chAng3m3" > /var/lib/kubelet/kubeconfig'
```

Create the kubelet systemd unit file:

```
sudo sh -c 'cat > /etc/systemd/system/kubelet.service <<"EOF"
[Unit]
Description=Kubernetes Kubelet
Documentation=https://github.com/GoogleCloudPlatform/kubernetes
After=docker.service
Requires=docker.service

[Service]
ExecPre=/bin/mount bpffs /sys/fs/bpf -t bpf
ExecStart=/usr/bin/kubelet \
  --allow-privileged=true \
  --api-servers=https://172.16.0.10:6443,https://172.16.0.11:6443,https://172.16.0.12:6443 \
  --cloud-provider= \
  --make-iptables-util-chains=false \
  --cluster-dns=10.32.0.10 \
  --cluster-domain=cluster.local \
  --container-runtime=docker \
  --docker=unix:///var/run/docker.sock \
  --network-plugin=cni \
  --kubeconfig=/var/lib/kubelet/kubeconfig \
  --serialize-image-pulls=false \
  --tls-cert-file=/var/lib/kubernetes/kubernetes.pem \
  --tls-private-key-file=/var/lib/kubernetes/kubernetes-key.pem \
  --v=2

Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF'
```

```
sudo systemctl daemon-reload
sudo systemctl enable kubelet
sudo systemctl start kubelet
```

```
sudo systemctl status kubelet --no-pager
```

> Remember to run these steps on `worker0`, `worker1`, and `worker2`

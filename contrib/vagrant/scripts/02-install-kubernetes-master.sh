#!/usr/bin/env bash
#
# Installs, configures and starts kubernetes master, it will use default values
# from ./helpers.bash
# Globals:
#   INSTALL, if set installs k8s binaries, otherwise it will only configure k8s
#######################################

dir=$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )

source "${dir}/helpers.bash"

cache_dir="${dir}/../../../hack/cache"

k8s_cache_dir="${cache_dir}/k8s/${k8s_version}"

log "Installing kubernetes master components..."

certs_dir="${dir}/certs"

set -e

sudo mkdir -p /var/lib/kubernetes

cp "${certs_dir}/ca-k8s.pem" \
   "${certs_dir}/ca-kubelet.pem" \
   "${certs_dir}/k8s-controller-manager-key.pem" \
   "${certs_dir}/k8s-controller-manager.pem" \
   "${certs_dir}/k8s-scheduler-key.pem" \
   "${certs_dir}/k8s-scheduler.pem" \
   "${certs_dir}/ca-etcd.pem" \
   "${certs_dir}/etcd-k8s-api-server-key.pem" \
   "${certs_dir}/etcd-k8s-api-server.pem" \
   "${certs_dir}/k8s-api-server-key.pem" \
   "${certs_dir}/k8s-api-server.pem" \
   "${certs_dir}/kubelet-api-server-key.pem" \
   "${certs_dir}/kubelet-api-server.pem" \
   "${certs_dir}/k8s-controller-manager-sa.pem" \
   "${certs_dir}/k8s-controller-manager-sa-key.pem" \
   /var/lib/kubernetes

# Since k8s 1.11.0-beta.2, kube-apiserver stop receiving the flag `--tls-ca-file`
# Now we need to append the CA after the certificate
cat "${certs_dir}/ca-k8s.pem" >> "/var/lib/kubernetes/k8s-api-server.pem"

if [ -n "${INSTALL}" ]; then
    for component in kubectl kube-apiserver kube-controller-manager kube-scheduler; do
        download_to "${k8s_cache_dir}" "${component}" \
            "https://dl.k8s.io/release/${k8s_version}/bin/linux/amd64/${component}"

        cp "${k8s_cache_dir}/${component}" .
    done

    chmod +x kube-apiserver kube-controller-manager kube-scheduler kubectl

    sudo cp kube-apiserver kube-controller-manager kube-scheduler kubectl /usr/bin/
fi

sudo tee /etc/systemd/system/kube-apiserver.service <<EOF
[Unit]
Description=Kubernetes API Server
Documentation=https://kubernetes.io/docs/home

[Service]
ExecStart=/usr/bin/kube-apiserver \\
  --enable-admission-plugins=NamespaceLifecycle,LimitRanger,ServiceAccount,PersistentVolumeClaimResize,DefaultStorageClass,DefaultTolerationSeconds,MutatingAdmissionWebhook,ValidatingAdmissionWebhook,ResourceQuota,Priority \\
  --advertise-address=${controllers_ips[1]} \\
  --allow-privileged=true \\
  --authorization-mode=Node,RBAC \\
  --bind-address=0.0.0.0 \\
  --cert-dir=/var/run/kubernetes \\
  --client-ca-file='/var/lib/kubernetes/ca-k8s.pem' \\
  --etcd-cafile='/var/lib/kubernetes/ca-etcd.pem' \\
  --etcd-certfile='/var/lib/kubernetes/etcd-k8s-api-server.pem' \\
  --etcd-keyfile='/var/lib/kubernetes/etcd-k8s-api-server-key.pem' \\
  --etcd-servers=https://${controllers_ips[0]}:2379 \\
  --feature-gates=EndpointSliceTerminatingCondition=true \\
  --kubelet-certificate-authority='/var/lib/kubernetes/ca-kubelet.pem' \\
  --kubelet-client-certificate='/var/lib/kubernetes/k8s-api-server.pem' \\
  --kubelet-client-key='/var/lib/kubernetes/k8s-api-server-key.pem' \\
  --service-account-issuer='api' \\
  --service-account-signing-key-file='/var/lib/kubernetes/k8s-controller-manager-sa-key.pem' \\
  --service-account-key-file='/var/lib/kubernetes/k8s-controller-manager-sa-key.pem' \\
  --service-cluster-ip-range=${k8s_service_cluster_ip_range} \\
  --service-node-port-range=30000-32767 \\
  --tls-cert-file='/var/lib/kubernetes/k8s-api-server.pem' \\
  --tls-private-key-file='/var/lib/kubernetes/k8s-api-server-key.pem' \\
  --v=2
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable kube-apiserver
sudo systemctl restart kube-apiserver

sudo systemctl status kube-apiserver --no-pager

kubectl config set-cluster kubernetes \
    --certificate-authority=/var/lib/kubernetes/ca-k8s.pem \
    --embed-certs=true \
    --server=https://${controllers_ips[0]}:6443 \
    --kubeconfig=controller-manager.kubeconfig

kubectl config set-credentials controller-manager \
    --client-certificate=/var/lib/kubernetes/k8s-controller-manager.pem \
    --client-key=/var/lib/kubernetes/k8s-controller-manager-key.pem \
    --embed-certs=true \
    --kubeconfig=controller-manager.kubeconfig

kubectl config set-context default \
    --cluster=kubernetes \
    --user=controller-manager \
    --kubeconfig=controller-manager.kubeconfig

kubectl config use-context default \
    --kubeconfig=controller-manager.kubeconfig

sudo cp ./controller-manager.kubeconfig /var/lib/kubernetes/controller-manager.kubeconfig

sudo tee /etc/systemd/system/kube-controller-manager.service <<EOF
[Unit]
Description=Kubernetes Controller Manager
Documentation=https://kubernetes.io/docs/home

[Service]
ExecStart=/usr/bin/kube-controller-manager \\
  --allocate-node-cidrs=true \\
  --cluster-cidr=${k8s_cluster_cidr} \\
  --cluster-name=kubernetes \\
  --configure-cloud-routes=false \\
  --kubeconfig='/var/lib/kubernetes/controller-manager.kubeconfig' \\
  --leader-elect=true \\
  --node-cidr-mask-size-ipv4=${k8s_node_cidr_v4_mask_size} \\
  --node-cidr-mask-size-ipv6=${k8s_node_cidr_v6_mask_size} \\
  --use-service-account-credentials \\
  --service-account-private-key-file='/var/lib/kubernetes/k8s-controller-manager-sa-key.pem' \\
  --service-cluster-ip-range=${k8s_service_cluster_ip_range} \\
  --v=2
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable kube-controller-manager
sudo systemctl restart kube-controller-manager

sudo systemctl status kube-controller-manager --no-pager

kubectl config set-cluster kubernetes \
    --certificate-authority=/var/lib/kubernetes/ca-k8s.pem \
    --embed-certs=true \
    --server=https://${controllers_ips[0]}:6443 \
    --kubeconfig=scheduler.kubeconfig

kubectl config set-credentials scheduler \
    --client-certificate=/var/lib/kubernetes/k8s-scheduler.pem \
    --client-key=/var/lib/kubernetes/k8s-scheduler-key.pem \
    --embed-certs=true \
    --kubeconfig=scheduler.kubeconfig

kubectl config set-context default \
    --cluster=kubernetes \
    --user=scheduler \
    --kubeconfig=scheduler.kubeconfig

kubectl config use-context default \
    --kubeconfig=scheduler.kubeconfig

sudo cp ./scheduler.kubeconfig /var/lib/kubernetes/scheduler.kubeconfig

sudo tee /etc/systemd/system/kube-scheduler.service <<EOF
[Unit]
Description=Kubernetes Scheduler
Documentation=https://kubernetes.io/docs/home

[Service]
ExecStart=/usr/bin/kube-scheduler \\
  --kubeconfig='/var/lib/kubernetes/scheduler.kubeconfig' \\
  --v=2
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable kube-scheduler
sudo systemctl restart kube-scheduler

sudo systemctl status kube-scheduler --no-pager

log "Installing kubernetes master components... DONE!"

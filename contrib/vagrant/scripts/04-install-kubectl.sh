#!/usr/bin/env bash
#
# Installs and configures kubernetes kubectl, it will use default values from
# ./helpers.bash
# Globals:
#   INSTALL, if set installs k8s binaries, otherwise it will only configure k8s
#######################################

dir=$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )

source "${dir}/helpers.bash"

cache_dir="${dir}/../../../hack/cache/k8s/${k8s_version}"

log "Installing kubernetes kubectl..."

set -e

# Add aliases and bash completion for kubectl
cat <<EOF >> /home/vagrant/.bashrc
# kubectl
source <(kubectl completion bash)
alias k='kubectl'
complete -F __start_kubectl k
alias ks='kubectl -n kube-system'
complete -F __start_kubectl ks
alias wk='watch -n2 kubectl get pods -o wide'
alias wks='watch -n2 kubectl -n kube-system get pods -o wide'
alias wka='watch -n2 kubectl get all --all-namespaces -o wide'
cilium_pod() {
    kubectl -n kube-system get pods -l k8s-app=cilium \
            -o jsonpath="{.items[?(@.spec.nodeName == \"\$1\")].metadata.name}"
}
EOF

if [ -n "${INSTALL}" ]; then
    download_to "${cache_dir}" "kubectl" \
        "https://dl.k8s.io/release/${k8s_version}/bin/linux/amd64/kubectl"

    cp "${cache_dir}/kubectl" .

    chmod +x kubectl
    sudo mv kubectl /usr/local/bin
fi

certs_dir="${dir}/certs"

mkdir -p /home/vagrant/.kube/certs

cp "${certs_dir}/k8s-admin.pem" \
   "${certs_dir}/k8s-admin-key.pem" \
   "${certs_dir}/ca-k8s.pem" \
   /home/vagrant/.kube/certs

kubectl config set-cluster kubernetes-cilium \
    --certificate-authority=/home/vagrant/.kube/certs/ca-k8s.pem \
    --embed-certs=true \
    --server=https://${kubernetes_master}:6443

kubectl config set-credentials admin \
    --client-certificate=/home/vagrant/.kube/certs/k8s-admin.pem \
    --client-key=/home/vagrant/.kube/certs/k8s-admin-key.pem \
    --embed-certs=true

kubectl config set-context kubernetes-cilium \
    --cluster=kubernetes-cilium \
    --user=admin

kubectl config use-context kubernetes-cilium

sudo cp /root/.kube/config /home/vagrant/.kube/config

sudo chmod 755 /home/vagrant/.kube/config

sudo chown vagrant.vagrant -R /home/vagrant/.kube

until kubectl get services
do
log "Waiting for kubectl to connect to api-server"
sleep 1s
done

kubectl get nodes

log "Installing kubernetes kubectl... DONE!"

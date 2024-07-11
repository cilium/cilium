#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright Authors of Cilium

# See also Documentation/contributing/testing/e2e_legacy.rst for reference

set -o errexit
set -o pipefail
set -o nounset

ginkgo_matrix_yaml=".github/actions/ginkgo/main-k8s-versions.yaml"

check_cmd() {
    for cmd in "$@"; do
        if ! (command -v "$cmd" >/dev/null); then
            return 1
        fi
    done
    return 0
}

check_cmd_or_fail() {
    for cmd in "$@"; do
        if ! (command -v "$cmd" >/dev/null); then
            echo "Error: $cmd not found."
            exit 1
        fi
    done
}

usage() {
    echo "Usage: $0 [options]"
    echo "Options:"
    echo "  -k <version>        [mandatory] Kubernetes version to use"
    echo "  -l <version>        [optional]  Linux kernel version to use, default: derived from Kubernetes version"
    echo "  -c <sha>            [optional]  Cilium commit to use to fetch the images, default: current commit SHA"
    echo "  -f <focus string>   [optional]  Ginkgo focus string to use, default: 'K8s'"
    echo "  -t <directory>      [optional]  temporary directory to store images, default: '/tmp'"
    echo "  -w                  [optional]  assume VM image is available, just wake it up"
    echo "  -s                  [optional]  skip straight to tests (do not set up VM or provision Kind)"
    echo "  -h                  [optional]  show this help message"
    exit "$1"
}

report() {
    printf '\033[1;34m%s\033[0m\n' "$*"
}

install_helm() {
    local HELM_VERSION=3.7.0

    pushd "${tmpdir}" >/dev/null
    wget "https://get.helm.sh/helm-v${HELM_VERSION}-linux-amd64.tar.gz"
    tar -xf "helm-v${HELM_VERSION}-linux-amd64.tar.gz"
    mv linux-amd64/helm ./helm
    popd >/dev/null
}

install_ginkgo() {
    go install github.com/onsi/ginkgo/ginkgo@v1.16.5
}

get_kernel_tag_from_k8s() {
    local k8s_version="${1}"

    ${yq} ".include[] | select(.k8s-version == \"${k8s_version}\").kernel" "${ginkgo_matrix_yaml}"
}

get_k8s_image_from_version() {
    local k8s_version="${1}"

    ${yq} ".include[] | select(.k8s-version == \"${k8s_version}\").kube-image" "${ginkgo_matrix_yaml}"
}

get_kernel_tag_from_kernel() {
    local kernel_version="${1}"

    ${yq} "[ .include[] | select(.kernel | test(\"^${kernel_version}-\")).kernel ][0]" "${ginkgo_matrix_yaml}"
}

build_tests() {
    pushd "${root_dir}/test" >/dev/null
    ginkgo build
    popd >/dev/null
}

retrieve_image() {
    local kernel_tag="$1"

    mkdir -p "${tmpdir}/_images"
    docker run -v "${tmpdir}/_images:/mnt/images" \
        "quay.io/lvh-images/kind:${kernel_tag}" \
        cp -r /data/images/. /mnt/images/
    zstd -f -d "${tmpdir}"/_images/kind_*.qcow2.zst \
        -o "${tmpdir}/_images/datapath-conformance.qcow2"
}

provision_vm() {
    qemu-system-x86_64 \
        -nodefaults \
        -no-reboot \
        -smp 4 \
        -m 12G \
        -enable-kvm \
        -cpu host \
        -hda "${tmpdir}/_images/datapath-conformance.qcow2" \
        -netdev user,id=user.0,hostfwd=tcp::2222-:22 \
        -device virtio-net-pci,netdev=user.0 \
        -fsdev local,id=host_id,path=./,security_model=none \
        -device virtio-9p-pci,fsdev=host_id,mount_tag=host_mount \
        -display none \
        -daemonize
}

wait_for_ssh() {
    local retries=0

    while ! (${connect} true); do
        if [[ "${retries}" -gt 30 ]]; then
            echo "SSH connection failed after 30 retries"
            exit 1
        fi
        retries=$((retries + 1))
        sleep 1
    done
}

install_vm_dep() {
    ${connect} "echo 'nameserver 8.8.8.8' > /etc/resolv.conf"
    ${connect} git config --global --add safe.directory /host
    ${connect} cp /host/helm /usr/bin
}

provision_kind() {
    local kernel_tag="$1" kubernetes_image="$2" ip_family="$3"

    if [[ "${kernel_tag}" == 6.6-* ]]; then
        ${connect} "cd /host; ./contrib/scripts/kind.sh '' 2 '' ${kubernetes_image} none ${ip_family}"
        ${connect} kubectl label node kind-worker2 cilium.io/ci-node=kind-worker2
        ${connect} kubectl label node kind-worker2 node-role.kubernetes.io/controlplane=

    else
        ${connect} "cd /host; ./contrib/scripts/kind.sh '' 1 '' ${kubernetes_image} iptables ${ip_family}"
    fi
    ${connect} mkdir -p /home/vagrant/go/src/github.com/cilium
    ${connect} ln -s /host /home/vagrant/go/src/github.com/cilium/cilium
    ${connect} git config --global --add safe.directory /cilium
}

run_tests() {
    local K8S_VERSION="$1" kernel_tag="$2" cli_focus="$3" commit_sha="$4" quay_org
    local K8S_NODES=2
    local NETNEXT=0
    local KERNEL=""
    local KUBEPROXY=1
    local NO_CILIUM_ON_NODES=""

    case "${kernel_tag}" in
        6.6-*)
            K8S_NODES=3
            NETNEXT=1
            KERNEL=net-next
            KUBEPROXY=0
            NO_CILIUM_ON_NODES=kind-worker2
            ;;
        5.4-*)
            KERNEL=54
            ;;
        *)
            usage 1
            ;;
    esac

    if [[ -z "${commit_sha}" ]]; then
        commit_sha="$(git rev-parse HEAD)"
    fi
    quay_org="cilium"

    # Let's run the tests.
    #
    # GitHub actions do not support IPv6 connectivity to outside world. If the
    # infrastructure environment supports it, then CILIUM_NO_IPV6_OUTSIDE can
    # be removed
    ${connect} -t "cd /host/test; \
        K8S_VERSION=${K8S_VERSION} \
        K8S_NODES=${K8S_NODES} \
        NETNEXT=${NETNEXT} \
        KERNEL=${KERNEL} \
        KUBEPROXY=${KUBEPROXY} \
        NO_CILIUM_ON_NODES=${NO_CILIUM_ON_NODES} \
        CNI_INTEGRATION=kind \
        INTEGRATION_TESTS=true \
        CILIUM_NO_IPV6_OUTSIDE=true \
        ./test.test \
            --ginkgo.focus=\"${cli_focus}\" \
            --ginkgo.skip= \
            --ginkgo.seed=1679952881 \
            --ginkgo.v -- \
            -cilium.provision=false \
            -cilium.image=quay.io/${quay_org}/cilium-ci \
            -cilium.tag=${commit_sha}  \
            -cilium.operator-image=quay.io/${quay_org}/operator \
            -cilium.operator-tag=${commit_sha} \
            -cilium.hubble-relay-image=quay.io/${quay_org}/hubble-relay-ci \
            -cilium.hubble-relay-tag=${commit_sha} \
            -cilium.kubeconfig=/root/.kube/config \
            -cilium.provision-k8s=false \
            -cilium.operator-suffix=-ci \
            -cilium.holdEnvironment=true"
}

# Parse options

commit_sha=""
cli_focus="K8s"
kernel_version=""
k8s_version=""
skip_to_tests=""
tmpdir="/tmp"
wakeup_vm=""
OPTIND=1
while getopts "c:f:hl:k:st:w" opt; do
    case "$opt" in
        c)
            commit_sha="${OPTARG}"
            ;;
        f)
            cli_focus="${OPTARG}"
            ;;
        h)
            usage 0
            ;;
        l)
            kernel_version="${OPTARG}"
            ;;
        k)
            k8s_version="${OPTARG}"
            ;;
        s)
            skip_to_tests=true
            ;;
        t)
            tmpdir="${OPTARG}"
            ;;
        w)
            wakeup_vm=true
            ;;
        *)
            usage 1
            ;;
    esac
done
shift $((OPTIND-1))

# Local dependencies

check_cmd_or_fail docker git qemu-system-x86_64 zstd
root_dir="$(git rev-parse --show-toplevel)"

helm="helm"
if ! check_cmd "${helm}"; then
    install_helm
    helm="${tmpdir}/helm"
fi

if ! check_cmd ginkgo; then
    install_ginkgo
fi

yq="docker run --rm -v ${PWD}:/workdir --user $(id -u):$(id -g) mikefarah/yq:4.27.3"

# Retrieve kernel and kubernetes image tags

if [[ -z "${k8s_version}" ]]; then
    usage 1
fi
kubernetes_image="$(get_k8s_image_from_version "${k8s_version}")"

kernel_tag=""
if [[ -n "${kernel_version}" ]]; then
    kernel_tag="$(get_kernel_tag_from_kernel "${kernel_version}")"
else
    kernel_tag="$(get_kernel_tag_from_k8s "${k8s_version}")"
fi

ip_family=""
case "${k8s_version}" in
    1.19)
        ip_family="ipv4"
        ;;
    *)
        ip_family="dual"
        ;;
esac

connect="ssh -p 2222 -o StrictHostKeyChecking=no root@localhost"

# Let's go!

if [[ -z "${skip_to_tests}" ]]; then
    report "Building tests"
    build_tests

    if [[ -z "${wakeup_vm}" ]]; then
        report "Retrieving disk image"
        retrieve_image "${kernel_tag}"
    fi

    report "Provisioning VM"
    provision_vm
    report "... QEMU VM launched, 'pkill qemu-system-x86' to clean up."

    report "Waiting for SSH to be available"
    wait_for_ssh

    if [[ -z "${wakeup_vm}" ]]; then
        report "Installing dependencies in VM"
        install_vm_dep

        report "Provisioning Kind cluster"
        provision_kind "${kernel_tag}" "${kubernetes_image}" "${ip_family}"
    fi
fi

report "Running tests"
run_tests "${k8s_version}" "${kernel_tag}" "${cli_focus}" "${commit_sha}"
report "All done! But I left the VM running."
report "    Run 'pkill qemu-system-x86' to clean up,"
report "    or re-run this script with '-s' to reuse the setup"

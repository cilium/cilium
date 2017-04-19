#!/usr/bin/env bash

dir=$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )

# Master's IPv4 address. Workers' IPv4 address will have their IP incremented by
# 1. The netmask used will be /24
export 'MASTER_IPV4'=${MASTER_IPV4:-"192.168.33.11"}
# NFS address is only set if NFS option is active. This will create a new
# network interface for each VM with starting on this IP. This IP will be
# available to reach from the host.
export 'MASTER_IPV4_NFS'=${MASTER_IPV4_NFS:-"192.168.34.11"}
# Enable IPv4 mode. It's enabled by default since it's required for several
# runtime tests.
export 'IPV4'=${IPV4:-1}
# Exposed IPv6 node CIDR, only set if IPV4 is disabled. Each node will be setup
# with a IPv6 network available from the host with $IPV6_PUBLIC_CIDR +
# 6to4($MASTER_IPV4). For IPv4 "192.168.33.11" we will have for example:
#   master  : FD00::B/16
#   worker 1: FD00::C/16
# The netmask used will be /16
export 'IPV6_PUBLIC_CIDR'=${IPV4+"FD00::"}
# Internal IPv6 node CIDR, always set up by default. Each node will be setup
# with a IPv6 network available from the host with IPV6_INTERNAL_CIDR +
# 6to4($MASTER_IPV4). For IPv4 "192.168.33.11" we will have for example:
#   master  : FD01::B/16
#   worker 1: FD01::C/16
# The netmask used will be /16
export 'IPV6_INTERNAL_CIDR'=${IPV4+"FD01::"}
# Cilium IPv6 node CIDR. Each node will be setup with IPv6 network of
# $CILIUM_IPV6_NODE_CIDR + 6to4($MASTER_IPV4). For IPv4 "192.168.33.11" we will
# have for example:
#   master  : FD02::C0A8:210B:0:0/96
#   worker 1: FD02::C0A8:210C:0:0/96
export 'CILIUM_IPV6_NODE_CIDR'=${CILIUM_IPV6_NODE_CIDR:-"FD02::"}
# VM memory
export 'VM_MEMORY'=${MEMORY:-3072}
# Number of CPUs
export 'VM_CPUS'=${CPUS:-2}
# K8STAG tag is only set if K8S option is active
export 'K8STAG'=${K8S+"-k8s"}
# Set VAGRANT_DEFAULT_PROVIDER to virtualbox
export 'VAGRANT_DEFAULT_PROVIDER'=${VAGRANT_DEFAULT_PROVIDER:-"virtualbox"}
# Sets the default cilium TUNNEL_MODE to "vxlan"
export 'TUNNEL_MODE_STRING'=${TUNNEL_MODE_STRING:-"-t vxlan"}
# Replies Yes to all prompts asked in this script
export 'YES_TO_ALL'=${YES_TO_ALL:-"0"}

# Internal variables used in the Vagrantfile
export 'CILIUM_SCRIPT'=true
# Sets the directory where the temporary setup scripts are created
export 'CILIUM_TEMP'="${dir}"

# split_ipv4 splits an IPv4 address into a bash array and assigns it to ${1}.
# Exits if ${2} is an invalid IPv4 address.
function split_ipv4(){
    IFS='.' read -r -a ipv4_array <<< "${2}"
    eval "${1}=( ${ipv4_array[@]} )"
    if [[ "${#ipv4_array[@]}" -ne 4 ]]; then
        echo "Invalid IPv4 address: ${2}"
        exit 1
    fi
}

# get_cilium_node_addr sets the cilium node address in ${1} for the IPv4 address
# in ${2}.
function get_cilium_node_addr(){
    split_ipv4 ipv4_array "${2}"
    hexIPv4=$(printf "%02X%02X:%02X%02X" "${ipv4_array[0]}" "${ipv4_array[1]}" "${ipv4_array[2]}" "${ipv4_array[3]}")
    eval "${1}=${CILIUM_IPV6_NODE_CIDR}${hexIPv4}:0:0"
}

# write_netcfg_header creates the file in ${3} and writes the internal network
# configuration for the vm IP ${1}. Sets the master's hostname with IPv6 address
# in ${2}.
function write_netcfg_header(){
    vm_ipv6="${1}"
    master_ipv6="${2}"
    filename="${3}"
    cat <<EOF > "${filename}"
#!/usr/bin/env bash
# Use of IPv6 'documentation block' to provide example
if [ -n "\$(grep DISTRIB_RELEASE=14.04 /etc/lsb-release)" ]; then
    ip -6 a a ${vm_ipv6}/16 dev eth1
else
    ip -6 a a ${vm_ipv6}/16 dev enp0s8
fi

echo '${master_ipv6} cilium${K8STAG}-master' >> /etc/hosts
    export 'TUNNEL_MODE_STRING'="--tunnel vxlan"

EOF
}

# write_master_route writes the cilium IPv4 and IPv6 routes for master in ${6}.
# Uses the IPv4 suffix in ${1} for the IPv4 route and cilium IPv6 in ${2} via
# ${3} for the IPv6 route. Sets the worker's hostname based on the index defined
# in ${4} with the IPv6 defined in ${5}.
function write_master_route(){
    master_ipv4_suffix="${1}"
    master_cilium_ipv6="${2}"
    master_ipv6="${3}"
    node_index="${4}"
    worker_ipv6="${5}"
    filename="${6}"
    cat <<EOF >> "${filename}"
# Master route
if [ -n "\$(grep DISTRIB_RELEASE=14.04 /etc/lsb-release)" ]; then
    ip r a 10.${master_ipv4_suffix}.0.1/32 dev eth1
    ip r a 10.${master_ipv4_suffix}.0.0/16 via 10.${master_ipv4_suffix}.0.1
else
    ip r a 10.${master_ipv4_suffix}.0.1/32 dev enp0s8
    ip r a 10.${master_ipv4_suffix}.0.0/16 via 10.${master_ipv4_suffix}.0.1
fi

ip -6 r a ${master_cilium_ipv6}/96 via ${master_ipv6}
echo "${worker_ipv6} cilium${K8STAG}-node-${node_index}" >> /etc/hosts

EOF
}

# write_nodes_routes writes in file ${3} the routes for all nodes in the
# clusters except for node with index ${1}. All routes will be based on IPv4
# defined in ${2}.
function write_nodes_routes(){
    node_index="${1}"
    base_ipv4_addr="${2}"
    filename="${3}"
    cat <<EOF >> "${filename}"
# Node's routes
EOF
    split_ipv4 ipv4_array "${base_ipv4_addr}"
    local i
    local index=1
    for i in `seq $(( ipv4_array[3] + 1 )) $(( ipv4_array[3] + NWORKERS ))`; do
        index=$(( index + 1 ))
        hexIPv4=$(printf "%02X%02X:%02X%02X" "${ipv4_array[0]}" "${ipv4_array[1]}" "${ipv4_array[2]}" "${i}")
        if [ "${node_index}" -eq "${index}" ]; then
            continue
        fi
        worker_internal_ipv6=${IPV6_INTERNAL_CIDR}$(printf "%02X" "${i}")

        cat <<EOF >> "${filename}"
if [ -n "\$(grep DISTRIB_RELEASE=14.04 /etc/lsb-release)" ]; then
    ip r a 10.${i}.0.1/32 dev eth1
else
    ip r a 10.${i}.0.1/32 dev enp0s8
fi

ip -6 r a ${CILIUM_IPV6_NODE_CIDR}${hexIPv4}:0:0/96 via ${worker_internal_ipv6}
echo "${worker_internal_ipv6} cilium${K8STAG}-node-${index}" >> /etc/hosts
EOF
    done

    cat <<EOF >> "${filename}"

EOF
}

# write_k8s_header create the file in ${2} and writes the k8s configuration.
# Sets up the k8s temporary directory inside the VM with ${1}.
function write_k8s_header(){
    k8s_dir="${1}"
    filename="${2}"
    cat <<EOF > "${filename}"
#!/usr/bin/env bash
# K8s installation
sudo apt-get -y install curl
mkdir -p "${k8s_dir}"
cd "${k8s_dir}"

EOF
}

# write_install_nsenter writes the dependencies and installation for nsenter in
# ${1}.
function write_install_nsenter(){
    filename="${1}"
    cat <<EOF >> "${filename}"
#Install nsenter
sudo apt-get -y install libncurses5-dev libslang2-dev gettext \
zlib1g-dev libselinux1-dev debhelper lsb-release pkg-config \
po-debconf autoconf automake autopoint libtool
wget -nv https://www.kernel.org/pub/linux/utils/util-linux/v2.24/util-linux-2.24.1.tar.gz
tar -xvzf util-linux-2.24.1.tar.gz
cd util-linux-2.24.1
./autogen.sh
./configure --without-python --disable-all-programs --enable-nsenter
make nsenter
sudo cp nsenter /usr/bin

EOF
}

# write_k8s_install writes the k8s installation first half in ${2} and the
# second half in ${3}. Changes the k8s temporary directory inside the VM,
# defined in ${1}, owner and group to vagrant.
function write_k8s_install() {
    k8s_dir="${1}"
    filename="${2}"
    filename_2nd_half="${3}"
    if [[ -n "${IPV6_EXT}" ]]; then
        split_ipv4 ipv4_array "${MASTER_IPV4}"
        hexIPv4=$(printf "%d.%d.0.0" "${ipv4_array[0]}" "${ipv4_array[1]}")
        get_cilium_node_addr k8s_cluster_cidr "${hexIPv4}"
        k8s_cluster_cidr+="/96"
        k8s_node_cidr_mask_size="112"
        k8s_service_cluster_ip_range="FD03::/112"
        k8s_cluster_dns_ip="FD03::A"
    fi
    k8s_cluster_cidr=${k8s_cluster_cidr:-"10.0.0.0/10"}
    k8s_node_cidr_mask_size=${k8s_node_cidr_mask_size:-"16"}
    k8s_service_cluster_ip_range=${k8s_service_cluster_ip_range:-"172.20.0.0/24"}
    k8s_cluster_dns_ip=${k8s_cluster_dns_ip:-"172.20.0.10"}

    cat <<EOF >> "${filename}"
# K8s
k8s_path="/home/vagrant/go/src/github.com/cilium/cilium/examples/kubernetes/scripts"
export IPV6_EXT="${IPV6_EXT}"
export K8S_CLUSTER_CIDR="${k8s_cluster_cidr}"
export K8S_NODE_CDIR_MASK_SIZE="${k8s_node_cidr_mask_size}"
export K8S_SERVICE_CLUSTER_IP_RANGE="${k8s_service_cluster_ip_range}"
export K8S_CLUSTER_DNS_IP="${k8s_cluster_dns_ip}"
if [[ "\$(hostname)" -eq "cilium${K8STAG}-master" ]]; then
    "\${k8s_path}/03-2-run-inside-vms-etcd.sh"
    "\${k8s_path}/04-2-run-inside-vms-kubernetes-controller.sh"
fi
# All nodes are a kubernetes worker
"\${k8s_path}/05-2-run-inside-vms-kubernetes-worker.sh"
INSTALL=1 "\${k8s_path}/06-kubectl.sh"
chown vagrant.vagrant -R "${k8s_dir}"

EOF

    cat <<EOF > "${filename_2nd_half}"
#!/usr/bin/env bash
# K8s installation 2nd half
k8s_path="/home/vagrant/go/src/github.com/cilium/cilium/examples/kubernetes/scripts"
export IPV6_EXT="${IPV6_EXT}"
export K8S_CLUSTER_CIDR="${k8s_cluster_cidr}"
export K8S_NODE_CDIR_MASK_SIZE="${k8s_node_cidr_mask_size}"
export K8S_SERVICE_CLUSTER_IP_RANGE="${k8s_service_cluster_ip_range}"
export K8S_CLUSTER_DNS_IP="${k8s_cluster_dns_ip}"

cd "${k8s_dir}"
"\${k8s_path}/08-cilium.sh"
if [[ "\$(hostname)" -eq "cilium${K8STAG}-master" ]]; then
    "\${k8s_path}/09-dns-addon.sh"
else
    "\${k8s_path}/06-kubectl.sh"
fi
EOF
}

function write_cilium_cfg() {
    node_index="${1}"
    master_ipv4_suffix="${2}"
    ipv6_addr="${3}"
    filename="${4}"

    cilium_options="-n ${ipv6_addr}"

    if [[ "${IPV4}" -eq "1" ]]; then
        cilium_options+=" --ipv4-range 10.${master_ipv4_suffix}.0.1"
    else
        cilium_options+=" --disable-ipv4"
    fi

    if [ -n "${K8S}" ]; then
        cilium_options+=" --k8s-api-server http://${MASTER_IPV4}:8080"
        cilium_options+=" --etcd-config-path /var/lib/cilium/etcd-config.yml"
        cilium_options+=" --kvstore etcd"
    else
        if [[ "${IPV4}" -eq "1" ]]; then
            cilium_options+=" --consul ${MASTER_IPV4}:8500"
        else
            cilium_options+=" --consul [${ipv6_addr}]:8500"
        fi
        cilium_options+=" --kvstore consul"
    fi

    if [ "$LB" = 1 ]; then
        # The LB interface needs to be the "exposed" to the host
        # interface only for master node.
        if [ $((node_index)) -eq 1 ]; then
            ubuntu_1404_interface="-d eth2"
            ubuntu_1604_interface="-d enp0s9"
            ubuntu_1404_cilium_lb="--lb eth2"
            ubuntu_1604_cilium_lb="--lb enp0s9"
        else
            ubuntu_1404_interface="-d eth1"
            ubuntu_1604_interface="-d enp0s8"
            ubuntu_1404_cilium_lb=""
            ubuntu_1604_cilium_lb=""
        fi
    else
        cilium_options+=" ${TUNNEL_MODE_STRING}"
    fi

cat <<EOF >> "$filename"
sleep 2s
if [ -n "\$(grep DISTRIB_RELEASE=14.04 /etc/lsb-release)" ]; then
    sed -i '/exec/d' /etc/init/cilium.conf
    echo 'exec cilium-agent --debug ${ubuntu_1404_cilium_lb} ${ubuntu_1404_interface} ${cilium_options}' >> /etc/init/cilium.conf
else
    sed -i '9s+.*+ExecStart=/usr/bin/cilium-agent --debug \$CILIUM_OPTS+' /lib/systemd/system/cilium.service
    echo 'CILIUM_OPTS="${ubuntu_1604_cilium_lb} ${ubuntu_1604_interface} ${cilium_options}"' >> /etc/sysconfig/cilium
    echo 'PATH=/usr/local/clang/bin:/usr/local/sbin:/usr/local/bin:/usr/bin:/usr/sbin:/sbin:/bin' >> /etc/sysconfig/cilium
    chmod 644 /etc/sysconfig/cilium
fi

service cilium restart

cilium_started=false

for ((i = 0 ; i < 24; i++)); do
    if cilium status > /dev/null 2>&1; then
        cilium_started=true
        break
    fi
    sleep 5s
    echo "Waiting for Cilium daemon to come up..."
done

if [ "\$cilium_started" = true ] ; then
    echo 'Cilium successfully started!'
else
    >&2 echo 'Timeout waiting for Cilium to start...'
fi
EOF
}

function create_master(){
    split_ipv4 ipv4_array "${MASTER_IPV4}"
    get_cilium_node_addr master_cilium_ipv6 "${MASTER_IPV4}"
    output_file="${dir}/cilium-master.sh"
    write_netcfg_header "${MASTER_IPV6}" "${MASTER_IPV6}" "${output_file}"

    if [ -n "${NWORKERS}" ]; then
        write_nodes_routes 1 "${MASTER_IPV4}" "${output_file}"
    fi

    write_cilium_cfg 1 "${ipv4_array[3]}" "${master_cilium_ipv6}" "${output_file}"
}

function create_workers(){
    split_ipv4 ipv4_array "${MASTER_IPV4}"
    get_cilium_node_addr master_cilium_ipv6 "${MASTER_IPV4}"
    base_workers_ip=$(printf "%d.%d.%d." "${ipv4_array[0]}" "${ipv4_array[1]}" "${ipv4_array[2]}")
    if [ -n "${NWORKERS}" ]; then
        for i in `seq 2 $(( NWORKERS + 1 ))`; do
            output_file="${dir}/node-start-${i}.sh"
            worker_ip_suffix=$(( ipv4_array[3] + i - 1 ))
            worker_ipv6=${IPV6_INTERNAL_CIDR}$(printf '%02X' ${worker_ip_suffix})
            worker_host_ipv6=${IPV6_PUBLIC_CIDR}$(printf '%02X' ${worker_ip_suffix})
            ipv6_public_workers_addrs+=(${worker_host_ipv6})

            write_netcfg_header "${worker_ipv6}" "${MASTER_IPV6}" "${output_file}"

            write_master_route "${ipv4_array[3]}" "${master_cilium_ipv6}" \
                "${MASTER_IPV6}" "${i}" "${worker_ipv6}" "${output_file}"

            write_nodes_routes "${i}" ${MASTER_IPV4} "${output_file}"

            worker_cilium_ipv4="${base_workers_ip}${worker_ip_suffix}"
            get_cilium_node_addr worker_cilium_ipv6 "${worker_cilium_ipv4}"
            write_cilium_cfg "${i}" "${worker_ip_suffix}" "${worker_cilium_ipv6}" "${output_file}"
        done
    fi
}

# create_k8s_config creates k8s config
function create_k8s_config(){
    if [ -n "${K8S}" ]; then
        k8s_temp_dir="/home/vagrant/k8s"
        output_file="${dir}/cilium-k8s-install-1st-part.sh"
        output_2nd_file="${dir}/cilium-k8s-install-2nd-part.sh"
        write_k8s_header "${k8s_temp_dir}" "${output_file}"
        write_install_nsenter "${output_file}"
        write_k8s_install "${k8s_temp_dir}" "${output_file}" "${output_2nd_file}"
    fi
}

# set_vagrant_env sets up Vagrantfile environment variables
function set_vagrant_env(){
    split_ipv4 ipv4_array "${MASTER_IPV4}"
    export 'IPV4_BASE_ADDR'="$(printf "%d.%d.%d." "${ipv4_array[0]}" "${ipv4_array[1]}" "${ipv4_array[2]}")"
    export 'FIRST_IP_SUFFIX'="${ipv4_array[3]}"
    export 'MASTER_IPV6_PUBLIC'="${IPV6_PUBLIC_CIDR}$(printf '%02X' ${ipv4_array[3]})"

    split_ipv4 ipv4_array_nfs "${MASTER_IPV4_NFS}"
    export 'IPV4_BASE_ADDR_NFS'="$(printf "%d.%d.%d." "${ipv4_array_nfs[0]}" "${ipv4_array_nfs[1]}" "${ipv4_array_nfs[2]}")"
    export 'FIRST_IP_SUFFIX_NFS'="${ipv4_array[3]}"
    if [[ -n "${NFS}" ]]; then
        echo "# NFS enabled. don't forget to enable this ports on your host"
        echo "# before starting the VMs in order to have nfs working"
        echo "# iptables -I INPUT -p udp -s ${IPV4_BASE_ADDR_NFS}0/24 --dport 111 -j ACCEPT"
        echo "# iptables -I INPUT -p udp -s ${IPV4_BASE_ADDR_NFS}0/24 --dport 2049 -j ACCEPT"
        echo "# iptables -I INPUT -p udp -s ${IPV4_BASE_ADDR_NFS}0/24 --dport 20048 -j ACCEPT"
    fi

    temp=$(printf " %s" "${ipv6_public_workers_addrs[@]}")
    export 'IPV6_PUBLIC_WORKERS_ADDRS'="${temp:1}"
    if [[ "${IPV4}" -ne "1" ]]; then
        export 'IPV6_EXT'=1
    fi
}

# vboxnet_create_new_interface creates a new host only network interface with
# VBoxManage utility. Returns the created interface name in ${1}.
function vboxnet_create_new_interface(){
    output=$(VBoxManage hostonlyif create)
    vboxnet_interface=$(echo "${output}" | grep -oE "'[a-zA-Z0-9]+'" | sed "s/'//g")
    if [ -z "${vboxnet_interface}" ]; then
        echo "Unable create VBox hostonly interface:"
        echo "${output}"
        return
    fi
    eval "${1}=${vboxnet_interface}"
}

# vboxnet_add_ipv6 adds the IPv6 in ${2} with the netmask length in ${3} in the
# hostonly network interface set in ${1}.
function vboxnet_add_ipv6(){
    vboxnetif="${1}"
    ipv6="${2}"
    ipv6_mask="${3}"
    VBoxManage hostonlyif ipconfig "${vboxnetif}" \
        --ipv6 "${ipv6}" --netmasklengthv6 "${ipv6_mask}"
}

# vboxnet_add_ipv4 adds the IPv4 in ${2} with the netmask in ${3} in the
# hostonly network interface set in ${1}.
function vboxnet_add_ipv4(){
    vboxnetif="${1}"
    ipv4="${2}"
    ipv4_mask="${3}"
    VBoxManage hostonlyif ipconfig "${vboxnetif}" \
        --ip "${ipv4}" --netmask "${ipv4_mask}"
}

# vboxnet_addr_finder checks if any vboxnet interface has the IPv6 public CIDR
function vboxnet_addr_finder(){
    if [ -z "${IPV6_EXT}" ] && [ -z "${NFS}" ]; then
        return
    fi
    all_vbox_interfaces=$(VBoxManage list hostonlyifs | grep -E "^Name|IPV6Address|IPV6NetworkMaskPrefixLength" | awk -F" " '{print $2}')
    # all_vbox_interfaces format example:
    # vboxnet0
    # fd00:0000:0000:0000:0000:0000:0000:0001
    # 64
    # vboxnet1
    # fd05:0000:0000:0000:0000:0000:0000:0001
    # 16
    all_ipv6=$(echo "${all_vbox_interfaces}" | awk 'NR % 3 == 2')
    line_ip=0
    if [[ -n "${all_vbox_interfaces}" ]]; then
        while read -r ip; do
            line_ip=$(( $line_ip + 1 ))
            if [ ! -z $(echo "${ip}" | grep -i "${IPV6_PUBLIC_CIDR::-1}") ]; then
                found=${line_ip}
                net_mask=$(echo "${all_vbox_interfaces}" | awk "NR == 3 * ${line_ip}")
                vboxnetname=$(echo "${all_vbox_interfaces}" | awk "NR == 3 * ${line_ip} - 2")
                break
            fi
        done <<< "${all_ipv6}"
    fi
    if [[ -z "${found}" ]]; then
        echo "WARN: VirtualBox interface with \"${IPV6_PUBLIC_CIDR}\" not found"
        if [ ${YES_TO_ALL} -eq "0" ]; then
            read -r -p "Create a new VBox hostonly network interface? [y/N] " response
        else
            response="Y"
        fi
        case "${response}" in
            [yY])
                echo "Creating VBox hostonly network..."
            ;;
            *)
                exit
            ;;
        esac
        vboxnet_create_new_interface vboxnetname
        if [ -z "${vboxnet_interface}" ]; then
            exit 1
        fi
    elif [[ "${net_mask}" -ne 16 ]]; then
        echo "WARN: VirtualBox interface with \"${IPV6_PUBLIC_CIDR}\" found in ${vboxnetname}"
        echo "but set wrong network mask (64 instead of 16)"
        if [ ${YES_TO_ALL} -eq "0" ]; then
            read -r -p "Change network mask of '${vboxnetname}' to 16? [y/N] " response
        else
            response="Y"
        fi
        case "${response}" in
            [yY])
                echo "Changing network mask to 16..."
            ;;
            *)
                exit
            ;;
        esac
    fi
    split_ipv4 ipv4_array_nfs "${MASTER_IPV4_NFS}"
    IPV4_BASE_ADDR_NFS="$(printf "%d.%d.%d.1" "${ipv4_array_nfs[0]}" "${ipv4_array_nfs[1]}" "${ipv4_array_nfs[2]}")"
    vboxnet_add_ipv6 "${vboxnetname}" "${IPV6_PUBLIC_CIDR}1" 16
    vboxnet_add_ipv4 "${vboxnetname}" "${IPV4_BASE_ADDR_NFS}" "255.255.255.0"
}

if [[ "${VAGRANT_DEFAULT_PROVIDER}" -eq "virtualbox" ]]; then
     vboxnet_addr_finder
fi

ipv6_public_workers_addrs=()

split_ipv4 ipv4_array "${MASTER_IPV4}"
MASTER_IPV6="${IPV6_INTERNAL_CIDR}$(printf '%02X' ${ipv4_array[3]})"

create_master
create_workers
set_vagrant_env
create_k8s_config

cd "${dir}/../.."

if [ -n "${RELOAD}" ]; then
    vagrant reload
else
    vagrant up
fi

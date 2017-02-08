#!/usr/bin/env bash

dir=$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )

# Master's IPv4 address. Workers' IPv4 address will have their IP incremented by
# 1. The netmask used will be /24
export 'MASTER_IPV4'=${MASTER_IPV4:-"192.168.33.11"}
# NFS address is only set if NFS option is active. This will create a new
# network interface for each VM with starting on this IP. This IP will be
# available to reach from the host.
export 'MASTER_IPV4_NFS'=${NFS+"192.168.34.11"}
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
export 'VM_MEMORY'=${MEMORY:-2048}
# Number of CPUs
export 'VM_CPUS'=${CPUS:-2}
# K8STAG tag is only set if K8S option is active
export 'K8STAG'=${K8S+"-k8s"}
# Set VAGRANT_DEFAULT_PROVIDER to virtualbox
export 'VAGRANT_DEFAULT_PROVIDER'=${VAGRANT_DEFAULT_PROVIDER:-"virtualbox"}
# Sets the default cilium TUNNEL_MODE to "vxlan"
export 'TUNNEL_MODE_STRING'=${TUNNEL_MODE_STRING:-"-t vxlan"}

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
        echo "${2}: Invalid IPv4 address"
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

# write_cilium_cfg writes cilium configuration options in ${3}. If node index
# ${1} is even and LB is enabled, adds cilium --lb option. Sets the cilium node
# IPv4 address with suffix ${2} and sets the IPv6 address with ${3}.
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
    else
        if [[ "${IPV4}" -eq "1" ]]; then
            cilium_options+=" --consul ${MASTER_IPV4}:8500"
        else
            cilium_options+=" --consul [${ipv6_addr}]:8500"
        fi
    fi

    if [ "$LB" = 1 ]; then
        # The LB interface needs to be the "exposed" to the host
        # interface only for master node.
        if [ $((node_index)) -eq 1 ]; then
            cilium_options+=" --lb"
            ubuntu_1404_interface="-d eth2"
            ubuntu_1604_interface="-d enp0s9"
        else
            ubuntu_1404_interface="-d eth1"
            ubuntu_1604_interface="-d enp0s8"
        fi
    else
        cilium_options+=" ${TUNNEL_MODE_STRING}"
    fi

cat <<EOF >> "$filename"
sleep 2s
if [ -n "\$(grep DISTRIB_RELEASE=14.04 /etc/lsb-release)" ]; then
    sed -i '/exec/d' /etc/init/cilium.conf
    echo 'exec cilium-agent --debug ${ubuntu_1404_interface} ${cilium_options}' >> /etc/init/cilium.conf
else
    sed -i '9s+.*+ExecStart=/usr/bin/cilium-agent --debug \$CILIUM_OPTS+' /lib/systemd/system/cilium.service
    echo 'CILIUM_OPTS="${ubuntu_1604_interface} ${cilium_options}"' >> /etc/sysconfig/cilium
    echo 'PATH=/usr/local/clang/bin:/usr/local/sbin:/usr/local/bin:/usr/bin:/usr/sbin:/sbin:/bin' >> /etc/sysconfig/cilium
    chmod 644 /etc/sysconfig/cilium
fi

service cilium restart

for ((i = 0 ; i < 24; i++)); do
    if cilium status > /dev/null 2>&1; then
        break
    fi
    sleep 5s
    echo "Waiting for Cilium daemon to come up..."
done
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

# set_vagrant_env sets up Vagrantfile environment variables
function set_vagrant_env(){
    split_ipv4 ipv4_array "${MASTER_IPV4}"
    export 'IPV4_BASE_ADDR'="$(printf "%d.%d.%d." "${ipv4_array[0]}" "${ipv4_array[1]}" "${ipv4_array[2]}")"
    export 'FIRST_IP_SUFFIX'="${ipv4_array[3]}"
    export 'MASTER_IPV6_PUBLIC'="${IPV6_PUBLIC_CIDR}$(printf '%02X' ${ipv4_array[3]})"

    if [[ -n "${NFS}" ]]; then
        split_ipv4 ipv4_array_nfs "${MASTER_IPV4_NFS}"
        export 'IPV4_BASE_ADDR_NFS'="$(printf "%d.%d.%d." "${ipv4_array_nfs[0]}" "${ipv4_array_nfs[1]}" "${ipv4_array_nfs[2]}")"
        export 'FIRST_IP_SUFFIX_NFS'="${ipv4_array[3]}"
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

# vboxnet_addr_finder checks if any vboxnet interface has the IPv6 public CIDR
function vboxnet_addr_finder(){
    iname_prefix="vboxnet"
    interfaces=$(ip l | grep -Eo "${iname_prefix}[0-9]+")
    for int in ${interfaces}; do
        addr_found=$(ip -6 a s dev "${int}" | grep -i "${IPV6_PUBLIC_CIDR}")
        if [[ -n "${addr_found}" ]]; then
            found=1
            break
        fi
    done
    if [[ -z "${found}" ]]; then
            echo "ERROR: VirtualBox interface with \"${IPV6_PUBLIC_CIDR}\" not found"
            echo "Please configure a HostOnly VirtualBox network interface with \"${IPV6_PUBLIC_CIDR}1/16\""
            exit 1
    fi
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

cd "${dir}/../.."

if [ -n "${RELOAD}" ]; then
    vagrant reload
else
    vagrant up
fi

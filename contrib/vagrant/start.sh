#!/usr/bin/env bash
dir=$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )

#If you change this IPv4 you'll have to change the following IPv6 base address as well
export 'NODE_IP_BASE'="192.168.33."
export 'FIRST_IP_SUFFIX'="11"
export 'VM_MEMORY'=3072
export 'VM_CPUS'=2
ipv6_base_addr="F00D::C0A8:210B"

# FIXME: Always enable IPv4 for now until it can be enabled at runtime
# Required for several runtime tests
if [ -z "${IPV4}" ]; then
    export 'IPV4'=1
fi

if [ -n "${NFS}" ]; then
    export 'NODE_NFS_IP_BASE'="192.168.34."
fi

if [ -n "${K8S}" ]; then
    export 'K8STAG'="-k8s"
    export 'VM_MEMORY'=5120
    export 'VM_CPUS'=8
    echo "Warning: In K8S mode, the VM memory and number of CPUs had to be"
    echo "increased to ${VM_MEMORY} and ${VM_CPUS} respectively."
    sleep 2s
fi

if [ -z "${VAGRANT_DEFAULT_PROVIDER}" ]; then
    export 'VAGRANT_DEFAULT_PROVIDER'="virtualbox"
fi

if [ -z "${TUNNEL_MODE_STRING}" ]; then
    export 'TUNNEL_MODE_STRING'="-t vxlan"
fi

export 'CILIUM_SCRIPT'=true
export 'CILIUM_TEMP'="${dir}"

function write_header(){
    index="${1}"
    filename="${2}"
    cat <<EOF > "${filename}"
# Use of IPv6 'documentation block' to provide example
ip -6 a a 2001:DB8:AAAA::${index}/48 dev eth1
echo '2001:DB8:AAAA::1 cilium${K8STAG}-master' >> /etc/hosts

EOF

}

function write_nodes_routes(){
    node_index="${2}"
    filename="${3}"
    cat <<EOF >> "${filename}"
# Node's routes
EOF
    local i
    local index=1
    for i in `seq $(( FIRST_IP_SUFFIX + 1 )) $(( FIRST_IP_SUFFIX + NUM_NODES ))`; do
        index=$(( index + 1 ))
        if [ "${node_index}" -eq "${index}" ]; then
            eval "${1}=$(printf '%02X' ${i})"
            continue
        fi
        hexIPv4=$(printf "%02X" "${i}")
        hexIPv6=$(printf "%04X" "${index}")

# Even numbered nodes are clients and odd numbered servers. Clients connect to servers via load balancer IP and servers directly connect to client nodes.
	if [ "$LB" = 1 ] && [ $((node_index%2)) -eq 0 ]; then
		cat <<EOF >> "${filename}"
ip r a 10.${index}.0.1/32 dev eth1
ip -6 r a ${ipv6_base_addr: : -2}${hexIPv4}:0:0/96 via 2001:DB8:AAAA::1
echo "2001:DB8:AAAA::${hexIPv6} cilium${K8STAG}-node-${index}" >> /etc/hosts

EOF
	else
		cat <<EOF >> "${filename}"
ip r a 10.${index}.0.1/32 dev eth1
ip -6 r a ${ipv6_base_addr: : -2}${hexIPv4}:0:0/96 via 2001:DB8:AAAA::${hexIPv6}
echo "2001:DB8:AAAA::${hexIPv6} cilium${K8STAG}-node-${index}" >> /etc/hosts

EOF
	fi
    done
}

function write_footer() {
    index="${1}"
    ipv6_addr="${2}"
    filename="${3}"

    if [ -n "${IPV4}" ] && [ "${IPV4}" -ne "0" ]; then
        ipv4_options="--ipv4 --ipv4-range 10.${index}.0.1 "
    fi

    if [ -n "${K8S}" ]; then
        if [ -n "${IPV4}" ] && [ "${IPV4}" -ne "0" ]; then
            k8s_options="-k http://10.1.0.1:8080 "
        else
            k8s_options="-k http://[f00d::c0a8:210b:0:ffff]:8080 "
        fi
    fi

    if [ "$LB" = 1 ] && [ "$index" = 1 ]; then
	    cat <<EOF >> "$filename"
sleep 2s
sed -i '/exec/d' /etc/init/cilium-net-daemon.conf
echo 'script' >> /etc/init/cilium-net-daemon.conf
echo 'cilium lb init 2001:db8:aaaa::1 f00d::' >> /etc/init/cilium-net-daemon.conf
echo 'exec cilium -D daemon run ${k8s_options}-n ${ipv6_addr} ${ipv4_options}--lb ${TUNNEL_MODE_STRING} -c "${NODE_IP_BASE}${FIRST_IP_SUFFIX}:8500"' >> /etc/init/cilium-net-daemon.conf
echo 'end script' >> /etc/init/cilium-net-daemon.conf
service cilium-net-daemon restart
sleep 6s

EOF
    else
	    cat <<EOF >> "$filename"
sleep 2s
sed -i '/exec/d' /etc/init/cilium-net-daemon.conf
echo 'exec cilium -D daemon run ${k8s_options}-n ${ipv6_addr} ${ipv4_options}${TUNNEL_MODE_STRING} -c "${NODE_IP_BASE}${FIRST_IP_SUFFIX}:8500"' >> /etc/init/cilium-net-daemon.conf
service cilium-net-daemon restart
sleep 6s

EOF
    fi
}

function create_master(){
    write_header 1 "${dir}/cilium-master.sh"

    if [ -n "${NUM_NODES}" ]; then
        write_nodes_routes hexNodeIPv4 1 "${dir}/cilium-master.sh"
    fi

    write_footer 1 "${ipv6_base_addr}:0:0" "${dir}/cilium-master.sh"

}

function create_nodes(){
    if [ -n "${NUM_NODES}" ]; then
        for i in `seq 2 $(( NUM_NODES + 1 ))`; do
            write_header "${i}" "${dir}/node-start-${i}.sh"

            cat <<EOF >> "${dir}/node-start-${i}.sh"
ip -6 r a ${ipv6_base_addr}:0:0/96 via 2001:DB8:AAAA::1
ip r a 10.1.0.1/32 dev eth1

echo "2001:DB8:AAAA::$(printf "%04X" "${i}") cilium${K8STAG}-node-${i}" >> /etc/hosts

EOF
            if [ -n "${NUM_NODES}" ]; then
                write_nodes_routes hexNodeIPv4 "${i}" "${dir}/node-start-${i}.sh"
            fi

            write_footer "${i}" "${ipv6_base_addr: : -2}${hexNodeIPv4}:0:0" "${dir}/node-start-${i}.sh"

        done
    fi
}

create_master
create_nodes

cd "${dir}/../.."

if [ -n "${RELOAD}" ]; then
    vagrant reload
else
    vagrant up
fi

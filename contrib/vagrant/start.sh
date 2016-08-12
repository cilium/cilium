#!/usr/bin/env bash
dir=$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )

#If you change this IPv4 you'll have to change the following IPv6 base address as well
export 'NODE_IP_BASE'="192.168.33."
export 'FIRST_IP_SUFFIX'="11"
ipv6_base_addr="F00D::C0A8:210B"

if [ -n "${NFS}" ]; then
    export 'NODE_NFS_IP_BASE'="192.168.34."
fi

if [ -n "${K8S}" ]; then
    export 'K8STAG'="-k8s"
fi

if [ -z "${VAGRANT_DEFAULT_PROVIDER}" ]; then
    export 'VAGRANT_DEFAULT_PROVIDER'="virtualbox"
fi

if [ -n "${1}" ]; then
    export 'NUM_NODES'="${1}"
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
        cat <<EOF >> "${filename}"
ip r a 10.${index}.0.1/32 dev eth1
ip -6 r a ${ipv6_base_addr: : -2}${hexIPv4}:0:0/96 via 2001:DB8:AAAA::${hexIPv6}
echo "2001:DB8:AAAA::${hexIPv6} cilium${K8STAG}-node-${index}" >> /etc/hosts

EOF
    done
}

function write_footer() {
    index="${1}"
    ipv6_addr="${2}"
    filename="${3}"

    if [ -n "${IPV4}" ]; then
        ipv4_options="--ipv4 --ipv4-range 10.${index}.0.1 "
    fi

    cat <<EOF >> "$filename"
sleep 2s
sed -i '/exec/d' /etc/init/cilium-net-daemon.conf
echo 'exec cilium -D daemon run -n ${ipv6_addr} ${ipv4_options}-t vxlan -c "${NODE_IP_BASE}${FIRST_IP_SUFFIX}:8500"' >> /etc/init/cilium-net-daemon.conf
service cilium-net-daemon restart
sleep 3s
EOF
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

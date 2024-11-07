#!/usr/bin/env bash

PS4='+[\t] '
set -eu

IMG_OWNER=${1:-cilium}
IMG_TAG=${2:-latest}
CILIUM_EXTRA_ARGS=${3:-}
V=${V:-"0"} # Verbosity. 0 = quiet, 1 = loud
if [ "$V" != "0" ]; then
    set -x
fi

CILIUM_EXEC="docker exec -t lb-node docker exec -t cilium-lb"

CFG_COMMON=("--enable-ipv4=true" "--enable-ipv6=true" "--devices=eth0" \
            "--datapath-mode=lb-only" "--enable-k8s=false" \
	    "--bpf-lb-mode=snat" "--enable-nat46x64-gateway=true")

TXT_XDP_MAGLEV="Mode:XDP\tAlgorithm:Maglev\tRecorder:Disabled"
CFG_XDP_MAGLEV=("--bpf-lb-acceleration=native" "--bpf-lb-algorithm=maglev")

TXT_TC__MAGLEV="Mode:TC \tAlgorithm:Maglev\tRecorder:Disabled"
CFG_TC__MAGLEV=("--bpf-lb-acceleration=disabled" "--bpf-lb-algorithm=maglev")

TXT_TC__RANDOM="Mode:TC \tAlgorithm:Random\tRecorder:Disabled"
CFG_TC__RANDOM=("--bpf-lb-acceleration=disabled" "--bpf-lb-algorithm=random")

TXT_XDP_MAGLEV_RECORDER="Mode:XDP\tAlgorithm:Maglev\tRecorder:Enabled"

CMD="$0"

function trace_offset {
    local line_no=$1
    shift
    >&2 echo -e "\e[92m[${CMD}:${line_no}]\t$*\e[0m"
}

function trace_exec {
    out=$($@ | nl -bn)
    if [ "$V" != "0" ]; then
        trace_offset "${BASH_LINENO[0]}"  "Executing $*:\n$out"
    fi
}

function info {
    trace_offset "${BASH_LINENO[0]}"  "$@"
}

function fatal_offset {
    local line_no=$1
    shift
    >&2 echo -e "\e[31m[${CMD}:${line_no}]\t$*\e[0m"
    exit 1
}

function fatal {
    fatal_offset "${BASH_LINENO[0]}"  "$@"
}

# $1 - Text to represent the install, used for logging
# $2+ - configuration options to pass to Cilium on startup
function cilium_install {
    local cfg_text=$1
    shift

    trace_offset "${BASH_LINENO[0]}" "Installing Cilium with $cfg_text"
    docker exec -t lb-node docker rm -f cilium-lb || true
    docker exec -t lb-node \
        docker run --name cilium-lb -td \
            -v /sys/fs/bpf:/sys/fs/bpf \
            -v /lib/modules:/lib/modules \
            --privileged=true \
            --network=host \
            "quay.io/${IMG_OWNER}/cilium-ci:${IMG_TAG}" \
            cilium-agent "${CFG_COMMON[@]}" "$@" ${CILIUM_EXTRA_ARGS}
    result=1
    for i in $(seq 1 10); do
        if ${CILIUM_EXEC} cilium-dbg status --brief; then
            result=0
            break;
        fi
        if [ -z "$(docker exec lb-node docker ps -qf 'name=cilium-lb')" ]; then
            # Early exit if cilium-agent is really just in trouble
            result=1
            break;
        fi
        sleep 3
    done
    if [ $result -ne 0 ]; then
        ${CILIUM_EXEC} cilium-dbg status
        containerID=$(docker exec lb-node docker inspect cilium-lb --format="{{ .Id }}")
        docker exec lb-node docker logs "${containerID}"
        fatal_offset "${BASH_LINENO[0]}" "Failed to install Cilium with $cfg_text"
    fi
    sleep 1
}

function initialize_docker_env {
    # With Docker-in-Docker we create two nodes:
    #
    # * "lb-node" runs cilium in the LB-only mode.
    # * "nginx" runs the nginx server.

    trace_offset "${BASH_LINENO[0]}" "Initializing docker environment..."

    docker network create --subnet="172.12.42.0/24,2001:db8:1::/64" --ipv6 cilium-l4lb
    docker run --privileged --name lb-node -d --restart=on-failure:10 \
        --network cilium-l4lb -v /lib/modules:/lib/modules \
        docker:dind
    docker exec -t lb-node mount bpffs /sys/fs/bpf -t bpf
    docker run --name nginx -d --network cilium-l4lb nginx

    # Wait until Docker is ready in the lb-node node
    while ! docker exec -t lb-node docker ps >/dev/null; do sleep 1; done

    # Disable TX and RX csum offloading, as veth does not support it. Otherwise,
    # the forwarded packets by the LB to the worker node will have invalid csums.
    IFIDX=$(docker exec -i lb-node \
        /bin/sh -c 'echo $(( $(ip -o l show eth0 | awk "{print $1}" | cut -d: -f1) ))')
    LB_VETH_HOST=$(ip -o l | grep "if$IFIDX" | awk '{print $2}' | cut -d@ -f1)
    ethtool -K "$LB_VETH_HOST" rx off tx off
}

function force_cleanup {
    ${CILIUM_EXEC} cilium-dbg service delete 1 || true
    ${CILIUM_EXEC} cilium-dbg service delete 2 || true
    ip -4 r d "10.0.0.4/32" || true
    ip -6 r d "fd00:cafe::1" || true
    docker rm -f lb-node || true
    docker rm -f nginx || true
    docker network rm cilium-l4lb || true
}

function cleanup {
    if tty -s; then
        read -p "Hold the environment for debugging? [y/n]" -n 1 -r
        echo
        if [[ $REPLY =~ ^[Nn]$ ]]; then
            force_cleanup
        fi
    fi
}

# $1 - target service, for example "[fd00:dead:beef:15:bad::1]:80"
function wait_service_ready {
    # Try and sleep until the LB2 comes up, seems to be no other way to detect when the service is ready.
    set +e
    for i in $(seq 1 10); do
        curl -s -o /dev/null "${1}" && break
        sleep 1
    done
    set -e
}

function configure_local_route {
    LB_VIP_RT="$1"
    LB_VIP_FAM="$2"

    LB_NODE_IP=$(docker exec -t lb-node \
                    ip -o "${LB_VIP_FAM}" a s eth0 \
                    | awk '{print $4}' \
                    | cut -d/ -f1 \
                    | head -n1)
    trace_offset "${BASH_LINENO[0]}" "Installing route: 'ip ${LB_VIP_FAM} r a ${LB_VIP_RT} via $LB_NODE_IP'"
    ip "${LB_VIP_FAM}" r a "${LB_VIP_RT}" via "$LB_NODE_IP" \
    || fatal "Failed to inject route into the localhost"
}

function assert_maglev_maps_sane {
    MAG_V4=$(${CILIUM_EXEC} cilium-dbg bpf lb maglev list -o=jsonpath='{.\[1\]/v4}' | tr -d '\r')
    MAG_V6=$(${CILIUM_EXEC} cilium-dbg bpf lb maglev list -o=jsonpath='{.\[1\]/v6}' | tr -d '\r')
    if [ -n "$MAG_V4" ] || [ -z "$MAG_V6" ]; then
        ${CILIUM_EXEC} cilium-dbg bpf lb maglev list
        fatal_offset "${BASH_LINENO[0]}" "Invalid content of Maglev table!"
    fi
}

function assert_connectivity_ok {
    for i in $(seq 1 10); do
        curl -s -o /dev/null "${1}" \
        || fatal_offset "${BASH_LINENO[0]}" "Failed connection from localhost to $1 (attempt $i/10)"
    done
}

function test_services {
    LB_VIP="$1"
    LB_VIP_SVC="$2"
    LB_VIP_FAM="$3"
    LB_VIP_SUBNET="$4"
    BACKEND_SVC="$5"
    LB_ALT="$6"
    LB_ALT_SVC="$7"
    LB_ALT_FAM="$8"
    LB_ALT_SUBNET="$9"

    cilium_install "$TXT_TC__MAGLEV" ${CFG_TC__MAGLEV[@]}

    info "Configuring service ${LB_VIP_SVC} -> ${BACKEND_SVC}"
    ${CILIUM_EXEC} \
        cilium-dbg service update --id 1 --frontend "${LB_VIP_SVC}" --backends "${BACKEND_SVC}" --k8s-load-balancer \
        || fatal "Unable to configure service"

    SVC_BEFORE=$(${CILIUM_EXEC} cilium-dbg service list | nl -bn)

    trace_exec "${CILIUM_EXEC} cilium-dbg bpf lb list"
    assert_maglev_maps_sane

    info "Testing service ${LB_VIP_SVC} -> ${BACKEND_SVC} via TC + Maglev"
    configure_local_route "${LB_VIP}/${LB_VIP_SUBNET}" "${LB_VIP_FAM}"
    assert_connectivity_ok "${LB_VIP_SVC}"

    cilium_install "$TXT_XDP_MAGLEV" ${CFG_XDP_MAGLEV[@]}

    # Check that restoration went fine. Note that we currently cannot do runtime test
    # as veth + XDP is broken when switching protocols. Needs something bare metal.
    SVC_AFTER=$(${CILIUM_EXEC} cilium-dbg service list | nl -bn)
    trace_exec "${CILIUM_EXEC} cilium-dbg bpf lb list"

    info "Validating service restore after restart for service ${LB_VIP_SVC} -> ${BACKEND_SVC}"
    if [ "$SVC_BEFORE" != "$SVC_AFTER" ]; then
        fatal "Service ${LB_VIP_SVC} was not restored correctly\n" \
              "Before:\n" \
              "$SVC_BEFORE\n" \
              "After:\n" \
              "$SVC_AFTER\n"
    fi

    cilium_install "$TXT_TC__MAGLEV" ${CFG_TC__MAGLEV[@]}
    info "Testing service ${LB_VIP_SVC} -> ${BACKEND_SVC} via TC + Maglev"
    assert_connectivity_ok "${LB_VIP_SVC}"

    # Check that curl also works for random selection
    cilium_install "$TXT_TC__RANDOM" ${CFG_TC__RANDOM[@]}
    info "Testing service ${LB_VIP_SVC} -> ${BACKEND_SVC} via TC + Random"
    assert_connectivity_ok "${LB_VIP_SVC}"

    # Add another same-protocol service and reuse backend (using $LB_ALT_FAM)
    info "Configuring service ${LB_ALT_SVC} -> ${BACKEND_SVC}"
    ${CILIUM_EXEC} \
        cilium-dbg service update --id 2 --frontend "${LB_ALT_SVC}" --backends "${BACKEND_SVC}" --k8s-load-balancer \
        || fatal "Unable to configure service"
    trace_exec "${CILIUM_EXEC} cilium-dbg service list"
    trace_exec "${CILIUM_EXEC} cilium-dbg bpf lb list"
    configure_local_route "${LB_ALT}/${LB_ALT_SUBNET}" "${LB_ALT_FAM}"

    info "Checking connectivity via ${LB_VIP_SVC} -> ${BACKEND_SVC}"
    assert_connectivity_ok "${LB_VIP_SVC}"
    wait_service_ready "${LB_ALT_SVC}"
    info "Checking connectivity via ${LB_ALT_SVC} -> ${BACKEND_SVC}"
    assert_connectivity_ok "${LB_ALT_SVC}"

    cilium_install "$TXT_TC__MAGLEV" ${CFG_TC__MAGLEV[@]}
    info "Testing service ${LB_VIP_SVC} -> ${BACKEND_SVC} via TC + Maglev"
    assert_connectivity_ok "${LB_VIP_SVC}"
    assert_connectivity_ok "${LB_ALT_SVC}"

    ${CILIUM_EXEC} cilium-dbg service delete 1
    ${CILIUM_EXEC} cilium-dbg service delete 2
}

# Check whether the list of filters matches the expected list.
#
# $1 - ID
# $@ - Filters
function check_recorder_list {
    ID=$1
    shift
    num_filters=$#
    if [ $(${CILIUM_EXEC} cilium-dbg bpf recorder list | grep "ID:${ID}" | wc -l) -ne "$num_filters" ]; then
        echo "Expected filters:"
        echo "$@" | nl -bn
        echo "Found filters:"
        ${CILIUM_EXEC} cilium-dbg bpf recorder list | nl -bn
        fatal "Recorder filters did not match expected list"
    fi
}

force_cleanup 2>&1 >/dev/null
initialize_docker_env
trap cleanup EXIT

NGINX_PID=$(docker inspect nginx -f '{{ .State.Pid }}')
WORKER_IP4=$(nsenter -t "$NGINX_PID" -n ip -o -4 a s eth0 | awk '{print $4}' | cut -d/ -f1 | head -n1)
WORKER_IP6=$(nsenter -t "$NGINX_PID" -n ip -o -6 a s eth0 | awk '{print $4}' | cut -d/ -f1 | head -n1)

# NAT 4->6 test suite (services)
################################

LB_VIP="10.0.0.4"
LB_VIP_SVC="$LB_VIP:80"
LB_VIP_FAM="-4"
BACKEND_SVC="[${WORKER_IP6}]:80"
LB_ALT="fd00:dead:beef:15:bad::1"
LB_ALT_SVC="[${LB_ALT}]:80"
LB_ALT_FAM="-6"

test_services "$LB_VIP" "$LB_VIP_SVC" "$LB_VIP_FAM" "32" "$BACKEND_SVC" \
              "$LB_ALT" "$LB_ALT_SVC" "$LB_ALT_FAM" "128"

# NAT 6->4 test suite (services)
################################

LB_VIP="fd00:cafe::1"
LB_VIP_SVC="[$LB_VIP]:80"
LB_VIP_FAM="-6"
BACKEND_SVC="${WORKER_IP4}:80"
LB_ALT="10.0.0.8"
LB_ALT_SVC="${LB_ALT}:80"
LB_ALT_FAM="-4"

test_services "$LB_VIP" "$LB_VIP_SVC" "$LB_VIP_FAM" "128" "$BACKEND_SVC" \
              "$LB_ALT" "$LB_ALT_SVC" "$LB_ALT_FAM" "32"

# NAT test suite & PCAP recorder
################################

RECORDER_FILTERS_IPV4=("2.2.2.2/0 0 1.1.1.1/32 80 TCP" \
                       "2.2.2.2/1 0 1.1.1.1/32 80 TCP" \
                       "2.2.2.2/2 0 1.1.1.1/31 80 TCP" \
                       "2.2.2.2/3 0 1.1.1.1/30 80 TCP" \
                       "2.2.2.2/4 0 1.1.1.1/29 80 TCP" \
                       "2.2.2.2/5 0 1.1.1.1/28 80 TCP" \
                       "2.2.2.2/6 0 1.1.1.1/27 80 TCP" \
                       "2.2.2.2/7 0 1.1.1.1/26 80 TCP" \
                       "2.2.2.2/8 0 1.1.1.1/25 80 TCP" \
                       "2.2.2.2/9 0 1.1.1.1/24 80 TCP" \
                       "2.2.2.2/10 0 1.1.1.1/23 80 TCP" \
                       "2.2.2.2/11 0 1.1.1.1/22 80 TCP" \
                       "2.2.2.2/12 0 1.1.1.1/21 80 TCP" \
                       "2.2.2.2/13 0 1.1.1.1/20 80 TCP" \
                       "2.2.2.2/14 0 1.1.1.1/19 80 TCP" \
                       "2.2.2.2/15 0 1.1.1.1/18 80 TCP" \
                       "2.2.2.2/16 0 1.1.1.1/17 80 TCP" \
                       "2.2.2.2/17 0 1.1.1.1/16 80 TCP" \
                       "2.2.2.2/18 0 1.1.1.1/15 80 TCP" \
                       "2.2.2.2/19 0 1.1.1.1/14 80 TCP" \
                       "2.2.2.2/20 0 1.1.1.1/13 80 TCP" \
                       "2.2.2.2/21 0 1.1.1.1/12 80 TCP" \
                       "2.2.2.2/22 0 1.1.1.1/11 80 TCP" \
                       "2.2.2.2/23 0 1.1.1.1/10 80 TCP" \
                       "2.2.2.2/24 0 1.1.1.1/9 80 TCP" \
                       "2.2.2.2/25 0 1.1.1.1/8 80 TCP" \
                       "2.2.2.2/26 0 1.1.1.1/7 80 TCP" \
                       "2.2.2.2/27 0 1.1.1.1/6 80 TCP" \
                       "2.2.2.2/28 0 1.1.1.1/5 80 TCP" \
                       "2.2.2.2/29 0 1.1.1.1/4 80 TCP" \
                       "2.2.2.2/30 0 1.1.1.1/3 80 TCP" \
                       "2.2.2.2/31 0 1.1.1.1/2 80 TCP" \
                       "2.2.2.2/32 0 1.1.1.1/1 80 TCP" \
                       "2.2.2.2/32 0 1.1.1.1/0 80 TCP")

RECORDER_FILTERS_IPV6=("f00d::1/0 80 cafe::/128 0 UDP" \
                       "f00d::1/1 80 cafe::/127 0 UDP" \
                       "f00d::1/2 80 cafe::/126 0 UDP" \
                       "f00d::1/3 80 cafe::/125 0 UDP" \
                       "f00d::1/4 80 cafe::/124 0 UDP" \
                       "f00d::1/5 80 cafe::/123 0 UDP" \
                       "f00d::1/6 80 cafe::/122 0 UDP" \
                       "f00d::1/7 80 cafe::/121 0 UDP" \
                       "f00d::1/8 80 cafe::/120 0 UDP" \
                       "f00d::1/9 80 cafe::/119 0 UDP" \
                       "f00d::1/10 80 cafe::/118 0 UDP" \
                       "f00d::1/11 80 cafe::/117 0 UDP" \
                       "f00d::1/12 80 cafe::/116 0 UDP" \
                       "f00d::1/13 80 cafe::/115 0 UDP" \
                       "f00d::1/14 80 cafe::/114 0 UDP" \
                       "f00d::1/15 80 cafe::/113 0 UDP" \
                       "f00d::1/16 80 cafe::/112 0 UDP" \
                       "f00d::1/17 80 cafe::/111 0 UDP" \
                       "f00d::1/18 80 cafe::/110 0 UDP" \
                       "f00d::1/19 80 cafe::/109 0 UDP" \
                       "f00d::1/20 80 cafe::/108 0 UDP" \
                       "f00d::1/21 80 cafe::/107 0 UDP" \
                       "f00d::1/22 80 cafe::/106 0 UDP" \
                       "f00d::1/23 80 cafe::/105 0 UDP" \
                       "f00d::1/24 80 cafe::/104 0 UDP" \
                       "f00d::1/25 80 cafe::/103 0 UDP" \
                       "f00d::1/26 80 cafe::/102 0 UDP" \
                       "f00d::1/27 80 cafe::/101 0 UDP" \
                       "f00d::1/28 80 cafe::/100 0 UDP" \
                       "f00d::1/29 80 cafe::/99 0 UDP" \
                       "f00d::1/30 80 cafe::/98 0 UDP" \
                       "f00d::1/31 80 cafe::/97 0 UDP" \
                       "f00d::1/32 80 cafe::/96 0 UDP" \
                       "f00d::1/32 80 cafe::/0 0 UDP")

# Install Cilium as standalone L4LB: XDP/Maglev/SNAT/Recorder
cilium_install "$TXT_XDP_MAGLEV_RECORDER" \
    --bpf-lb-algorithm=maglev \
    --bpf-lb-acceleration=native \
    --enable-recorder=true

# Trigger recompilation with 32 IPv4 filter masks
${CILIUM_EXEC} \
    cilium-dbg recorder update --id 1 --caplen 100 \
        --filters="$(printf '%s,' "${RECORDER_FILTERS_IPV4[@]}" | sed 's/,*$//')"

# Trigger recompilation with 32 IPv6 filter masks
${CILIUM_EXEC} \
    cilium-dbg recorder update --id 2 --caplen 100 \
        --filters="$(printf '%s,' "${RECORDER_FILTERS_IPV6[@]}" | sed 's/,*$//')"

check_recorder_list 1 "${RECORDER_FILTERS_IPV4[@]}"
check_recorder_list 2 "${RECORDER_FILTERS_IPV6[@]}"

trace_exec ${CILIUM_EXEC} cilium-dbg recorder list
trace_exec ${CILIUM_EXEC} cilium-dbg bpf recorder list
${CILIUM_EXEC} cilium-dbg recorder delete 1
${CILIUM_EXEC} cilium-dbg recorder delete 2
trace_exec ${CILIUM_EXEC} cilium-dbg recorder list

force_cleanup
echo "YAY!"

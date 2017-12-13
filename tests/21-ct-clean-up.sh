#!/bin/bash

dir=$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )
source "${dir}/helpers.bash"
# dir might have been overwritten by helpers.bash
dir=$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )

TEST_NAME=$(get_filename_without_extension $0)
LOGS_DIR="${dir}/cilium-files/${TEST_NAME}/logs"
redirect_debug_logs ${LOGS_DIR}

set -ex

function cleanup {
  docker rm -f server server-2 httpd-server netcat client client-2 2> /dev/null || true
  monitor_stop
}

function finish_test {
  log "setting configuration of Cilium: PolicyEnforcement=default"
  cilium config PolicyEnforcement=default
  gather_files ${TEST_NAME} ${TEST_SUITE}
  cleanup
}

function endpoint_disable_policy {
  cilium endpoint config $1 IngressPolicy=false
  cilium endpoint config $1 EgressPolicy=false
}

function start_containers {
  log "starting containers"
  docker run -dt --net=$TEST_NET --name server -l id.server httpd
  docker run -dt --net=$TEST_NET --name server-2 -l id.server-2 httpd
  docker run -dt --net=$TEST_NET --name httpd-server -l id.server-3 cilium/demo-httpd
  docker run -dt --net=$TEST_NET --name netcat -l id.server-4 busybox sleep 30000s
  docker run -dt -v $dir/21-ct-clean-up-nc.py:/nc.py --net=$TEST_NET --name client -l id.client python:2.7.14
  docker run -dt --net=$TEST_NET --name client-2 -l id.client tgraf/netperf
  wait_for_endpoints 6
  echo "containers started and ready"
}

function get_container_metadata {
  CLIENT_SEC_ID=$(cilium endpoint list | grep id.client-2 | awk '{ print $4}')
  log "CLIENT_SEC_ID: $CLIENT_SEC_ID"
  CLIENT_IP=$(docker inspect --format '{{ .NetworkSettings.Networks.cilium.GlobalIPv6Address }}' client)
  log "CLIENT_IP: $CLIENT_IP"
  CLIENT_IP4=$(docker inspect --format '{{ .NetworkSettings.Networks.cilium.IPAddress }}' client)
  log "CLIENT_IP4: $CLIENT_IP4"
  CLIENT_2_IP=$(docker inspect --format '{{ .NetworkSettings.Networks.cilium.GlobalIPv6Address }}' client-2)
  log "CLIENT_2_IP: $CLIENT_2_IP"
  CLIENT_2_IP4=$(docker inspect --format '{{ .NetworkSettings.Networks.cilium.IPAddress }}' client-2)
  log "CLIENT_2_IP4: $CLIENT_2_IP4"
  CLIENT_ID=$(cilium endpoint list | grep "${CLIENT_IP4}" | awk '{ print $1}')
  log "CLIENT_ID: $CLIENT_ID"
  CLIENT_2_ID=$(cilium endpoint list | grep "${CLIENT_2_IP4}" | awk '{ print $1}')
  log "CLIENT_2_ID: $CLIENT_2_ID"
  SERVER_IP=$(docker inspect --format '{{ .NetworkSettings.Networks.cilium.GlobalIPv6Address }}' server)
  log "SERVER_IP: $SERVER_IP"
  SERVER_IP4=$(docker inspect --format '{{ .NetworkSettings.Networks.cilium.IPAddress }}' server)
  log "SERVER_IP4: $SERVER_IP4"
  SERVER_ID=$(cilium endpoint list | grep -E 'id.server($|\s)' | awk '{ print $1}')
  log "SERVER_ID: $SERVER_ID"
  SERVER_2_IP=$(docker inspect --format '{{ .NetworkSettings.Networks.cilium.GlobalIPv6Address }}' server-2)
  log "SERVER_2_IP: $SERVER_2_IP"
  SERVER_2_IP4=$(docker inspect --format '{{ .NetworkSettings.Networks.cilium.IPAddress }}' server-2)
  log "SERVER_2_IP4: $SERVER_2_IP4"
  SERVER_2_ID=$(cilium endpoint list | grep id.server-2 | awk '{ print $1}')
  log "SERVER_2_ID: $SERVER_2_ID"
  SERVER_3_IP=$(docker inspect --format '{{ .NetworkSettings.Networks.cilium.GlobalIPv6Address }}' httpd-server)
  log "SERVER_3_IP: $SERVER_3_IP"
  SERVER_3_IP4=$(docker inspect --format '{{ .NetworkSettings.Networks.cilium.IPAddress }}' httpd-server)
  log "SERVER_3_IP4: $SERVER_3_IP4"
  SERVER_3_ID=$(cilium endpoint list | grep id.server-3 | awk '{ print $1}')
  log "SERVER_3_ID: $SERVER_3_ID"
  SERVER_4_IP=$(docker inspect --format '{{ .NetworkSettings.Networks.cilium.GlobalIPv6Address }}' netcat)
  log "SERVER_3_IP: $SERVER_4_IP"
  SERVER_4_IP4=$(docker inspect --format '{{ .NetworkSettings.Networks.cilium.IPAddress }}' netcat)
  log "SERVER_4_IP4: $SERVER_4_IP4"
  SERVER_4_ID=$(cilium endpoint list | grep id.server-4 | awk '{ print $1}')
  log "SERVER_4_ID: $SERVER_4_ID"
}

function test_reachability(){
  local TIMEOUT="5"

  local container="${1}"
  local dst_ip="${2}"
  local http_path="${3}"
  log "trying to docker exec -i ${container} bash -c \"curl -s -o /dev/null -w \"%{http_code}\" --connect-timeout $TIMEOUT -XGET http://${dst_ip}:80${http_path}\" from client container (should work)"
  ret="$(docker exec -i "${container}" bash -c "curl -s -o /dev/null -w \"%{http_code}\" --connect-timeout $TIMEOUT -XGET http://${dst_ip}:80${http_path}")"
  if [ "${ret}" -eq 403 ]; then
    abort "Error: Could not reach ${dst_ip}:80${http_path} from ${container}"
  fi
}

function test_reachability_nc(){
  local TIMEOUT="5"

  local container="${1}"
  local src_port="${2}"
  local dst_ip="${3}"
  local http_path="${4}"
  log "trying to do docker exec -i "${container}" bash -c \"python ./nc.py ${src_port} ${TIMEOUT} ${dst_ip} 80 "${http_path}" | head -n 1\" from client container (should work)"
  ret="$(docker exec -i "${container}" bash -c "python ./nc.py ${src_port} ${TIMEOUT} ${dst_ip} 80 "${http_path}" | head -n 1")"
  if [[ ${ret} != "HTTP/1.1 200 OK"* && ${ret} != "HTTP/1.0 200 OK"* ]]; then
    abort "Error: Could not reach ${dst_ip}:80${http_path} from ${container}, got ${ret}, expecting HTTP/1.1 200 OK"
  fi
}

function test_unreachability(){
  local DROP_TIMEOUT="2"

  local container="${1}"
  local dst_ip="${2}"
  local http_path="${3}"
  log "trying to curl http://${dst_ip}:80${http_path} from client container (shouldn't work)"
  ret="$(docker exec -i "${container}" bash -c "curl -s -o /dev/null -w \"%{http_code}\" --connect-timeout $DROP_TIMEOUT -XGET http://${dst_ip}:80${http_path}")"
  if [ "${ret}" -eq 200 ]; then
    abort "Error: Unexpected success reaching ${dst_ip}:80${http_path} from ${container}"
  fi
}

function test_reachability_port(){
  local DROP_TIMEOUT="2"

  local container="${1}"
  local dst_ip="${2}"
  local dst_port="${3}"
  local http_path="${4}"
  log "trying to curl http://${dst_ip}:${dst_port}${http_path} from client container (shouldn't work)"
  ret="$(docker exec -d ${container} bash -c "curl -s -o /dev/null -w \"%{http_code}\" --connect-timeout $DROP_TIMEOUT -XGET http://${dst_ip}:${dst_port}${http_path}")"
  if [[ ${ret} -ne 0 ]]; then
    abort "Error: unable to run docker exec -d "${container}" bash -c \"curl -s -o /dev/null -w \"%{http_code}\" --connect-timeout $DROP_TIMEOUT -XGET http://${dst_ip}:${dst_port}${http_path}\""
  fi
}

function test_unreachability_nc(){
  local DROP_TIMEOUT="2"

  local container="${1}"
  local src_port="${2}"
  local dst_ip="${3}"
  local http_path="${4}"
  log "trying to do docker exec -i "${container}" bash -c \"python ./nc.py ${src_port} ${DROP_TIMEOUT} ${dst_ip} 80 "${http_path}" | head -n 1\" from client container (shouldn't work)"
  ret="$(docker exec -i "${container}" bash -c "python ./nc.py ${src_port} ${DROP_TIMEOUT} ${dst_ip} 80 "${http_path}" | head -n 1")"
  if [[ "${ret}" != "HTTP/1.0 403 Forbidden"* && "${ret}" != "HTTP/1.1 403 Forbidden"* ]]; then
    abort "Error: Unexpected success reaching ${dst_ip}:80${http_path} from ${container}, got ${ret}"
  fi
}


function count_ct_entries_of(){
  local from_ip="${1}"
  local to_ip="${2}"
  local src_sec_id="${3}"
  cilium bpf ct list global | grep "${from_ip}:80 -> ${to_ip}:" | grep "sec_id=${src_sec_id}" | wc -l
}

function check_ct_entries_of(){
  n_entries="${1}"
  n_entries_expected="${2}"
  src="${3}"
  dst="${4}"

  if [ "${n_entries}" -ne "${n_entries_expected}" ]; then
    abort "CT map should have exactly ${n_entries_expected} and not ${n_entries} entries for the communication between ${src} and ${dst}"
  fi
}

function check_ct_entries_of_le(){
  n_entries="${1}"
  n_entries_expected="${2}"
  src="${3}"
  dst="${4}"

  if [ "${n_entries}" -gt "${n_entries_expected}" ]; then
    abort "CT map should be less than ${n_entries_expected} and not ${n_entries} entries for the communication between ${src} and ${dst}"
  fi
}

function start_server_netcat(){
  ip="${1}"
  port="$2"
  docker exec -d netcat nc -l "${ip}:${port}"
}

trap finish_test EXIT

log "setting configuration of Cilium: PolicyEnforcement=always"
cilium config PolicyEnforcement=always

cleanup
monitor_start
logs_clear

create_cilium_docker_network

start_containers
get_container_metadata

log "endpoint list output:"
cilium endpoint list

cilium policy delete --all

cat <<EOF | policy_import_and_wait -
[{
    "endpointSelector": {"matchLabels":{"id.server":""}},
    "ingress": [{
        "fromEndpoints": [{
           "matchLabels":{"id.client":""}
        }],
        "toPorts": [{
            "ports": [{"port": "80", "protocol": "tcp"}]
        }]
    }],
    "labels": ["id=server"]
},{
    "endpointSelector": {"matchLabels":{"id.server-2":""}},
    "ingress": [{
        "fromEndpoints": [{
           "matchLabels":{"id.client":""}
        }],
        "toPorts": [{
            "ports": [{"port": "80", "protocol": "tcp"}]
        }]
    }],
    "labels": ["id=server-2"]
}]
EOF

wait_for_endpoints 6

log "beginning connectivity between client, client-2 and servers"
monitor_clear

test_reachability "client" "[$SERVER_IP]"
test_reachability "client-2" "[$SERVER_IP]"
monitor_clear

test_reachability "client" "$SERVER_IP4"
test_reachability "client-2" "$SERVER_IP4"
monitor_clear

test_reachability "client" "[$SERVER_2_IP]"
test_reachability "client-2" "[$SERVER_2_IP]"
monitor_clear

test_reachability "client" "$SERVER_2_IP4"
test_reachability "client-2" "$SERVER_2_IP4"
monitor_clear

entriesBefore=$(cilium bpf ct list global | wc -l)

bef_client_server_2_ct_entries=$(count_ct_entries_of "\[${SERVER_2_IP}\]" "\[${CLIENT_IP}\]" "${CLIENT_SEC_ID}")
bef_client4_server_2_ct_entries=$(count_ct_entries_of "${SERVER_2_IP4}" "${CLIENT_IP4}" "${CLIENT_SEC_ID}")
bef_client_2_server_2_ct_entries=$(count_ct_entries_of "\[${SERVER_2_IP}\]" "\[${CLIENT_2_IP}\]" "${CLIENT_SEC_ID}")
bef_client4_2_server_2_ct_entries=$(count_ct_entries_of "${SERVER_2_IP4}" "${CLIENT_2_IP4}" "${CLIENT_SEC_ID}")

check_ct_entries_of_le "${bef_client_server_2_ct_entries}" 2 "${SERVER_2_IP}" "${CLIENT_IP}"
check_ct_entries_of_le "${bef_client4_server_2_ct_entries}" 2 "${SERVER_2_IP4}" "${CLIENT_IP4}"
check_ct_entries_of_le "${bef_client_2_server_2_ct_entries}" 2 "${SERVER_2_IP}" "${CLIENT_2_IP}"
check_ct_entries_of_le "${bef_client4_2_server_2_ct_entries}" 2 "${SERVER_2_IP4}" "${CLIENT_2_IP4}"

policy_delete_and_wait id=server-2

wait_for_endpoints 6

aft_client_server_2_ct_entries=$(count_ct_entries_of "\[${SERVER_2_IP}\]" "\[${CLIENT_IP}\]" "${CLIENT_SEC_ID}")
aft_client4_server_2_ct_entries=$(count_ct_entries_of "${SERVER_2_IP4}" "${CLIENT_IP4}" "${CLIENT_SEC_ID}")
aft_client_2_server_2_ct_entries=$(count_ct_entries_of "\[${SERVER_2_IP}\]" "\[${CLIENT_2_IP}\]" "${CLIENT_SEC_ID}")
aft_client4_2_server_2_ct_entries=$(count_ct_entries_of "${SERVER_2_IP4}" "${CLIENT_2_IP4}" "${CLIENT_SEC_ID}")

check_ct_entries_of "${aft_client_server_2_ct_entries}" 0 "${SERVER_2_IP}" "${CLIENT_IP}"
check_ct_entries_of "${aft_client4_server_2_ct_entries}" 0 "${SERVER_2_IP4}" "${CLIENT_IP4}"
check_ct_entries_of "${aft_client_2_server_2_ct_entries}" 0 "${SERVER_2_IP}" "${CLIENT_2_IP}"
check_ct_entries_of "${aft_client4_2_server_2_ct_entries}" 0 "${SERVER_2_IP4}" "${CLIENT_2_IP4}"

entriesAfter=$(cilium bpf ct list global | wc -l)

if [ "$(( entriesBefore - entriesAfter ))" -gt "8" ]; then
    abort "CT map should have exactly 8 entries less and not $(( entriesBefore - entriesAfter )) after deleting the policy"
fi

test_reachability "client" "[$SERVER_IP]"
test_reachability "client-2" "[$SERVER_IP]"
monitor_clear

test_reachability "client" "$SERVER_IP4"
test_reachability "client-2" "$SERVER_IP4"
monitor_clear

# FIXME if we don't set +e, the return code from test_unreachability makes the
# test to fail GH #1919
set +e
test_unreachability "client" "[$SERVER_2_IP]"
test_unreachability "client-2" "[$SERVER_2_IP]"
set -e
monitor_clear

# FIXME if we don't set +e, the return code from test_unreachability makes the
# test to fail GH #1919
set +e
test_unreachability "client" "$SERVER_2_IP4"
test_unreachability "client-2" "$SERVER_2_IP4"
set -e
monitor_clear

log "beginning connectivity between client and server to test L7 clean up"
cat <<EOF | policy_import_and_wait -
[{
    "endpointSelector": {"matchLabels":{"id.server-3":""}},
    "ingress": [{
        "fromEndpoints": [{
           "matchLabels":{"id.client":""}
        }],
        "toPorts": [{
            "ports": [{"port": "80", "protocol": "tcp"}]
        }]
    }],
    "labels": ["id=server-3"]
}]
EOF

test_reachability "client" "$SERVER_3_IP4" "/public"
test_reachability "client" "[$SERVER_3_IP]" "/public"
test_reachability "client" "$SERVER_3_IP4" "/private"
test_reachability "client" "[$SERVER_3_IP]" "/private"
monitor_clear

policy_delete_and_wait id=server-3
# Install L7 rule after testing L4

cat <<EOF | policy_import_and_wait -
[{
    "endpointSelector": {"matchLabels":{"id.server-3":""}},
    "ingress": [{
        "fromEndpoints": [{
           "matchLabels":{"id.client":""}
        }],
        "toPorts": [{
            "ports": [{"port": "80", "protocol": "tcp"}],
            "rules": {"http": [{
                  "path": "/public",
                  "method": "GET"
            }]}
        }]
    }],
    "labels": ["id=server-3"]
}]
EOF

test_reachability "client" "$SERVER_3_IP4" "/public"
test_reachability "client" "[$SERVER_3_IP]" "/public"
# FIXME if we don't set +e, the return code from test_unreachability makes the
# test to fail GH #1919
set +e
test_unreachability "client" "$SERVER_3_IP4" "/private"
test_unreachability "client" "[$SERVER_3_IP]" "/private"
set -e
monitor_clear

policy_delete_and_wait id=server-3
# Install other L7 rule after testing L7. The previous rule shouldn't work!

cat <<EOF | policy_import_and_wait -
[{
    "endpointSelector": {"matchLabels":{"id.server-3":""}},
    "ingress": [{
        "fromEndpoints": [{
           "matchLabels":{"id.client":""}
        }],
        "toPorts": [{
            "ports": [{"port": "80", "protocol": "tcp"}],
            "rules": {"http": [{
                  "path": "/dummy",
                  "method": "GET"
            }]}
        }]
    }],
    "labels": ["id=server-3"]
}]
EOF

test_reachability "client" "$SERVER_3_IP4" "/dummy"
test_reachability "client" "[$SERVER_3_IP]" "/dummy"
# FIXME if we don't set +e, the return code from test_unreachability makes the
# test to fail GH #1919
set +e
test_unreachability "client" "$SERVER_3_IP4" "/private"
test_unreachability "client" "[$SERVER_3_IP]" "/private"
test_unreachability "client" "$SERVER_3_IP4" "/public"
test_unreachability "client" "[$SERVER_3_IP]" "/public"
set -e
monitor_clear

log "deleting all policies in cilium"
policy_delete_and_wait --all

log "Installing L4 policy to confirm L4 connectivity"

# Install a L4 policy and confirm connectivity

cat <<EOF | policy_import_and_wait -
[{
    "endpointSelector": {"matchLabels":{"id.server-3":""}},
    "ingress": [{
        "fromEndpoints": [{
           "matchLabels":{"id.client":""}
        }],
        "toPorts": [{
            "ports": [{"port": "80", "protocol": "tcp"}]
        }]
    }],
    "labels": ["id=server-3"]
}]
EOF

test_reachability_nc "client" 11111 "$SERVER_3_IP4" "/public"
test_reachability_nc "client" 11111 "$SERVER_3_IP" "/public"
test_reachability_nc "client" 11111 "$SERVER_3_IP4" "/private"
test_reachability_nc "client" 11111 "$SERVER_3_IP" "/private"
monitor_clear

# Install L7 rule after testing L4 to test if the connection is going
# to the proxy. Since we will use the same source port, after switching
# to L7 the connection should fail when trying to reach /private
log "Installing L7 policy over while the L4 is installed to confirm L7 policy enforcement over the proxy"

cat <<EOF | policy_import_and_wait -
[{
    "endpointSelector": {"matchLabels":{"id.server-3":""}},
    "ingress": [{
        "fromEndpoints": [{
           "matchLabels":{"id.client":""}
        }],
        "toPorts": [{
            "ports": [{"port": "80", "protocol": "tcp"}],
            "rules": {"http": [{
                  "path": "/public",
                  "method": "GET"
            }]}
        }]
    }],
    "labels": ["id=server-4"]
}]
EOF

test_reachability_nc "client" 11111 "$SERVER_3_IP4" "/public"
test_reachability_nc "client" 11111 "$SERVER_3_IP" "/public"
# FIXME if we don't set +e, the return code from test_unreachability makes the
# test to fail GH #1919
set +e
test_unreachability_nc "client" 11111 "$SERVER_3_IP4" "/private"
test_unreachability_nc "client" 11111 "$SERVER_3_IP" "/private"
set -e
monitor_clear

policy_delete_and_wait id=server-4
# After deleting the L7 rule, we will test the L4 connectivity with the same
# source port. We should be able to connect to "/private"
log "Removing the L4 only policy to confirm L4 only policy enforcement withouth the proxy"

test_reachability_nc "client" 11111 "$SERVER_3_IP4" "/private"
test_reachability_nc "client" 11111 "$SERVER_3_IP" "/private"
test_reachability_nc "client" 11111 "$SERVER_3_IP4" "/public"
test_reachability_nc "client" 11111 "$SERVER_3_IP" "/public"
monitor_clear

log "deleting all policies in cilium"
policy_delete_and_wait --all

# Not a single connection should be allowed without any policy loaded

# FIXME if we don't set +e, the return code from test_unreachability makes the
# test to fail GH #1919
set +e
test_unreachability "client" "$SERVER_3_IP4"
test_unreachability "client" "[$SERVER_3_IP]"
test_unreachability "client" "$SERVER_3_IP4" "/dummy"
test_unreachability "client" "[$SERVER_3_IP]" "/dummy"
test_unreachability "client" "$SERVER_3_IP4" "/private"
test_unreachability "client" "[$SERVER_3_IP]" "/private"
test_unreachability "client" "$SERVER_3_IP4" "/public"
test_unreachability "client" "[$SERVER_3_IP]" "/public"
set -e

# Set policy enforcement as default
cilium config PolicyEnforcement=default
endpoint_disable_policy $CLIENT_ID
endpoint_disable_policy $CLIENT_2_ID
endpoint_disable_policy $SERVER_ID
endpoint_disable_policy $SERVER_2_ID
endpoint_disable_policy $SERVER_3_ID

# Clean all ct entries
cilium bpf ct flush global

wait_for_endpoints 6

test_reachability "client" "$SERVER_3_IP4"                      # +2 CT entries
test_reachability "client" "[$SERVER_3_IP]"                     # +2 CT6 entries
test_reachability "client" "$SERVER_3_IP4" "/dummy"             # +2 CT entries
test_reachability "client" "[$SERVER_3_IP]" "/dummy"            # +2 CT6 entries
test_reachability_nc "client" 11111 "$SERVER_3_IP4" "/public"   # +2 CT entries
test_reachability_nc "client" 11111 "$SERVER_3_IP" "/public"    # +2 CT6 entries
test_reachability_nc "client" 11112 "$SERVER_3_IP4" "/public"   # +2 CT entries
test_reachability_nc "client" 11112 "$SERVER_3_IP" "/public"    # +2 CT6 entries
test_reachability_nc "client" 11111 "$SERVER_3_IP4" "/private"  # +0 CT entries since 5 tuple is the same
test_reachability_nc "client" 11111 "$SERVER_3_IP" "/private"   # +0 CT6 entries since 5 tuple is the same

bef_client_server_3_ct_entries=$(count_ct_entries_of "\[${SERVER_3_IP}\]" "\[${CLIENT_IP}\]" "${CLIENT_SEC_ID}")
bef_client4_server_3_ct_entries=$(count_ct_entries_of "${SERVER_3_IP4}" "${CLIENT_IP4}" "${CLIENT_SEC_ID}")

check_ct_entries_of_le "${bef_client_server_3_ct_entries}" 8 "${SERVER_3_IP}" "${CLIENT_IP}"
check_ct_entries_of_le "${bef_client4_server_3_ct_entries}" 8 "${SERVER_3_IP4}" "${CLIENT_IP4}"

# Install L7 rule after testing L4 to test if the connection is going
# to the proxy. Since we will use the same source port, after switching
# to L7 the connection should fail when trying to reach /private
log "Installing L7 policy while the L4 connection was previously made to confirm L7 policy enforcement over the proxy"

cat <<EOF | policy_import_and_wait -
[{
    "endpointSelector": {"matchLabels":{"id.server-3":""}},
    "ingress": [{
        "fromEndpoints": [{
           "matchLabels":{"id.client":""}
        }],
        "toPorts": [{
            "ports": [{"port": "80", "protocol": "tcp"}],
            "rules": {"http": [{
                  "path": "/public",
                  "method": "GET"
            }]}
        }]
    }],
    "labels": ["id=server-4"]
}]
EOF

sudo cilium bpf ct list global

if [ -n "${CILIUM_USE_ENVOY}" ]; then
  test_reachability "client" "$SERVER_3_IP4" "/public"
  test_reachability "client" "[$SERVER_3_IP]" "/public"
  test_reachability_nc "client" 11111 "$SERVER_3_IP4" "/public"
  test_reachability_nc "client" 11111 "$SERVER_3_IP" "/public"
  test_reachability_nc "client" 11112 "$SERVER_3_IP4" "/public"
  test_reachability_nc "client" 11112 "$SERVER_3_IP" "/public"
  # FIXME if we don't set +e, the return code from test_unreachability makes the
  # test to fail GH #1919
  set +e
  test_unreachability_nc "client" 11111 "$SERVER_3_IP4" "/private"
  test_unreachability_nc "client" 11111 "$SERVER_3_IP" "/private"
  set -e
  monitor_clear

  log "deleting all policies in cilium"
  policy_delete_and_wait --all
  # Clean all ct entries
  cilium bpf ct flush global

  wait_for_endpoints 6

  log "Testing if the CT deletes all entries except the ones specified in the policy"

  # FIXME use a http server that allows to specify multiple ports
  start_server_netcat 0.0.0.0 80
  test_reachability_port "client" "$SERVER_4_IP4" 80 "/dummy"
  start_server_netcat [::] 80
  test_reachability_port "client" "[$SERVER_4_IP]" 80 "/dummy"
  start_server_netcat 0.0.0.0 81
  test_reachability_port "client" "$SERVER_4_IP4" 81 "/dummy"
  start_server_netcat [::] 82
  test_reachability_port "client" "[$SERVER_4_IP]" 82 "/dummy"
  start_server_netcat 0.0.0.0 83
  test_reachability_port "client" "$SERVER_4_IP4" 83 "/dummy"
  start_server_netcat [::] 84
  test_reachability_port "client" "[$SERVER_4_IP]" 84 "/dummy"
  start_server_netcat 0.0.0.0 85
  test_reachability_port "client" "$SERVER_4_IP4" 85 "/dummy"
  start_server_netcat [::] 86
  test_reachability_port "client" "[$SERVER_4_IP]" 86 "/dummy"

  bef_client_server_4_ct_entries=$(count_ct_entries_of "\[${SERVER_4_IP4}\]" "\[${CLIENT_IP}\]" "${CLIENT_SEC_ID}")
  bef_client4_server_4_ct_entries=$(count_ct_entries_of "${SERVER_4_IP4}" "${CLIENT_IP4}" "${CLIENT_SEC_ID}")

  check_ct_entries_of_le "${bef_client_server_4_ct_entries}" 8 "${SERVER_4_IP}" "${CLIENT_IP}"
  check_ct_entries_of_le "${bef_client4_server_4_ct_entries}" 8 "${SERVER_4_IP4}" "${CLIENT_IP4}"

  cat <<EOF | policy_import_and_wait -
[{
    "endpointSelector": {"matchLabels":{"id.server-4":""}},
    "ingress": [{
        "fromEndpoints": [{
           "matchLabels":{"id.client":""}
        }],
        "toPorts": [{
            "ports": [{"port": "80", "protocol": "tcp"}],
            "rules": {"http": [{
                  "path": "/public",
                  "method": "GET"
            }]}
        }]
    },{
        "fromEndpoints": [{
           "matchLabels":{"id.client":""}
        }],
        "toPorts": [{
            "ports": [{"port": "81", "protocol": "tcp"},{"port": "82", "protocol": "tcp"}]
        }]
    }],
    "labels": ["id=server-4"]
}]
EOF

  sudo cilium bpf ct list global

  log "checking if only port 81 and port 82 are open the ct table since they are specified on a imported rule and are not going through the proxy"

  bef_client_server_4_ct_entries=$(count_ct_entries_of "\[${SERVER_4_IP4}\]" "\[${CLIENT_IP}\]" "${CLIENT_SEC_ID}")
  bef_client4_server_4_ct_entries=$(count_ct_entries_of "${SERVER_4_IP4}" "${CLIENT_IP4}" "${CLIENT_SEC_ID}")

  check_ct_entries_of_le "${bef_client_server_4_ct_entries}" 2 "${SERVER_4_IP}" "${CLIENT_IP}"
  check_ct_entries_of_le "${bef_client4_server_4_ct_entries}" 2 "${SERVER_4_IP4}" "${CLIENT_IP4}"
else
  log "Not using envoy proxy: skipping rest of CT tests due to oxy bug GH 2240"
fi

test_succeeded "${TEST_NAME}"

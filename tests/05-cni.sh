#!/bin/bash

export PATH=$PATH:/opt/cni/bin

dir=$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )
source "${dir}/helpers.bash"
# dir might have been overwritten by helpers.bash
dir=$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )

TEST_NAME=$(get_filename_without_extension $0)
LOGS_DIR="${dir}/cilium-files/${TEST_NAME}/logs"
redirect_debug_logs ${LOGS_DIR}

set -ex

server_id=""
client_id=""

logs_clear


function run_cni_container {
  LABELS=""
  ARGS=""

  while [[ $# != 0 ]]; do
    if [ "$1" == "-l" -o "$1" == "--label" ]; then
      LABELS="$LABELS -l $2"
    fi
    ARGS="$ARGS $1"
    shift
  done

  contid=$(docker run -t -d --net=none $LABELS busybox:latest)
  pid=$(docker inspect -f '{{ .State.Pid }}' $contid)
  netnspath=/proc/$pid/ns/net

  sudo -E PATH=$PATH:/opt/cni/bin ./exec-plugins.sh add $contid $netnspath

  docker run --net=container:$contid $ARGS > /dev/null

  echo $contid
}

function kill_cni_container {
  log "killing CNI container"
  if [ ! -z "$1" ]; then
    pid=$(docker inspect -f '{{ .State.Pid }}' $1)
    netnspath=/proc/$pid/ns/net

    sudo -E PATH=$PATH:/opt/cni/bin ./exec-plugins.sh del $1 $netnspath
    docker rm -f $1 >/dev/null
  fi

  clean_container $2
  log "finished killing CNI container"
}

function extract_ip4 {
  docker exec -i $1 ip -4 a show dev eth0 scope global | grep inet | sed -e 's%.*inet \(.*\)\/.*%\1%'
}

function extract_ip6 {
  docker exec -i $1 ip -6 a show dev eth0 scope global | grep inet6 | sed -e 's%.*inet6 \(.*\)\/.*%\1%'
}

function clean_container {
  log "removing Docker container $1"
  docker rm -f $1 2> /dev/null || true
}

function cleanup {
  log "beginning cleanup for ${TEST_NAME}"
  cilium policy delete --all 2> /dev/null || true
  kill_cni_container $server_id cni-server 2> /dev/null || true
  kill_cni_container $client_id cni-client 2> /dev/null || true
  monitor_stop
  rm -rf $DIR
  log "finished cleanup for ${TEST_NAME}"
}

function finish_test {
  gather_files ${TEST_NAME} ${TEST_SUITE}
  cleanup
}

trap finish_test EXIT
cleanup

clean_container cni-server
clean_container cni-client
DIR=$(mktemp -d)
cd $DIR

monitor_start


log "deleting all policies in Cilium"
cilium policy delete --all 2> /dev/null || true
cat <<EOF | policy_import_and_wait -
[{
    "endpointSelector": {"matchLabels":{"id.server":""}},
    "ingress": [{
        "fromEndpoints": [
	    {"matchLabels":{"reserved:host":""}},
	    {"matchLabels":{"id.client":""}}
	]
    }]
}]
EOF

mkdir net.d
cat > net.d/10-cilium-cni.conf <<EOF
{
	"name": "cilium",
	"type": "cilium-cni",
	"mtu": 1450
}
EOF
export NETCONFPATH=`pwd`/net.d

log "cloning CNI repository"
git clone 'https://github.com/containernetworking/cni'
cd cni
git checkout tags/v0.5.2
./build.sh
export CNI_PATH=`pwd`/bin
cp "${dir}/../plugins/cilium-cni/cilium-cni" "${CNI_PATH}"
cd scripts

server_id=$(run_cni_container -d -l id.server --name cni-server tgraf/netperf)
client_id=$(run_cni_container -d -l id.client --name cni-client tgraf/netperf)

server_ip=$(extract_ip6 $server_id)
server_ip4=$(extract_ip4 $server_id)

log "Waiting for containers to come up"
while true; do
  output=`docker ps -a`

  if echo ${output} | grep cni-server && \
     echo ${output} | grep cni-client; then
    break
  fi
done

monitor_clear
log "trying to ping6 server from cni-client (should work)"
docker exec -i cni-client ping6 -c 10 $server_ip
monitor_clear
if [ $server_ip4 ]; then
  log "trying to ping server from cni-client (should work)"
  docker exec -i cni-client ping -c 10 $server_ip4
fi

test_succeeded "${TEST_NAME}"

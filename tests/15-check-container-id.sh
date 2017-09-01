#!/usr/bin/env bash

source ./helpers.bash

CLIENT_LABEL="id.client"
SERVER_LABEL="id.server"

function cleanup {
  docker rm -f server client 2> /dev/null || true
}

function setup {
    logs_clear
    monitor_start
    echo "Logging at $DUMP_FILE"
    docker network rm ${TEST_NET} > /dev/null 2>&1
    create_cilium_docker_network
    cilium config PolicyEnforcement=always
}

trap cleanup EXIT

setup

docker run -d --net cilium --name server -l ${SERVER_LABEL} tgraf/netperf

cilium endpoint list

docker inspect --format '{{ .NetworkSettings.Networks.cilium.GlobalIPv6Address }}' server
SERVER_IP=$(docker inspect --format '{{ .NetworkSettings.Networks.cilium.GlobalIPv6Address }}' server)
SERVER_ID=$(cilium endpoint list | grep ${SERVER_LABEL} | awk '{ print $1}')

ping6 -c 1 ${SERVER_IP}

docker run -d --net cilium --name client -l ${CLIENT_LABEL} tgraf/netperf

CLIENT_IP=$(docker inspect --format '{{ .NetworkSettings.Networks.cilium.GlobalIPv6Address }}' client)
CLIENT_ID=$(cilium endpoint list | grep ${CLIENT_LABEL} | awk '{ print $1}')

cilium endpoint list

docker exec -ti client ping6 -c 1 ${SERVER_IP}

sudo cilium bpf policy list ${SERVER_ID}

docker exec -ti server ping6 -c 1 ${CLIENT_IP}

cilium endpoint config ${CLIENT_ID} Conntrack=false
cilium endpoint config ${SERVER_ID} Conntrack=false

docker exec -ti server ping6 -c 1 ${CLIENT_IP}
docker exec -ti client ping6 -c 1 ${SERVER_IP}

known_ids=(`cilium endpoint list| awk '{ if (NR > 1) print " "$1 }' |tr -d '\n'`)

grep "Attempting local delivery for container id " ${DUMP_FILE} | while read -r entry ; do
        # CPU 01: MARK 0x3de3947b FROM 48896 DEBUG: Attempting local delivery for container id 29381 from seclabel 263
        #                              ^                                                       ^
        # Above is the expected full example output.
        container_id=`echo ${entry} | awk '{ print $14 }'`
        from_id=`echo ${entry} | awk '{ print $5 }'`
        did_match=false

        if [[ "$container_id" == "$from_id" ]]; then
                abort "was not expecting container id ($container_id) to equal from ($from_id)"
        fi

        for id in "${known_ids[@]}"; do
                if [[ "$container_id" == "$id" ]]; then
                        did_match=true
                        break
                fi
        done

        if ! ${did_match} ; then
                abort "$container_id is not in the known list of ids"
        fi
done

monitor_stop

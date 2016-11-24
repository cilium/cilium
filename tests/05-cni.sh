#!/bin/bash

export PATH=$PATH:/opt/cni/bin

source "./helpers.bash"

server_id=""
client_id=""

set -e

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

	contid=$(docker run -d --net=none $LABELS busybox:latest /bin/sleep 10000000)
	pid=$(docker inspect -f '{{ .State.Pid }}' $contid)
	netnspath=/proc/$pid/ns/net

	sudo -E PATH=$PATH:/opt/cni/bin ./exec-plugins.sh add $contid $netnspath

	docker run --net=container:$contid $ARGS > /dev/null

	echo $contid
}

function kill_cni_container {
	if [ ! -z "$1" ]; then
		pid=$(docker inspect -f '{{ .State.Pid }}' $1)
		netnspath=/proc/$pid/ns/net

		sudo -E PATH=$PATH:/opt/cni/bin ./exec-plugins.sh del $1 $netnspath
		docker rm -f $1 >/dev/null
	fi

	clean_container $2
}

function extract_ip4 {
	docker exec -i $1 ip -4 a show dev eth0 scope global | grep inet | sed -e 's%.*inet \(.*\)\/.*%\1%'
}

function extract_ip6 {
	docker exec -i $1 ip -6 a show dev eth0 scope global | grep inet6 | sed -e 's%.*inet6 \(.*\)\/.*%\1%'
}

function clean_container {
	docker rm -f $1 2> /dev/null || true
}

function cleanup {
	kill_cni_container $server_id cni-server
	kill_cni_container $client_id cni-client
	monitor_stop
	rm -rf $DIR
}

trap cleanup EXIT

clean_container cni-server
clean_container cni-client
DIR=$(mktemp -d)
cd $DIR

monitor_start

cat <<EOF | cilium -D policy import -
{
        "name": "io.cilium",
        "children": {
		"client": { },
		"server": {
			"rules": [{
				"allow": ["reserved:host", "../client"]
			}]
		}

	}
}
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

git clone 'https://github.com/containernetworking/cni'
cd cni
./build
export CNI_PATH=`pwd`/bin
cd scripts

server_id=$(run_cni_container -d -l io.cilium.server --name cni-server noironetworks/netperf)
client_id=$(run_cni_container -d -l io.cilium.client --name cni-client noironetworks/netperf)

server_ip=$(extract_ip6 $server_id)
server_ip4=$(extract_ip4 $server_id)

echo "Waiting for containers to come up"
sleep 3s

monitor_clear
docker exec -i cni-client ping6 -c 5 $server_ip
monitor_clear
if [ $server_ip4 ]; then
	docker exec -i cni-client ping -c 5 $server_ip4
fi

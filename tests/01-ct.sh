#!/bin/bash

source "./helpers.bash"

set -e

function cleanup {
  docker rm -f server client httpd1 httpd2 curl curl2 2> /dev/null || true
  monitor_stop
}

function finish_test {
  gather_files 01-ct ${TEST_SUITE}
  cleanup 
}

function start_containers {
  set +x
  log "starting containers"
  docker run -dt --net=$TEST_NET --name server -l id.server tgraf/netperf
  docker run -dt --net=$TEST_NET --name httpd1 -l id.httpd httpd
  docker run -dt --net=$TEST_NET --name httpd2 -l id.httpd_deny httpd
  docker run -dt --net=$TEST_NET --name client -l id.client tgraf/netperf
  docker run -dt --net=$TEST_NET --name curl   -l id.curl tgraf/netperf
  docker run -dt --net=$TEST_NET --name curl2  -l id.curl tgraf/netperf
  wait_for_endpoints 6
  echo "containers started and ready"
  set -x
}

function get_container_metadata {
  set +x
  CLIENT_IP=$(docker inspect --format '{{ .NetworkSettings.Networks.cilium.GlobalIPv6Address }}' client)
  log "CLIENT_IP: $CLIENT_IP"
  CLIENT_IP4=$(docker inspect --format '{{ .NetworkSettings.Networks.cilium.IPAddress }}' client)
  log "CLIENT_IP4: $CLIENT_IP4"
  CLIENT_ID=$(cilium endpoint list | grep id.client | awk '{ print $1}')
  log "CLIENT_ID: $CLIENT_ID"
  SERVER_IP=$(docker inspect --format '{{ .NetworkSettings.Networks.cilium.GlobalIPv6Address }}' server)
  log "SERVER_IP: $SERVER_IP"
  SERVER_IP4=$(docker inspect --format '{{ .NetworkSettings.Networks.cilium.IPAddress }}' server)
  log "SERVER_IP4: $SERVER_IP4"
  SERVER_ID=$(cilium endpoint list | grep id.server | awk '{ print $1}')
  log "SERVER_ID: $SERVER_ID"
  HTTPD1_IP=$(docker inspect --format '{{ .NetworkSettings.Networks.cilium.GlobalIPv6Address }}' httpd1)
  log "HTTPD1_IP: $HTTPD1_IP"
  HTTPD1_IP4=$(docker inspect --format '{{ .NetworkSettings.Networks.cilium.IPAddress }}' httpd1)
  log "HTTPD1_IP4: $HTTPD1_IP4"
  HTTPD2_IP=$(docker inspect --format '{{ .NetworkSettings.Networks.cilium.GlobalIPv6Address }}' httpd2)
  log "HTTPD2_IP: $HTTPD2_IP"
  HTTPD2_IP4=$(docker inspect --format '{{ .NetworkSettings.Networks.cilium.IPAddress }}' httpd2)
  log "HTTPD2_IP4: $HTTPD2_IP4"
  set -x
} 

trap finish_test EXIT

cleanup
monitor_start
logs_clear

create_cilium_docker_network

start_containers
get_container_metadata


log "endpoint list output:"
cilium endpoint list

set -x

cat <<EOF | policy_import_and_wait -
[{
    "endpointSelector": {"matchLabels":{"id.curl":""}},
    "egress": [{
	    "toPorts": [{
		    "ports": [{"port": "80", "protocol": "tcp"}]
	    }]
    }],
    "labels": ["id=curl"]
},{
    "endpointSelector": {"matchLabels":{"id.server":""}},
    "ingress": [{
        "fromEndpoints": [
	    {"matchLabels":{"reserved:host":""}},
	    {"matchLabels":{"id.client":""}}
	]
    }],
    "labels": ["id=server"]
},{
    "endpointSelector": {"matchLabels":{"id.httpd":""}},
    "ingress": [{
        "fromEndpoints": [
	    {"matchLabels":{"id.curl":""}}
	],
	"toPorts": [
	    {"ports": [{"port": "80", "protocol": "tcp"}]}
	]
    }],
    "labels": ["id=httpd"]
},{
    "endpointSelector": {"matchLabels":{"id.httpd":""}},
    "ingress": [{
        "fromEndpoints": [
	    {"matchLabels":{"id.curl2":""}}
	],
	"toPorts": [
	    {"ports": [{"port": "8080", "protocol": "tcp"}]}
	]
    }],
    "labels": ["id=httpd"]
},{
    "endpointSelector": {"matchLabels":{"id.httpd_deny":""}},
    "ingress": [{
        "fromEndpoints": [
	    {"matchLabels":{"id.curl":""}}
	],
	"toPorts": [
	    {"ports": [{"port": "9090", "protocol": "tcp"}]}
	]
    }],
    "labels": ["id=httpd_deny"]
}]
EOF

wait_for_endpoints 6

function connectivity_test() {
  monitor_clear
  docker exec -i curl bash -c "curl --connect-timeout 5 -XGET http://[$HTTPD1_IP]:80" || {
    abort "Error: Could not reach httpd1 on port 80"
  }

  monitor_clear
  docker exec -i curl bash -c "curl --connect-timeout 5 -XGET http://$HTTPD1_IP4:80" || {
    abort "Error: Could not reach httpd1 on port 80"
  }

  # FIXME(amre): Change following two expectations to the opposite when Issue #789 is fixed
  monitor_clear
  docker exec -i curl2 bash -c "curl --connect-timeout 5 -XGET http://[$HTTPD1_IP]:80" || {
    abort "Error: Could not reach httpd1 on port 80"
  }

  monitor_clear
  docker exec -i curl2 bash -c "curl --connect-timeout 5 -XGET http://$HTTPD1_IP4:80" || {
    abort "Error: Could not reach httpd1 on port 80"
  }

  monitor_clear
  docker exec -i curl bash -c "curl --connect-timeout 5 -XGET http://[$HTTPD2_IP]:80" && {
    abort "Error: Unexpected success reaching httpd2 on port 80"
  }

  monitor_clear
  docker exec -i curl bash -c "curl --connect-timeout 5 -XGET http://$HTTPD2_IP4:80" && {
    abort "Error: Unexpected success reaching httpd2 on port 80"
  }

  # ICMPv6 echo request client => server should succeed
  monitor_clear
  docker exec -i client ping6 -c 5 $SERVER_IP || {
    abort "Error: Could not ping server container from client"
  }

  if [ $SERVER_IP4 ]; then
    # ICMPv4 echo request client => server should succeed
    monitor_clear
    docker exec -i client ping -c 5 $SERVER_IP4 || {
      abort "Error: Could not ping server container from client"
    }
  fi

  # ICMPv6 echo request host => server should succeed
  monitor_clear
  ping6 -c 5 $SERVER_IP || {
    abort "Error: Could not ping server container from host"
  }

  if [ $SERVER_IP4 ]; then
    # ICMPv4 echo request host => server should succeed
    monitor_clear
    ping -c 5 $SERVER_IP4 || {
      abort "Error: Could not ping server container from host"
    }
  fi

  # FIXME: IPv4 host connectivity not working yet

  if [ $BIDIRECTIONAL = 1 ]; then
    # ICMPv6 echo request server => client should not succeed
    monitor_clear
    docker exec -i server ping6 -c 2 $CLIENT_IP && {
      abort "Error: Unexpected success of ICMPv6 echo request"
    }

    if [ $CLIENT_IP4 ]; then
      # ICMPv4 echo request server => client should not succeed
      monitor_clear
      docker exec -i server ping -c 2 $CLIENT_IP4 && {
        abort "Error: Unexpected success of ICMPv4 echo request"
      }
    fi
  fi

  # TCP request to closed port should fail
  monitor_clear
  docker exec -i client nc -w 5 $SERVER_IP 777 && {
    abort "Error: Unexpected success of TCP IPv6 session to port 777"
  }

  if [ $SERVER_IP4 ]; then
    # TCP request to closed port should fail
    monitor_clear
    docker exec -i client nc -w 5 $SERVER_IP4 777 && {
      abort "Error: Unexpected success of TCP IPv4 session to port 777"
    }
  fi

  # TCP client=>server should succeed
  monitor_clear
  docker exec -i client netperf -l 3 -t TCP_RR -H $SERVER_IP || {
    abort "Error: Unable to reach netperf TCP IPv6 endpoint"
  }

  if [ $SERVER_IP4 ]; then
    # TCP client=>server should succeed
    monitor_clear
    docker exec -i client netperf -l 3 -t TCP_RR -H $SERVER_IP4 || {
      abort "Error: Unable to reach netperf TCP IPv4 endpoint"
    }
  fi

  # FIXME: Need shorter timeout
  # TCP server=>client should not succeed
  #docker exec -i server netperf -l 3 -t TCP_RR -H $CLIENT_IP && {
  #	abort "Error: Unexpected success of TCP netperf session"
  #}

  # UDP client=server should succeed
  monitor_clear
  docker exec -i client netperf -l 3 -t UDP_RR -H $SERVER_IP || {
    abort "Error: Unable to reach netperf TCP IPv6 endpoint"
  }

  if [ $SERVER_IP4 ]; then
    # UDP client=server should succeed
    monitor_clear
    docker exec -i client netperf -l 3 -t UDP_RR -H $SERVER_IP4 || {
      abort "Error: Unable to reach netperf TCP IPv4 endpoint"
    }
  fi

  # FIXME: Need shorter timeout
  # TCP server=>client should not succeed
  #docker exec -i server netperf -l 3 -t UDP_RR -H $CLIENT_IP && {
  #	abort "Error: Unexpected success of UDP netperf session"
  #}
}

BIDIRECTIONAL=1
connectivity_test
cilium endpoint config $SERVER_ID ConntrackLocal=true || {
	abort "Error: Unable to change config for $SERVER_ID"
}
cilium endpoint config $CLIENT_ID ConntrackLocal=true || {
  abort "Error: Unable to change config for $CLIENT_ID"
}
connectivity_test
cilium endpoint config $SERVER_ID ConntrackLocal=false || {
  abort "Error: Unable to change config for $SERVER_ID"
}
cilium endpoint config $CLIENT_ID ConntrackLocal=false || {
  abort "Error: Unable to change config for $CLIENT_ID"
}
connectivity_test
cilium endpoint config $SERVER_ID Conntrack=false || {
  abort "Error: Unable to change config for $SERVER_ID"
}
cilium endpoint config $CLIENT_ID Conntrack=false || {
  abort "Error: Unable to change config for $CLIENT_ID"
}
wait_for_endpoints 6
BIDIRECTIONAL=0
connectivity_test

entriesBefore=$(sudo cilium bpf ct list global | wc -l)

policy_delete_and_wait id=httpd

# FIXME: Disabled for now, need a reliable way to know when this happened as it occurs async
#entriesAfter=$(sudo cilium bpf ct list global | wc -l)

#if [ "${entriesAfter}" -eq 0 ]; then
#    abort "CT map should not be empty"
#elif [ "${entriesBefore}" -le "${entriesAfter}" ]; then
#    abort "some of the CT entries should have been removed after policy change"
#fi

cilium policy delete --all

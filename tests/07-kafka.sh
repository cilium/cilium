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
  cilium policy delete --all 2> /dev/null || true
  docker rm -f kafka zook client 2> /dev/null || true
}

function finish_test {
  gather_files ${TEST_NAME} ${TEST_SUITE}
  cleanup
}

trap finish_test EXIT

KAFKA_LABEL="id.kafka"
ZOOK_LABEL="id.zook"
CLIENT_LABEL="id.client"

cleanup
logs_clear

function proxy_init {
  log "beginning proxy_init"
  create_cilium_docker_network

  docker run -dt --net=$TEST_NET --name zook -l $ZOOK_LABEL digitalwonderland/zookeeper
  wait_for_docker_ipv6_addr zook
  ZOOK_IP4=$(docker inspect --format '{{ .NetworkSettings.Networks.cilium.IPAddress }}' zook)

  docker run -dt --net=$TEST_NET --name kafka -e KAFKA_ZOOKEEPER_CONNECT=$ZOOK_IP4:2181 -l $KAFKA_LABEL wurstmeister/kafka
  KAFKA_IP4=$(docker inspect --format '{{ .NetworkSettings.Networks.cilium.IPAddress }}' kafka)

  docker run -dt --net=cilium --name client -l $CLIENT_LABEL cilium/kafkaclient2
  CLIENT_IP4=$(docker inspect --format '{{ .NetworkSettings.Networks.cilium.IPAddress }}' client)

  wait_for_docker_ipv6_addr kafka
  wait_for_docker_ipv6_addr client

  wait_for_cilium_ep_gen
  cilium endpoint list
  log "finished proxy_init"
}

function policy_single_ingress {
  cilium policy delete --all
  cat <<EOF | policy_import_and_wait -
[{
    "endpointSelector": {"matchLabels":{"id.kafka":""}},
    "ingress": [{
        "fromEndpoints": [
	    {"matchLabels":{"reserved:host":""}},
	    {"matchLabels":{"id.client":""}}
	],
	"toPorts": [{
	    "ports": [{"port": "9092", "protocol": "tcp"}],
	    "rules": {
                "kafka": [{
		    "apiKey": "metadata"
                },{
		    "apiKey": "apiversions"
                },{
                    "apiKey": "findcoordinator"
                },{
                    "apiKey": "joingroup"
                },{
                    "apiKey": "leavegroup"
                },{
                    "apiKey": "syncgroup"
                },{
                    "apiKey": "offsets"
                },{
                    "apiKey": "offsetcommit"
                },{
                    "apiKey": "heartbeat"
                },{
                    "topic": "allowedTopic"
                }]
	    }
	}]
    }]
}]
EOF
}

function create_topic {
  docker exec -i client /opt/kafka/bin/kafka-topics.sh --create --zookeeper zook:2181 --replication-factor 1 --partitions 1 --topic $1 || {
    abort "Error: Unable to create Kafka topic $1"
  }
}

function proxy_test {
  log "beginning proxy test"
  wait_for_endpoints 3

  create_topic "allowedTopic"
  create_topic "disallowedTopic"

  echo "Available Kafka topics:"
  docker exec -i client /opt/kafka/bin/kafka-topics.sh --list --zookeeper zook:2181 || {
    abort "Error: Unable to list Kafka topics"
  }

  # Setup consumer, waiting for 5 messages on topic allowedTopic, timeout=30s
  docker exec client /opt/kafka/bin/kafka-console-consumer.sh --bootstrap-server kafka:9092 --topic allowedTopic --max-messages 5 --timeout-ms 30000 &
  consumer_pid=$!

  kafka_consumer_delay

  for i in $(seq 1 5); do
    message="This is test message $i"
    echo $message | docker exec -i client /opt/kafka/bin/kafka-console-producer.sh --broker-list kafka:9092 --topic allowedTopic || {
      abort "Error: Unable to produce to topic allowedTopic"
    }
  done

  wait $consumer_pid || {
    abort "Error: Kafka consumer returned with an error"
  }
}

proxy_init
policy_single_ingress

wait_for_cilium_ep_gen
cilium endpoint list
proxy_test

log "deleting all policies from Cilium"
cilium policy delete --all 2> /dev/null || true
log "removing containers"
docker rm -f kafka zook client 2> /dev/null || true
wait_for_cilium_ep_gen

test_succeeded "${TEST_NAME}"

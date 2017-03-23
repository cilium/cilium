#!/usr/bin/env bash

. $(dirname ${BASH_SOURCE})/../../contrib/shell/util.sh

dir=$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )

run ""

desc "Import kubernetes' network policy when kubernetes is ready"
run "${dir}/../../examples/kubernetes/0-policy.sh 300"
desc "Import guestbook's replication controller and service to kubernetes"
run "${dir}/../../examples/kubernetes/1-guestbook.sh 300"
desc "Success!"
desc "Wait until the guestbook's service is ready"
run "${dir}/../../tests/wait-for-docker.bash k8s_guestbook 100"
desc "Success!"
desc "Wait until the redis-slave's service is ready"
run "${dir}/../../tests/wait-for-docker.bash k8s_redis-slave 100"
desc "Success!"
desc "Wait until the redis-master's service is ready"
run "${dir}/../../tests/wait-for-docker.bash k8s_redis-master 100"
desc "Success!"
desc ""
desc "List the services which have been installed"
run "sudo cilium service list"

containerID=$(docker ps -aq --filter=name=k8s_guestbook)
desc "Ping will not work because we are not load balancing ICMP messages for the redis-master service"
run "docker exec -ti ${containerID} ping6 -c 2 redis-master"

run "cilium endpoint list"
redis_master_IP_dirty=$(docker exec -ti `docker ps -aq --filter=name=k8s_redis-master` sh -c "ip -6 a s | grep global | grep -oE \"${ipv6regex}\" ")
redis_master_IP=$(echo ${redis_master_IP_dirty}|tr -d '\r')
desc "Although it will work if we directly ping the redis-master container's IP"
run "docker exec -ti ${containerID} ping6 -c 2 ${redis_master_IP}"

desc "We are load balancing services, so we will \"ping\" the redis service on port 6379"
run "docker exec -ti ${containerID} sh -c 'nc redis-master 6379 <<EOF
PING
EOF'"

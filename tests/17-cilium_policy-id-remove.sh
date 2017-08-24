#!/bin/bash

source ./helpers.bash

function cleanup {
	gather_files 17-cilium_policy-id-remove ${TEST_SUITE}
	docker rm -f a b 2> /dev/null || true
	docker network rm $TEST_NET > /dev/null 2>&1
}

trap cleanup EXIT

cleanup
logs_clear

create_cilium_docker_network

docker run -dt --net=$TEST_NET --name a -l id.a tgraf/netperf
docker run -dt --net=$TEST_NET --name b -l id.b tgraf/netperf

known_endpoints=`cilium endpoint list|awk 'NR>2 { print $1 }'`

# Sanity check
for ep in $known_endpoints; do
  ep_policy_map="/sys/fs/bpf/tc/globals/cilium_policy_$ep"
  if [ ! -f $ep_policy_map ]; then
    abort "No such file $ep_policy_map"
  fi
done

docker rm -f a b

# There should only be one cilium_policy file after the containers are gone.
# Ignoring the reserved files.
actual=`find /sys/fs/bpf/tc/globals/cilium_policy*|grep -v reserved`
expected="/sys/fs/bpf/tc/globals/cilium_policy"
if [ "$actual" != "$expected" ]; then
  abort "want $expected got $actual"
fi

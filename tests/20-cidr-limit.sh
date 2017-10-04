#!/bin/bash

# GH-1686 Re-enable when fixed
exit 0

dir=$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )
source "${dir}/helpers.bash"
# dir might have been overwritten by helpers.bash
dir=$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )

TEST_NAME=$(get_filename_without_extension $0)
LOGS_DIR="${dir}/cilium-files/${TEST_NAME}/logs"
redirect_debug_logs ${LOGS_DIR}

set -ex # Required for the linter
set +x # Reduce noise

function create_artifacts() {
  gather_files 20-cidr-limit ${TEST_SUITE}
}

function cleanup() {
  docker rm -f id.service2 2> /dev/null || true
  # FIXME: use daemon cleanup flag when implemented,
  # GH-979 (Provide a cilium-agent flag to clean all state data)
  systemctl stop cilium
  rm -r /sys/fs/bpf/tc/globals/ 2> /dev/null
  rm -r /var/run/cilium/state/ 2> /dev/null
  systemctl start cilium
}

trap create_artifacts EXIT
trap cleanup EXIT

ID=""
function spin_up_container() {
  docker run -d --net $TEST_NET -l id.service2 --name id.service2 httpd
  wait_for_endpoints 1

  cilium config Debug=True
  ID=`cilium endpoint list|grep service|awk '{ print $1}'`
  log "endpoint is $ID"
  cilium endpoint config $ID Debug=true
}

function gen_policy() {
  policy_file=$1
  max_ent=$2
  function gen_ent() {
      for x in $(seq 1 $max_ent); do
        i=$(( ( RANDOM % 31 )  + 1 ))
        b=$(( ( RANDOM % 255 )  + 1 ))
        c=$(( ( RANDOM % 255 )  + 1 ))
        d=$(( ( RANDOM % 255 )  + 1 ))
        echo "          \"20.$b.$c.$d/$i\"," >> $policy_file
      done
  }

  echo "[" >> $policy_file
  echo "  {" >> $policy_file
  echo "    \"endpointSelector\": {" >> $policy_file
  echo "      \"matchLabels\": {" >> $policy_file
  echo "        \"any:id.service2\": \"\"" >> $policy_file
  echo "      }" >> $policy_file
  echo "    }," >> $policy_file
  echo "    \"egress\": [" >> $policy_file
  echo "      {" >> $policy_file
  echo "	\"toCIDR\": [ " >> $policy_file
  gen_ent
  echo "          \"1.0.0.0/32\"" >> $policy_file
  echo "        ]," >> $policy_file
  echo "	\"fromCIDR\": [ " >>  $policy_file
  gen_ent
  echo "          \"1.0.0.0/24\"" >> $policy_file
  echo "        ]" >> $policy_file
  echo "      }" >> $policy_file
  echo "    ]" >> $policy_file
  echo "  }" >> $policy_file
  echo "]" >> $policy_file
}

create_cilium_docker_network
spin_up_container

log "will generate and import random policies"
SINCE="$(date +'%F %T')"
for x in $(seq 1 3); do
  for i in $(seq 20 41); do
    policy_file=`mktemp`
    gen_policy $policy_file $i
    # At some point max limit can be reached by import even though it might be
    # too late.
    if ! cilium policy import $policy_file > /dev/null; then
      break
    fi
  done
done

# Check logs for verifier output, should not be present on success.
if journalctl --no-pager --since "${SINCE}" -u cilium | grep "Verifier analysis"; then
  abort "verifier in log"
fi

test_succeeded "${TEST_NAME}"

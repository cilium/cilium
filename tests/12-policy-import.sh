#!/bin/bash

dir=$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )
source "${dir}/helpers.bash"
# dir might have been overwritten by helpers.bash
dir=$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )

TEST_NAME=$(get_filename_without_extension $0)
LOGS_DIR="${dir}/cilium-files/${TEST_NAME}/logs"
redirect_debug_logs ${LOGS_DIR}

set -ex

DENIED="Final verdict: DENIED"
ALLOWED="Final verdict: ALLOWED"


function test_policy_trace_policy_disabled {
  # If policy enforcement is disabled, then `cilium policy trace` should return that traffic is allowed between all security identities.
  wait_for_endpoints 3
  local FOO_ID=$(cilium endpoint list | grep id.foo | awk '{print $1}')
  local BAR_ID=$(cilium endpoint list | grep id.bar | awk '{ print $1}')
  log "verify verbose trace for expected output using endpoint IDs "
  local TRACE_OUTPUT=$(cilium policy trace --src-endpoint $FOO_ID --dst-endpoint $BAR_ID -v)
  log "Trace output: ${TRACE_OUTPUT}"
  local DIFF=$(diff -Nru <(echo "$ALLOWED") <(cilium policy trace --src-endpoint $FOO_ID --dst-endpoint $BAR_ID -v | grep "Final verdict:")) || true
  if [[ "$DIFF" != "" ]]; then
    abort "DIFF: $DIFF"
  fi
}

function cleanup {
  log "beginning cleanup for ${TEST_NAME}"
  log "deleting all policies"
  cilium policy delete --all 2> /dev/null || true
  log "removing containers foo, bar, and baz"
  docker rm -f foo bar baz 2> /dev/null || true
  log "removing Docker network $TEST_NET"
  remove_cilium_docker_network
  log "finished cleanup for ${TEST_NAME}"
}

function finish_test {
  log "beginning finishing up ${TEST_NAME}"
  gather_files ${TEST_NAME} ${TEST_SUITE}
  cleanup
  log "done finishing up ${TEST_NAME}"
}

trap finish_test EXIT
cleanup
logs_clear

create_cilium_docker_network

log "simple policy import"

cat <<EOF | cilium -D policy import -
[{
    "endpointSelector": {"matchLabels":{"role":"frontend"}}
}]
EOF

read -d '' EXPECTED_POLICY <<"EOF" || true
[
  {
    "endpointSelector": {
      "matchLabels": {
        "any:role": "frontend"
      }
    }
  }
]
EOF

DIFF=$(diff -Nru  <(cilium policy get | grep -v Revision:) <(echo "$EXPECTED_POLICY")) || true
if [[ "$DIFF" != "" ]]; then
  abort "$DIFF"
fi

cilium policy delete --all

log "get on empty policy should succeed"
cilium policy get

log "import policy with labels"
cat <<EOF | cilium -D policy import -
[{
    "endpointSelector": {"matchLabels":{"role":"frontend"}},
    "labels": ["key1"]
},{
    "endpointSelector": {"matchLabels":{"role":"frontend"}},
    "labels": ["key2"]
},{
    "endpointSelector": {"matchLabels":{"role":"frontend"}},
    "labels": ["key3"]
}]
EOF

log "retrieve policy by labels"
cilium policy get key1
cilium policy get key2
cilium policy get key3

log "delete policy with label key2"
cilium policy delete key2
cilium policy get key2 > /dev/null &&
	abort "policy rule [key2] should have been deleted"

log "policy key1 and key3 should still exist"
cilium policy get key1
cilium policy get key3

log "delete policy key1 key3"
cilium policy delete key1
cilium policy delete key3

log "policy empty again, get must still succeed"
cilium policy get

log "delete --all on already empty policy"
cilium policy delete --all

log "validate (localhost|foo)=>bar policy"

docker run -dt --net=$TEST_NET --name foo -l id.foo -l id.teamA tgraf/netperf
docker run -dt --net=$TEST_NET --name bar -l id.bar -l id.teamA tgraf/netperf
docker run -dt --net=$TEST_NET --name baz -l id.baz tgraf/netperf

cat <<EOF | cilium -D policy import -
[{
    "endpointSelector": {"matchLabels":{"id.bar":""}},
    "ingress": [{
        "fromEndpoints": [
	    {"matchLabels":{"reserved:host":""}},
	    {"matchLabels":{"id.foo":""}}
	]
    }]
}]
EOF

log "verify trace for expected output"
DIFF=$(diff -Nru <(echo "$ALLOWED") <(cilium policy trace -s id.foo -d id.bar | grep "Final verdict:")) || true
if [[ "$DIFF" != "" ]]; then
  abort "$DIFF"
fi

BAR_ID=$(cilium endpoint list | grep id.bar | awk '{ print $1}')
FOO_SEC_ID=$(cilium endpoint list | grep id.foo | awk '{ print $3}')

EXPECTED_CONSUMER="1\n$FOO_SEC_ID"

log "verify allowed consumers"
DIFF=$(diff -Nru <(echo -e "$EXPECTED_CONSUMER") <(cilium endpoint get $BAR_ID | jq '.[].policy | .["allowed-consumers"] | .[]' | sort)) || true
if [[ "$DIFF" != "" ]]; then
  abort "$DIFF"
fi

cilium policy delete --all

log "validate foo=>bar && teamA requires teamA policy"

cat <<EOF | cilium -D policy import -
[{
    "endpointSelector": {"matchLabels":{"id.bar":""}},
    "ingress": [{
        "fromEndpoints": [
	    {"matchLabels":{"id.foo":""}}
	]
    }]
},{
    "endpointSelector": {"matchLabels":{"id.teamA":""}},
    "ingress": [{
        "fromRequires": [
	    {"matchLabels":{"id.teamA":""}}
	]
    }]
}]
EOF

log "verify trace for expected output"
DIFF=$(diff -Nru <(echo "$ALLOWED") <(cilium policy trace -s id.foo -d id.bar | grep "Final verdict:")) || true
if [[ "$DIFF" != "" ]]; then
	abort "$DIFF"
fi

log "verify verbose trace for expected output using source and destination labels"
DIFF=$(diff -Nru <(echo "$ALLOWED") <(cilium policy trace -s id.foo -d id.bar -v | grep "Final verdict:")) || true
if [[ "$DIFF" != "" ]]; then
  abort "$DIFF"
fi

FOO_ID=$(cilium endpoint list | grep id.foo | awk '{print $1}')
BAR_ID=$(cilium endpoint list | grep id.bar | awk '{ print $1}')
FOO_SEC_ID=$(cilium endpoint list | grep id.foo | awk '{ print $3}')
BAR_SEC_ID=$(cilium endpoint list | grep id.bar | awk '{print $3}')

log "verify verbose trace for expected output using security identities"
DIFF=$(diff -Nru <(echo "$ALLOWED") <(cilium policy trace --src-identity $FOO_SEC_ID --dst-identity $BAR_SEC_ID -v | grep "Final verdict:")) || true
if [[ "$DIFF" != "" ]]; then
  abort "DIFF: $DIFF"
fi

log "verify verbose trace for expected output using endpoint IDs"
DIFF=$(diff -Nru <(echo "$ALLOWED") <(cilium policy trace --src-endpoint $FOO_ID --dst-endpoint $BAR_ID -v | grep "Final verdict:")) || true
if [[ "$DIFF" != "" ]]; then
  abort "DIFF: $DIFF"
fi

EXPECTED_CONSUMER="$FOO_SEC_ID"

log "verify allowed consumers"
DIFF=$(diff -Nru <(echo -e "$EXPECTED_CONSUMER") <(cilium endpoint get $BAR_ID | jq '.[].policy | .["allowed-consumers"] | .[]')) || true
if [[ "$DIFF" != "" ]]; then
  abort "$DIFF"
fi

log "verify max ingress nports is enforced"

set +e
cat <<EOF | cilium -D policy import -
[{
	"endpointSelector": {
		"matchLabels": {
			"foo": ""
		}
	},
	"ingress": [{
		"fromEndpoints": [{
				"matchLabels": {
					"reserved:host": ""
				}
			},
			{
				"matchLabels": {
					"bar": ""
				}
			}
		],
		"toPorts": [{
			"ports": [{
					"port": "1",
					"protocol": "tcp"
				},
				{
					"port": "2",
					"protocol": "tcp"
				},
				{
					"port": "3",
					"protocol": "tcp"
				},
				{
					"port": "4",
					"protocol": "tcp"
				},
				{
					"port": "5",
					"protocol": "tcp"
				},
				{
					"port": "6",
					"protocol": "tcp"
				},
				{
					"port": "7",
					"protocol": "tcp"
				},
				{
					"port": "8",
					"protocol": "tcp"
				},
				{
					"port": "9",
					"protocol": "tcp"
				},
				{
					"port": "10",
					"protocol": "tcp"
				},
				{
					"port": "11",
					"protocol": "tcp"
				},
				{
					"port": "12",
					"protocol": "tcp"
				},
				{
					"port": "13",
					"protocol": "tcp"
				},
				{
					"port": "14",
					"protocol": "tcp"
				},
				{
					"port": "15",
					"protocol": "tcp"
				},
				{
					"port": "16",
					"protocol": "tcp"
				},
				{
					"port": "17",
					"protocol": "tcp"
				},
				{
					"port": "18",
					"protocol": "tcp"
				},
				{
					"port": "19",
					"protocol": "tcp"
				},
				{
					"port": "20",
					"protocol": "tcp"
				},
				{
					"port": "21",
					"protocol": "tcp"
				},
				{
					"port": "22",
					"protocol": "tcp"
				},
				{
					"port": "23",
					"protocol": "tcp"
				},
				{
					"port": "24",
					"protocol": "tcp"
				},
				{
					"port": "25",
					"protocol": "tcp"
				},
				{
					"port": "26",
					"protocol": "tcp"
				},
				{
					"port": "27",
					"protocol": "tcp"
				},
				{
					"port": "28",
					"protocol": "tcp"
				},
				{
					"port": "29",
					"protocol": "tcp"
				},
				{
					"port": "30",
					"protocol": "tcp"
				},
				{
					"port": "31",
					"protocol": "tcp"
				},
				{
					"port": "32",
					"protocol": "tcp"
				},
				{
					"port": "33",
					"protocol": "tcp"
				},
				{
					"port": "34",
					"protocol": "tcp"
				},
				{
					"port": "35",
					"protocol": "tcp"
				},
				{
					"port": "36",
					"protocol": "tcp"
				},
				{
					"port": "37",
					"protocol": "tcp"
				},
				{
					"port": "38",
					"protocol": "tcp"
				},
				{
					"port": "39",
					"protocol": "tcp"
				},
				{
					"port": "40",
					"protocol": "tcp"
				},
				{
					"port": "41",
					"protocol": "tcp"
				}
			]
		}]
	}]
}]
EOF

if [ "$?" -ne 1 ]; then
  abort "expected L4 policy with more than 40 ports to fail"
fi
set -e

policy_delete_and_wait "--all"
test_policy_trace_policy_disabled

test_succeeded "${TEST_NAME}"

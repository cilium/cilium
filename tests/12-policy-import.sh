#!/bin/bash

source "./helpers.bash"

DENIED="Result: DENIED"
ALLOWED="Result: ALLOWED"

function cleanup {
	gather_files 12-policy-import ${TEST_SUITE}
	cilium policy delete --all 2> /dev/null || true
	docker rm -f foo foo bar baz 2> /dev/null || true
	docker network rm $TEST_NET > /dev/null 2>&1
}

trap cleanup EXIT
cleanup
logs_clear

create_cilium_docker_network

echo "------ simple policy import ------"

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

echo "------ get on empty policy should succeed ------"
cilium policy get

echo "------ import policy with labels ------"
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

echo "------ retrieve policy by labels ------"
cilium policy get key1
cilium policy get key2
cilium policy get key3

echo "------ delete policy with label key2 ------"
cilium policy delete key2
cilium policy get key2 > /dev/null &&
	abort "policy rule [key2] should have been deleted"

echo "------ policy key1 and key3 should still exist ------"
cilium policy get key1
cilium policy get key3

echo "------ delete policy key1 key3 ------"
cilium policy delete key1
cilium policy delete key3

echo "------ policy empty again, get must still succeed ------"
cilium policy get

echo "------ delete --all on already empty policy ------"
cilium policy delete --all

echo "------ validate (localhost|foo)=>bar policy ------"

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

read -d '' EXPECTED_POLICY <<"EOF" || true
----------------------------------------------------------------
Tracing From: [any:id.foo] => To: [any:id.bar]
* Rule 0 {"matchLabels":{"any:id.bar":""}}: match
    Allows from labels {"matchLabels":{"reserved:host":""}}
      Labels [any:id.foo] not found
    Allows from labels {"matchLabels":{"any:id.foo":""}}
+     Found all required labels
1 rules matched
Result: ALLOWED
L3 verdict: allowed

Verdict: allowed

EOF

echo "------ verify trace for expected output ------"
DIFF=$(diff -Nru <(echo "$EXPECTED_POLICY") <(cilium policy trace -s id.foo -d id.bar)) || true
if [[ "$DIFF" != "" ]]; then
	abort "$DIFF"
fi

BAR_ID=$(cilium endpoint list | grep id.bar | awk '{ print $1}')
FOO_SEC_ID=$(cilium endpoint list | grep id.foo | awk '{ print $3}')

EXPECTED_CONSUMER="1\n$FOO_SEC_ID"

echo "------ verify allowed consumers ------"
DIFF=$(diff -Nru <(echo -e "$EXPECTED_CONSUMER") <(cilium endpoint get $BAR_ID | jq '.policy | .["allowed-consumers"] | .[]' | sort)) || true
if [[ "$DIFF" != "" ]]; then
	abort "$DIFF"
fi

cilium policy delete --all

echo "------ validate foo=>bar && teamA requires teamA policy ------"

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

read -d '' EXPECTED_POLICY <<"EOF" || true
----------------------------------------------------------------
Tracing From: [any:id.foo] => To: [any:id.bar]
* Rule 0 {"matchLabels":{"any:id.bar":""}}: match
    Allows from labels {"matchLabels":{"any:id.foo":""}}
+     Found all required labels
1 rules matched
Result: ALLOWED
L3 verdict: allowed

Verdict: allowed

EOF

echo "------ verify trace for expected output ------"
DIFF=$(diff -Nru <(echo "$EXPECTED_POLICY") <(cilium policy trace -s id.foo -d id.bar)) || true
if [[ "$DIFF" != "" ]]; then
	abort "$DIFF"
fi

read -d '' EXPECTED_POLICY <<"EOF" || true
----------------------------------------------------------------
Tracing From: [any:id.foo] => To: [any:id.bar]
* Rule 0 {"matchLabels":{"any:id.bar":""}}: match
    Allows from labels {"matchLabels":{"any:id.foo":""}}
+     Found all required labels
  Rule 1 {"matchLabels":{"any:id.teamA":""}}: no match for [any:id.bar]
1 rules matched
Result: ALLOWED
L3 verdict: allowed

Verdict: allowed

EOF


echo "------ verify verbose trace for expected output using source and destination labels ------"
DIFF=$(diff -Nru <(echo "$EXPECTED_POLICY") <(cilium policy trace -s id.foo -d id.bar -v)) || true
if [[ "$DIFF" != "" ]]; then
  abort "$DIFF"
fi

FOO_ID=$(cilium endpoint list | grep id.foo | awk '{print $1}')
BAR_ID=$(cilium endpoint list | grep id.bar | awk '{ print $1}')
FOO_SEC_ID=$(cilium endpoint list | grep id.foo | awk '{ print $3}')
BAR_SEC_ID=$(cilium endpoint list | grep id.bar | awk '{print $3}')

read -d '' EXPECTED_POLICY <<"EOF" || true
----------------------------------------------------------------
Tracing From: [container:id.foo, container:id.teamA] => To: [container:id.bar, container:id.teamA]
* Rule 0 {"matchLabels":{"any:id.bar":""}}: match
    Allows from labels {"matchLabels":{"any:id.foo":""}}
+     Found all required labels
* Rule 1 {"matchLabels":{"any:id.teamA":""}}: match
    Requires from labels {"matchLabels":{"any:id.teamA":""}}
+     Found all required labels
2 rules matched
Result: ALLOWED
L3 verdict: allowed

Verdict: allowed

EOF


echo "------ verify verbose trace for expected output using security identities ------"
DIFF=$(diff -Nru <(echo "$ALLOWED") <(cilium policy trace --src-identity $FOO_SEC_ID --dst-identity $BAR_SEC_ID -v | grep "Result:")) || true
if [[ "$DIFF" != "" ]]; then
    abort "DIFF: $DIFF"
fi

echo "------ verify verbose trace for expected output using endpoint IDs ------"
TRACE_OUTPUT=$(cilium policy trace --src-endpoint $FOO_ID --dst-endpoint $BAR_ID -v)
DIFF=$(diff -Nru <(echo "$ALLOWED") <(cilium policy trace --src-endpoint $FOO_ID --dst-endpoint $BAR_ID -v | grep "Result:")) || true
if [[ "$DIFF" != "" ]]; then
    abort "DIFF: $DIFF"
fi

EXPECTED_CONSUMER="$FOO_SEC_ID"

echo "------ verify allowed consumers ------"
DIFF=$(diff -Nru <(echo -e "$EXPECTED_CONSUMER") <(cilium endpoint get $BAR_ID | jq '.policy | .["allowed-consumers"] | .[]')) || true
if [[ "$DIFF" != "" ]]; then
	abort "$DIFF"
fi

echo "------ verify max ingress nports is enforced ------"

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

cilium policy delete --all


#!/bin/bash

source "./helpers.bash"

TEST_NET="cilium"
LIST_CMD="cilium endpoint list | awk '{print \$2}' | grep 'Enabled\|Disabled'"
CFG_CMD="cilium config | grep Policy | grep -v PolicyTracing | awk '{print \$2}'"

function start_containers {
	docker run -dt --net=$TEST_NET --name foo -l id.foo -l id.teamA tgraf/netperf
	docker run -dt --net=$TEST_NET --name bar -l id.bar -l id.teamA tgraf/netperf
	docker run -dt --net=$TEST_NET --name baz -l id.baz tgraf/netperf
}

function remove_containers {
	docker rm -f foo foo bar baz 2> /dev/null || true
}

function import_test_policy {
	echo "------ adding policy ------"
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
}

function cleanup {
	cilium policy delete --all 2> /dev/null || true
	docker rm -f foo foo bar baz 2> /dev/null || true
}

function wait_endpoints_ready {
	until [ "$(cilium endpoint list | grep ready -c)" -eq "3" ]; do
		echo "Waiting for all endpoints to be ready"
		sleep 2s
	done
}

function check_endpoints_policy_enabled {
	echo "------ checking if all endpoints have policy enforcement enabled ------"
	POLICY_ENFORCED=`eval ${LIST_CMD}`
	for line in $POLICY_ENFORCED; do
		if [[ "$line" != "Enabled" ]]; then
			cilium config
			cilium endpoint list
			abort "Policy Enabled should be set to 'Enabled' since there are policies added to Cilium"
		fi
	done
}

function check_endpoints_policy_disabled {
	echo "------ checking if all endpoints have policy enforcement disabled ------"
	POLICY_ENFORCED=`eval ${LIST_CMD}`
	for line in $POLICY_ENFORCED; do
		if [[ "$line" != "Disabled" ]]; then
			cilium config
			cilium endpoint list
			abort "Policy Enforcement  should be set to 'Disabled' since policy enforcement was set to never be enabled"
		fi
	done
}

function check_config_policy_enabled {
	echo "------ checking if cilium daemon has policy enforcement enabled ------"
	sleep 5
	POLICY_ENFORCED=`eval ${CFG_CMD}`
	for line in $POLICY_ENFORCED; do
		if [[ "$line" != "Enabled" ]]; then
                        cilium config
		        cilium endpoint list	
			abort "Policy Enforcement should be set to 'Enabled' for the daemon"
		fi
	done
}

function check_config_policy_disabled {
	echo "------ checking if cilium daemon has policy enforcement disabled ------"
	sleep 5
	POLICY_ENFORCED=`eval ${CFG_CMD}`
	for line in $POLICY_ENFORCED; do
		if [[ "$line" != "Disabled" ]]; then
			cilium config
			cilium endpoint list
			abort "Policy Enforcement should be set to 'Disabled' for the daemon"
		fi
	done
}

function test_default_policy_configuration {
echo "------ test default configuration for enable-policy ------"
	# cilium-agent has enable-policy flag, which by default is set as "default".
	# Expected behavior is that if Kubernetes is not enabled, policy enforcement is enabled if at least one policy exists.
	# If no policy exists, then policy enforcement is disabled.
	remove_containers
	sudo service cilium restart
	sleep 10
	start_containers

	wait_endpoints_ready
	check_config_policy_disabled
	check_endpoints_policy_disabled
	
	import_test_policy
	wait_endpoints_ready
	check_config_policy_enabled
	check_endpoints_policy_enabled
	
	cilium policy delete --all
	wait_endpoints_ready
	check_config_policy_disabled
}

function test_true_policy_configuration {
	echo "------ test true configuration for enable-policy ------"
	remove_containers
	cilium config Policy=true
	start_containers

	wait_endpoints_ready
	check_config_policy_enabled
	check_endpoints_policy_enabled
	import_test_policy
	
	wait_endpoints_ready
	check_config_policy_enabled
	check_endpoints_policy_enabled
	cilium policy delete --all
	
	wait_endpoints_ready
	check_config_policy_enabled
}

function test_false_policy_configuration {
	echo "------ test false configuration for enable-policy ------"
	remove_containers
	cilium config Policy=false
	start_containers

	wait_endpoints_ready
	check_config_policy_disabled
	check_endpoints_policy_disabled
	import_test_policy
	wait_endpoints_ready
	check_config_policy_disabled
	check_endpoints_policy_disabled
	cilium policy delete --all
	wait_endpoints_ready
	check_config_policy_disabled
}

trap cleanup EXIT

cleanup
logs_clear

docker network inspect $TEST_NET 2> /dev/null || {
        docker network create --ipv6 --subnet ::1/112 --ipam-driver cilium --driver cilium $TEST_NET
}
test_default_policy_configuration
test_true_policy_configuration
test_false_policy_configuration 

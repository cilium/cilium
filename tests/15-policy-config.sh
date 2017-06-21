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

function restart_cilium {
	echo "------ restarting cilium ------"
	service cilium restart
	echo "------ waiting for cilium agent get up and running ------"
	wait_for_cilium_status
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
	gather_files 15-policy-config
	cilium policy delete --all 2> /dev/null || true
	docker rm -f foo foo bar baz 2> /dev/null || true
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
	restart_cilium
	start_containers

	wait_for_endpoints 3
	check_config_policy_disabled
	check_endpoints_policy_disabled
	# TODO - renable when we clear conntrack state upon policy deletion.
	#ping_success foo bar
	#ping_success foo baz

	import_test_policy
	wait_for_endpoints 3
	check_config_policy_enabled
	check_endpoints_policy_enabled
	ping_success foo bar
	ping_fail foo baz

	cilium policy delete --all
	wait_for_endpoints 3
	check_config_policy_disabled
	ping_success foo baz
	ping_success foo bar
}

function test_default_to_true_policy_configuration {
	echo "------ test that policy enforcement flag gets updated with no running endpoints: true ------"
	remove_containers
	# Make sure cilium agent starts in 'default' mode, so restart it.
	restart_cilium
	import_test_policy
	check_config_policy_enabled
	echo "------ setting cilium agent Policy=true"
	cilium config Policy=true
	check_config_policy_enabled
	echo "------ deleting policy ------"
	cilium policy delete --all
	# After policy is deleted, policy enforcement should still be enabled.
	check_config_policy_enabled
}

function test_default_to_false_policy_configuration {
	 echo "------ test that policy enforcement flag gets updated with no running endpoints: false ------"
	remove_containers
	# Make sure cilium agent starts in 'default' mode, so restart it.
	restart_cilium
	import_test_policy
	check_config_policy_enabled
	echo "------ setting cilium agent Policy=false"
	cilium config Policy=false
	check_config_policy_disabled
	echo "------ deleting policy ------"
	cilium policy delete --all
	# After policy is deleted, policy enforcement should be disabled.
	check_config_policy_disabled
}

function test_true_policy_configuration {
	echo "------ test true configuration for enable-policy ------"
	remove_containers
	restart_cilium
	cilium config Policy=true
	start_containers

	wait_for_endpoints 3
	check_config_policy_enabled
	check_endpoints_policy_enabled
	ping_fail foo bar	
	import_test_policy
	
	wait_for_endpoints 3
	check_config_policy_enabled
	check_endpoints_policy_enabled
	ping_success foo bar
	cilium policy delete --all
	
	wait_for_endpoints 3
	check_config_policy_enabled
	# TODO - renable when we clear conntrack state upon policy deletion. 
	# ping_fail foo bar
}

function test_false_policy_configuration {
	echo "------ test false configuration for enable-policy ------"
	remove_containers
	restart_cilium
	cilium config Policy=false
	start_containers

	wait_for_endpoints 3
	check_config_policy_disabled
	check_endpoints_policy_disabled
	ping_success foo bar
	import_test_policy
	wait_for_endpoints 3
	check_config_policy_disabled
	check_endpoints_policy_disabled
	ping_success foo bar
	cilium policy delete --all
	wait_for_endpoints 3
	check_config_policy_disabled
}

function ping_fail {
	C1=$1
	C2=$2
	echo "------ pinging $C2 from $C1 (expecting failure) ------"
	docker exec -i  ${C1} bash -c "ping -c 5 ${C2}" && {
  		abort "Error: Unexpected success pinging ${C2} from ${C1}"
  	}
}

function ping_success {
	C1=$1
	C2=$2
	echo "------ pinging $C2 from $C1 (expecting success) ------"
	docker exec -i ${C1} bash -c "ping -c 5 ${C2}" || {
		abort "Error: Could not ping ${C2} from ${C1}"
	}
}

trap cleanup EXIT

cleanup
logs_clear

docker network inspect $TEST_NET 2> /dev/null || {
        docker network create --ipv6 --subnet ::1/112 --ipam-driver cilium --driver cilium $TEST_NET
}

test_default_policy_configuration
test_default_to_true_policy_configuration
test_default_to_false_policy_configuration
test_true_policy_configuration
test_false_policy_configuration 

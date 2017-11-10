#!/bin/bash

# Tests to validate visibility rules.

dir=$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )
source "${dir}/helpers.bash"
# dir might have been overwritten by helpers.bash
dir=$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )

TEST_NAME=$(get_filename_without_extension $0)
LOGS_DIR="${dir}/cilium-files/${TEST_NAME}/logs"
redirect_debug_logs ${LOGS_DIR}

set -ex

function start_container {
  create_cilium_docker_network
  docker run -dt --net=$TEST_NET --name foo -l id.foo tgraf/netperf
}

function policy_allow_none() {
  log "importing policy with no ingress rule"
  cilium policy delete --all
  policy_import_and_wait - <<EOF
[{
    "endpointSelector": {"matchLabels":{"id.foo":""}},
    "ingressVisibility": [{
	"toPorts": [{"port": "80", "protocol": "tcp"}],
	"l7Protocol": "http"
    }]
}]
EOF
}

function policy_allow_all() {
  log "importing policy with one ingress rule allowing from all endpoints"
  cilium policy delete --all
  policy_import_and_wait - <<EOF
[{
    "endpointSelector": {"matchLabels":{"id.foo":""}},
    "ingress": [{
        "fromEndpoints": [{"matchLabels":{}}]
    }]
},{
    "endpointSelector": {"matchLabels":{"id.foo":""}},
    "ingressVisibility": [{
	"toPorts": [{"port": "80", "protocol": "tcp"}],
	"l7Protocol": "http"
    }]
}]
EOF
}

function policy_allow_all_to_port() {
  log "importing policy with one ingress rule allowing from all endpoints to port 80"
  cilium policy delete --all
  policy_import_and_wait - <<EOF
[{
    "endpointSelector": {"matchLabels":{"id.foo":""}},
    "ingress": [{
        "fromEndpoints": [{"matchLabels":{}}],
	"toPorts": [{
	    "ports": [{"port": "80", "protocol": "tcp"}]
	}]
    }]
},{
    "endpointSelector": {"matchLabels":{"id.foo":""}},
    "ingressVisibility": [{
	"toPorts": [{"port": "80", "protocol": "tcp"}],
	"l7Protocol": "http"
    }]
}]
EOF
}

function policy_allow_all_to_port_http() {
  log "importing policy with one ingress rule allowing from all endpoints to port 80 & HTTP"
  cilium policy delete --all
  policy_import_and_wait - <<EOF
[{
    "endpointSelector": {"matchLabels":{"id.foo":""}},
    "ingress": [{
        "fromEndpoints": [{"matchLabels":{}}],
	"toPorts": [{
	    "ports": [{"port": "80", "protocol": "tcp"}],
	    "rules": {
                "http": [{
		    "method": "GET",
		    "path": "/public"
                }]
	    }
	}]
    }]
},{
    "endpointSelector": {"matchLabels":{"id.foo":""}},
    "ingressVisibility": [{
	"toPorts": [{"port": "80", "protocol": "tcp"}],
	"l7Protocol": "http"
    }]
}]
EOF
}

function policy_allow_all_to_another_port() {
  log "importing policy with one ingress rule allowing from all endpoints to port 1234"
  cilium policy delete --all
  policy_import_and_wait - <<EOF
[{
    "endpointSelector": {"matchLabels":{"id.foo":""}},
    "ingress": [{
        "fromEndpoints": [{"matchLabels":{}}],
	"toPorts": [{
	    "ports": [{"port": "1234", "protocol": "tcp"}]
	}]
    }]
},{
    "endpointSelector": {"matchLabels":{"id.foo":""}},
    "ingressVisibility": [{
	"toPorts": [{"port": "80", "protocol": "tcp"}],
	"l7Protocol": "http"
    }]
}]
EOF
}

function policy_allow_from_bar() {
  log "importing policy with one ingress rule allowing from id.bar"
  cilium policy delete --all
  policy_import_and_wait - <<EOF
[{
    "endpointSelector": {"matchLabels":{"id.foo":""}},
    "ingress": [{
        "fromEndpoints": [{"matchLabels":{"id.bar":""}}]
    }]
},{
    "endpointSelector": {"matchLabels":{"id.foo":""}},
    "ingressVisibility": [{
	"toPorts": [{"port": "80", "protocol": "tcp"}],
	"l7Protocol": "http"
    }]
}]
EOF
}

function policy_allow_from_bar_to_port() {
  log "importing policy with one ingress rule allowing from id.bar to port 80"
  cilium policy delete --all
  policy_import_and_wait - <<EOF
[{
    "endpointSelector": {"matchLabels":{"id.foo":""}},
    "ingress": [{
        "fromEndpoints": [{"matchLabels":{"id.bar":""}}],
	"toPorts": [{
	    "ports": [{"port": "80", "protocol": "tcp"}]
	}]
    }]
},{
    "endpointSelector": {"matchLabels":{"id.foo":""}},
    "ingressVisibility": [{
	"toPorts": [{"port": "80", "protocol": "tcp"}],
	"l7Protocol": "http"
    }]
}]
EOF
}

function policy_allow_from_bar_to_port_http() {
  log "importing policy with one ingress rule allowing from id.bar to port 80 & HTTP"
  cilium policy delete --all
  policy_import_and_wait - <<EOF
[{
    "endpointSelector": {"matchLabels":{"id.foo":""}},
    "ingress": [{
        "fromEndpoints": [{"matchLabels":{"id.bar":""}}],
	"toPorts": [{
	    "ports": [{"port": "80", "protocol": "tcp"}],
	    "rules": {
                "http": [{
		    "method": "GET",
		    "path": "/public"
                }]
	    }
	}]
    }]
},{
    "endpointSelector": {"matchLabels":{"id.foo":""}},
    "ingressVisibility": [{
	"toPorts": [{"port": "80", "protocol": "tcp"}],
	"l7Protocol": "http"
    }]
}]
EOF
}

function cilium_endpoint_get_policy_enabled() {
  cilium endpoint get $* -o json | jq '.[0]."policy-enabled"'
}

function cilium_endpoint_get_policy_l4() {
  cilium endpoint get $* -o json | jq '.[0].policy.l4'
}

function cilium_endpoint_get_policy_l4_ingress() {
  cilium endpoint get $* -o json | jq '[.[0].policy.l4.ingress[] | fromjson] | sort'
}

function cilium_endpoint_get_policy_l4_egress() {
  cilium endpoint get $* -o json | jq '[.[0].policy.l4.egress[] | fromjson] | sort'
}

function cilium_endpoint_get_policy_l4_ingress_visibility() {
  cilium endpoint get $* -o json | jq '[.[0].policy.l4."ingress-visibility"[] | fromjson] | sort'
}

function assert_l4_ingress_equals() {
  log "testing the L4 ingress policy"
  local expected_response=`cat`
  local response=`cilium_endpoint_get_policy_l4_ingress -l container:id.foo`
  if [ "$response" != "$expected_response" ]; then
    abort "Expected: ${expected_response}; Got: ${response}; L4 policy: `cilium_endpoint_get_policy_l4 -l container:id.foo`"
  fi
}

function assert_policy_enabled() {
  log "testing that policy is enabled"
  local expected_response="true"
  local response=`cilium_endpoint_get_policy_enabled -l container:id.foo`
  if [ "$response" != "$expected_response" ]; then
    abort "Expected: ${expected_response}; Got: ${response}"
  fi
}

function assert_policy_disabled() {
  log "testing that policy is disabled"
  local expected_response="false"
  local response=`cilium_endpoint_get_policy_enabled -l container:id.foo`
  if [ "$response" != "$expected_response" ]; then
    abort "Expected: ${expected_response}; Got: ${response}"
  fi
}

function assert_visibility_rule_inactive() {
  log "testing that visibility rule is inactive"
  local expected_response="[]"
  local response=`cilium_endpoint_get_policy_l4_ingress_visibility -l container:id.foo`
  if [ "$response" != "$expected_response" ]; then
    abort "Expected: ${expected_response}; Got: ${response}; L4 policy: `cilium_endpoint_get_policy_l4 -l container:id.foo`"
  fi
}

function assert_visibility_rule_active() {
  log "testing that visibility rule is active"
  local expected_response=`cat <<EOF
[
  {
    "port": 80,
    "protocol": "TCP",
    "l7Protocol": "http"
  }
]
EOF`
  local response=`cilium_endpoint_get_policy_l4_ingress_visibility -l container:id.foo`
  if [ "$response" != "$expected_response" ]; then
    abort "Expected: ${expected_response}; Got: ${response}; L4 policy: `cilium_endpoint_get_policy_l4 -l container:id.foo`"
  fi
}

function assert_port80_allowed_from_bar() {
  log "testing that id.bar has access to port 80"
  local expected_response="ALLOWED"
  local trace=`cilium policy trace -s any:id.bar -d container:id.foo --dport 80/tcp`
  local response=`echo "$trace" | sed -n -e 's/^Final verdict: \(.*\)$/\1/p'`
  if [ "$response" != "$expected_response" ]; then
    abort "Expected: ${expected_response}; Got: ${response}; Trace: ${trace}"
  fi
}

function assert_port80_denied_from_bar() {
  log "testing that id.bar is denied access to port 80"
  local expected_response="DENIED"
  local trace=`cilium policy trace -s any:id.bar -d container:id.foo --dport 80/tcp`
  local response=`echo "$trace" | sed -n -e 's/^Final verdict: \(.*\)$/\1/p'`
  if [ "$response" != "$expected_response" ]; then
    abort "Expected: ${expected_response}; Got: ${response}; Trace: ${trace}"
  fi
}

function assert_port80_allowed_from_other() {
  log "testing that id.other has access to port 80"
  local expected_response="ALLOWED"
  local trace=`cilium policy trace -s any:id.other -d container:id.foo --dport 80/tcp`
  local response=`echo "$trace" | sed -n -e 's/^Final verdict: \(.*\)$/\1/p'`
  if [ "$response" != "$expected_response" ]; then
    abort "Expected: ${expected_response}; Got: ${response}; Trace: ${trace}"
  fi
}

function assert_port80_denied_from_other() {
  log "testing that id.other is denied access to port 80"
  local expected_response="DENIED"
  local trace=`cilium policy trace -s any:id.other -d container:id.foo --dport 80/tcp`
  local response=`echo "$trace" | sed -n -e 's/^Final verdict: \(.*\)$/\1/p'`
  if [ "$response" != "$expected_response" ]; then
    abort "Expected: ${expected_response}; Got: ${response}; Trace: ${trace}"
  fi
}

function test_policy_enforcement_never() {
  cilium config PolicyEnforcement=never

  policy_allow_none
  assert_policy_disabled

  policy_allow_all
  assert_policy_disabled

  policy_allow_all_to_port
  assert_policy_disabled

  policy_allow_all_to_port_http
  assert_policy_disabled

  policy_allow_all_to_another_port
  assert_policy_disabled

  policy_allow_from_bar
  assert_policy_disabled

  policy_allow_from_bar_to_port
  assert_policy_disabled

  policy_allow_from_bar_to_port_http
  assert_policy_disabled
}

function test_policy_enforcement_always() {
  cilium config PolicyEnforcement=always

  policy_allow_none
  assert_policy_enabled
  assert_visibility_rule_inactive
  assert_port80_denied_from_bar
  assert_port80_denied_from_other
  echo "[]" | assert_l4_ingress_equals

  policy_allow_all
  assert_policy_enabled
  assert_visibility_rule_active
  assert_port80_allowed_from_bar
  assert_port80_allowed_from_other
  assert_l4_ingress_equals <<EOF
[
  {
    "port": 80,
    "protocol": "TCP",
    "l7Rules": [
      {
        "<none>": {
          "http": [
            {}
          ]
        }
      }
    ]
  },
  {
    "port": 0,
    "protocol": "ANY"
  }
]
EOF

  policy_allow_all_to_port
  assert_policy_enabled
  assert_visibility_rule_active
  assert_port80_allowed_from_bar
  assert_port80_allowed_from_other
  assert_l4_ingress_equals <<EOF
[
  {
    "port": 80,
    "protocol": "TCP",
    "l7Rules": [
      {
        "<none>": {
          "http": [
            {}
          ]
        }
      }
    ]
  }
]
EOF

  policy_allow_all_to_port_http
  assert_policy_enabled
  assert_visibility_rule_inactive
  assert_port80_allowed_from_bar
  assert_port80_allowed_from_other
  assert_l4_ingress_equals <<EOF
[
  {
    "port": 80,
    "protocol": "TCP",
    "l7Rules": [
      {
        "<none>": {
          "http": [
            {
              "path": "/public",
              "method": "GET"
            }
          ]
        }
      }
    ]
  }
]
EOF

  policy_allow_all_to_another_port
  assert_policy_enabled
  assert_visibility_rule_inactive
  assert_port80_denied_from_bar
  assert_port80_denied_from_other
  assert_l4_ingress_equals <<EOF
[
  {
    "port": 1234,
    "protocol": "TCP"
  }
]
EOF

  policy_allow_from_bar
  assert_policy_enabled
  assert_visibility_rule_active
  assert_port80_allowed_from_bar
  assert_port80_denied_from_other
  assert_l4_ingress_equals <<EOF
[
  {
    "port": 80,
    "protocol": "TCP",
    "l7Rules": [
      {
        "any.id.bar=": {
          "http": [
            {}
          ]
        }
      }
    ]
  },
  {
    "port": 0,
    "protocol": "ANY"
  }
]
EOF

  policy_allow_from_bar_to_port
  assert_policy_enabled
  assert_visibility_rule_active
  assert_port80_allowed_from_bar
  assert_port80_denied_from_other
  assert_l4_ingress_equals <<EOF
[
  {
    "port": 80,
    "protocol": "TCP",
    "l7Rules": [
      {
        "any.id.bar=": {
          "http": [
            {}
          ]
        }
      }
    ]
  }
]
EOF

  policy_allow_from_bar_to_port_http
  assert_policy_enabled
  assert_visibility_rule_inactive
  assert_port80_allowed_from_bar
  assert_port80_denied_from_other
  assert_l4_ingress_equals <<EOF
[
  {
    "port": 80,
    "protocol": "TCP",
    "l7Rules": [
      {
        "any.id.bar=": {
          "http": [
            {
              "path": "/public",
              "method": "GET"
            }
          ]
        }
      }
    ]
  }
]
EOF
}

function test_policy_enforcement_default() {
  cilium config PolicyEnforcement=default

  policy_allow_none
  assert_policy_enabled
  assert_visibility_rule_active
  assert_port80_allowed_from_bar
  assert_port80_allowed_from_other
  assert_l4_ingress_equals <<EOF
[
  {
    "port": 80,
    "protocol": "TCP",
    "l7Rules": [
      {
        "<none>": {
          "http": [
            {}
          ]
        }
      }
    ]
  },
  {
    "port": 0,
    "protocol": "ANY"
  }
]
EOF

  policy_allow_all
  assert_policy_enabled
  assert_visibility_rule_active
  assert_port80_allowed_from_bar
  assert_port80_allowed_from_other
  assert_l4_ingress_equals <<EOF
[
  {
    "port": 80,
    "protocol": "TCP",
    "l7Rules": [
      {
        "<none>": {
          "http": [
            {}
          ]
        }
      }
    ]
  },
  {
    "port": 0,
    "protocol": "ANY"
  }
]
EOF

  policy_allow_all_to_port
  assert_policy_enabled
  assert_visibility_rule_active
  assert_port80_allowed_from_bar
  assert_port80_allowed_from_other
  assert_l4_ingress_equals <<EOF
[
  {
    "port": 80,
    "protocol": "TCP",
    "l7Rules": [
      {
        "<none>": {
          "http": [
            {}
          ]
        }
      }
    ]
  }
]
EOF

  policy_allow_all_to_port_http
  assert_policy_enabled
  assert_visibility_rule_inactive
  assert_port80_allowed_from_bar
  assert_port80_allowed_from_other
  assert_l4_ingress_equals <<EOF
[
  {
    "port": 80,
    "protocol": "TCP",
    "l7Rules": [
      {
        "<none>": {
          "http": [
            {
              "path": "/public",
              "method": "GET"
            }
          ]
        }
      }
    ]
  }
]
EOF

  policy_allow_all_to_another_port
  assert_policy_enabled
  assert_visibility_rule_inactive
  assert_port80_denied_from_bar
  assert_port80_denied_from_other
  assert_l4_ingress_equals <<EOF
[
  {
    "port": 1234,
    "protocol": "TCP"
  }
]
EOF

  policy_allow_from_bar
  assert_policy_enabled
  assert_visibility_rule_active
  assert_port80_allowed_from_bar
  assert_port80_denied_from_other
  assert_l4_ingress_equals <<EOF
[
  {
    "port": 80,
    "protocol": "TCP",
    "l7Rules": [
      {
        "any.id.bar=": {
          "http": [
            {}
          ]
        }
      }
    ]
  },
  {
    "port": 0,
    "protocol": "ANY"
  }
]
EOF

  policy_allow_from_bar_to_port
  assert_policy_enabled
  assert_visibility_rule_active
  assert_port80_allowed_from_bar
  assert_port80_denied_from_other
  assert_l4_ingress_equals <<EOF
[
  {
    "port": 80,
    "protocol": "TCP",
    "l7Rules": [
      {
        "any.id.bar=": {
          "http": [
            {}
          ]
        }
      }
    ]
  }
]
EOF

  policy_allow_from_bar_to_port_http
  assert_policy_enabled
  assert_visibility_rule_inactive
  assert_port80_allowed_from_bar
  assert_port80_denied_from_other
  assert_l4_ingress_equals <<EOF
[
  {
    "port": 80,
    "protocol": "TCP",
    "l7Rules": [
      {
        "any.id.bar=": {
          "http": [
            {
              "path": "/public",
              "method": "GET"
            }
          ]
        }
      }
    ]
  }
]
EOF
}

function cleanup {
  gather_files ${TEST_NAME} ${TEST_SUITE}
  cilium policy delete --all 2> /dev/null || true
  cilium config PolicyEnforcement=default
  docker rm -f foo 2> /dev/null || true
}

trap cleanup EXIT

cleanup
logs_clear

start_container

test_policy_enforcement_never
test_policy_enforcement_always
test_policy_enforcement_default

test_succeeded "${TEST_NAME}"

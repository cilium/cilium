// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"bytes"
	"path"
	"slices"
	"testing"

	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/policy/trafficdirection"
	"github.com/cilium/cilium/pkg/u8proto"
)

func init() {
	log = logging.DefaultSlogLogger.With(logfields.LogSubsys, "cilium-dbg")
}

func TestExpandNestedJSON(t *testing.T) {
	buf := bytes.NewBufferString("not json at all")
	res, err := expandNestedJSON(*buf)
	require.NoError(t, err)
	require.Equal(t, "not json at all", res.String())

	buf = bytes.NewBufferString(`{\n\"notEscapedJson\": \"foo\"}`)
	res, err = expandNestedJSON(*buf)
	require.NoError(t, err)
	require.Equal(t, `{\n\"notEscapedJson\": \"foo\"}`, res.String())

	buf = bytes.NewBufferString(`nonjson={\n\"notEscapedJson\": \"foo\"}`)
	res, err = expandNestedJSON(*buf)
	require.NoError(t, err)
	require.Equal(t, `nonjson={\n\"notEscapedJson\": \"foo\"}`, res.String())

	buf = bytes.NewBufferString(`nonjson:morenonjson={\n\"notEscapedJson\": \"foo\"}`)
	res, err = expandNestedJSON(*buf)
	require.NoError(t, err)
	require.Equal(t, `nonjson:morenonjson={\n\"notEscapedJson\": \"foo\"}`, res.String())

	buf = bytes.NewBufferString(`{"foo": ["{\n  \"port\": 8080,\n  \"protocol\": \"TCP\"\n}"]}`)
	res, err = expandNestedJSON(*buf)
	require.NoError(t, err)
	require.JSONEq(t, `{"foo": [{
  "port": 8080,
  "protocol": "TCP"
}]}`, res.String())

	buf = bytes.NewBufferString(`"foo": [
  "bar:baz/alice={\"bob\":{\"charlie\":4}}\n"
]`)
	res, err = expandNestedJSON(*buf)
	require.NoError(t, err)
	require.Equal(t, `"foo": [
  bar:baz/alice={
				  "bob": {
				    "charlie": 4
				  }
				}

]`, res.String())

	buf = bytes.NewBufferString(`"foo": [
  "bar:baz/alice={\n\"bob\":\n{\n\"charlie\":\n4\n}\n}\n"
]`)
	res, err = expandNestedJSON(*buf)
	require.NoError(t, err)
	require.Equal(t, `"foo": [
  bar:baz/alice={
				  "bob": {
				    "charlie": 4
				  }
				}

]`, res.String())

	buf = bytes.NewBufferString(`[
  {
    "id": 2669,
    "spec": {
      "label-configuration": {},
      "options": {
        "Conntrack": "Enabled",
        "ConntrackAccounting": "Enabled",
        "Debug": "Enabled",
        "DebugLB": "Enabled",
        "DebugPolicy": "Enabled",
        "DropNotification": "Enabled",
        "MonitorAggregationLevel": "None",
        "TraceNotification": "Enabled"
      }
    },
    "status": {
      "controllers": [
        {
          "configuration": {
            "error-retry": true,
            "interval": "5m0s"
          },
          "name": "resolve-identity-2669",
          "status": {
            "last-failure-timestamp": "0001-01-01T00:00:00.000Z",
            "last-success-timestamp": "2019-06-10T19:36:42.497Z",
            "success-count": 4
          },
          "uuid": "aba643d9-8bb5-11e9-9be2-080027486be3"
        },
        {
          "configuration": {
            "error-retry": true,
            "interval": "5m0s"
          },
          "name": "sync-IPv4-identity-mapping (2669)",
          "status": {
            "last-failure-timestamp": "0001-01-01T00:00:00.000Z",
            "last-success-timestamp": "2019-06-10T19:36:42.529Z",
            "success-count": 4
          },
          "uuid": "aba631c3-8bb5-11e9-9be2-080027486be3"
        },
        {
          "configuration": {
            "error-retry": true,
            "interval": "5m0s"
          },
          "name": "sync-IPv6-identity-mapping (2669)",
          "status": {
            "last-failure-timestamp": "0001-01-01T00:00:00.000Z",
            "last-success-timestamp": "2019-06-10T19:36:42.529Z",
            "success-count": 4
          },
          "uuid": "aba637e9-8bb5-11e9-9be2-080027486be3"
        },
        {
          "configuration": {
            "error-retry": true,
            "interval": "1m0s"
          },
          "name": "sync-policymap-2669",
          "status": {
            "last-failure-timestamp": "0001-01-01T00:00:00.000Z",
            "last-success-timestamp": "2019-06-10T19:39:43.974Z",
            "success-count": 16
          },
          "uuid": "ad0a1388-8bb5-11e9-9be2-080027486be3"
        }
      ],
      "external-identifiers": {
        "container-id": "1968a48396a0e42f3faad360a7ffa23d8629faddee7f828408bf177d3eeac47a",
        "container-name": "client",
        "docker-endpoint-id": "05a27bef9f339e5ae25a191108b91ee1e7fdc2696d2c46908645157a62438ccd",
        "docker-network-id": "e3ea8f2e1df2250df6702fd802ea0d3706091c1b374db998d48e7327bf9bd0fe",
        "pod-name": "/"
      },
      "health": {
        "bpf": "OK",
        "connected": true,
        "overallHealth": "OK",
        "policy": "OK"
      },
      "identity": {
        "id": 62004,
        "labels": [
          "container:id.client"
        ],
        "labelsSHA256": "c2e7b3482b5e9e1abca840b8cc5568ff876c7524d723b3068683f539008537dc"
      },
      "labels": {
        "realized": {},
        "security-relevant": [
          "container:id.client"
        ]
      },
      "log": [
        {
          "code": "OK",
          "message": "Successfully regenerated endpoint program (Reason: policy rules added)",
          "state": "ready",
          "timestamp": "2019-06-10T19:26:43Z"
        }
      ],
      "networking": {
        "addressing": [
          {
            "ipv4": "10.11.212.174",
            "ipv6": "f00d::a0b:0:0:8cdf"
          }
        ],
        "host-mac": "1a:c9:b9:4f:98:65",
        "interface-index": 250,
        "interface-name": "lxca8e38e6f627e",
        "mac": "7e:41:1b:fd:02:81"
      },
      "policy": {
        "proxy-policy-revision": 48,
        "proxy-statistics": [
          {
            "allocated-proxy-port": 15814,
            "location": "egress",
            "port": 80,
            "protocol": "http",
            "statistics": {
              "requests": {
                "denied": 2,
                "forwarded": 2,
                "received": 4
              },
              "responses": {
                "forwarded": 2,
                "received": 2
              }
            }
          }
        ],
        "realized": {
          "allowed-egress-identities": [],
          "allowed-ingress-identities": [
            0,
            1
          ],
          "build": 48,
          "cidr-policy": {
            "egress": [],
            "ingress": []
          },
          "id": 62004,
          "l4": {
            "egress": [
              {
                "derived-from-rules": [
                  []
                ],
                "rule": "{\n  \"port\": 80,\n  \"protocol\": \"TCP\",\n  \"l7-rules\": [\n    {\n      \"\\u0026LabelSelector{MatchLabels:map[string]string{},MatchExpressions:[],}\": {\n        \"http\": [\n          {\n            \"path\": \"/public\",\n            \"method\": \"GET\"\n          }\n        ]\n      }\n    }\n  ]\n}"
              }
            ],
            "ingress": []
          },
          "policy-enabled": "egress",
          "policy-revision": 48
        },
        "spec": {
          "allowed-egress-identities": [],
          "allowed-ingress-identities": [
            0,
            1
          ],
          "build": 48,
          "cidr-policy": {
            "egress": [],
            "ingress": []
          },
          "id": 62004,
          "l4": {
            "egress": [
              {
                "derived-from-rules": [
                  []
                ],
                "rule": "{\n  \"port\": 80,\n  \"protocol\": \"TCP\",\n  \"l7-rules\": [\n    {\n      \"\\u0026LabelSelector{MatchLabels:map[string]string{},MatchExpressions:[],}\": {\n        \"http\": [\n          {\n            \"path\": \"/public\",\n            \"method\": \"GET\"\n          }\n        ]\n      }\n    }\n  ]\n}"
              }
            ],
            "ingress": []
          },
          "policy-enabled": "egress",
          "policy-revision": 48
        }
      },
      "realized": {
        "label-configuration": {},
        "options": {
          "Conntrack": "Enabled",
          "ConntrackAccounting": "Enabled",
          "Debug": "Enabled",
          "DebugLB": "Enabled",
          "DebugPolicy": "Enabled",
          "DropNotification": "Enabled",
          "MonitorAggregationLevel": "None",
          "TraceNotification": "Enabled"
        }
      },
      "state": "ready"
    }
  }
]`)
	res, err = expandNestedJSON(*buf)
	require.NoError(t, err)
	require.JSONEq(t, `[
  {
    "id": 2669,
    "spec": {
      "label-configuration": {},
      "options": {
        "Conntrack": "Enabled",
        "ConntrackAccounting": "Enabled",
        "Debug": "Enabled",
        "DebugLB": "Enabled",
        "DebugPolicy": "Enabled",
        "DropNotification": "Enabled",
        "MonitorAggregationLevel": "None",
        "TraceNotification": "Enabled"
      }
    },
    "status": {
      "controllers": [
        {
          "configuration": {
            "error-retry": true,
            "interval": "5m0s"
          },
          "name": "resolve-identity-2669",
          "status": {
            "last-failure-timestamp": "0001-01-01T00:00:00.000Z",
            "last-success-timestamp": "2019-06-10T19:36:42.497Z",
            "success-count": 4
          },
          "uuid": "aba643d9-8bb5-11e9-9be2-080027486be3"
        },
        {
          "configuration": {
            "error-retry": true,
            "interval": "5m0s"
          },
          "name": "sync-IPv4-identity-mapping (2669)",
          "status": {
            "last-failure-timestamp": "0001-01-01T00:00:00.000Z",
            "last-success-timestamp": "2019-06-10T19:36:42.529Z",
            "success-count": 4
          },
          "uuid": "aba631c3-8bb5-11e9-9be2-080027486be3"
        },
        {
          "configuration": {
            "error-retry": true,
            "interval": "5m0s"
          },
          "name": "sync-IPv6-identity-mapping (2669)",
          "status": {
            "last-failure-timestamp": "0001-01-01T00:00:00.000Z",
            "last-success-timestamp": "2019-06-10T19:36:42.529Z",
            "success-count": 4
          },
          "uuid": "aba637e9-8bb5-11e9-9be2-080027486be3"
        },
        {
          "configuration": {
            "error-retry": true,
            "interval": "1m0s"
          },
          "name": "sync-policymap-2669",
          "status": {
            "last-failure-timestamp": "0001-01-01T00:00:00.000Z",
            "last-success-timestamp": "2019-06-10T19:39:43.974Z",
            "success-count": 16
          },
          "uuid": "ad0a1388-8bb5-11e9-9be2-080027486be3"
        }
      ],
      "external-identifiers": {
        "container-id": "1968a48396a0e42f3faad360a7ffa23d8629faddee7f828408bf177d3eeac47a",
        "container-name": "client",
        "docker-endpoint-id": "05a27bef9f339e5ae25a191108b91ee1e7fdc2696d2c46908645157a62438ccd",
        "docker-network-id": "e3ea8f2e1df2250df6702fd802ea0d3706091c1b374db998d48e7327bf9bd0fe",
        "pod-name": "/"
      },
      "health": {
        "bpf": "OK",
        "connected": true,
        "overallHealth": "OK",
        "policy": "OK"
      },
      "identity": {
        "id": 62004,
        "labels": [
          "container:id.client"
        ],
        "labelsSHA256": "c2e7b3482b5e9e1abca840b8cc5568ff876c7524d723b3068683f539008537dc"
      },
      "labels": {
        "realized": {},
        "security-relevant": [
          "container:id.client"
        ]
      },
      "log": [
        {
          "code": "OK",
          "message": "Successfully regenerated endpoint program (Reason: policy rules added)",
          "state": "ready",
          "timestamp": "2019-06-10T19:26:43Z"
        }
      ],
      "networking": {
        "addressing": [
          {
            "ipv4": "10.11.212.174",
            "ipv6": "f00d::a0b:0:0:8cdf"
          }
        ],
        "host-mac": "1a:c9:b9:4f:98:65",
        "interface-index": 250,
        "interface-name": "lxca8e38e6f627e",
        "mac": "7e:41:1b:fd:02:81"
      },
      "policy": {
        "proxy-policy-revision": 48,
        "proxy-statistics": [
          {
            "allocated-proxy-port": 15814,
            "location": "egress",
            "port": 80,
            "protocol": "http",
            "statistics": {
              "requests": {
                "denied": 2,
                "forwarded": 2,
                "received": 4
              },
              "responses": {
                "forwarded": 2,
                "received": 2
              }
            }
          }
        ],
        "realized": {
          "allowed-egress-identities": [],
          "allowed-ingress-identities": [
            0,
            1
          ],
          "build": 48,
          "cidr-policy": {
            "egress": [],
            "ingress": []
          },
          "id": 62004,
          "l4": {
            "egress": [
              {
                "derived-from-rules": [
                  []
                ],
                "rule": {
		  "l7-rules": [
		    {
		      "\u0026LabelSelector{MatchLabels:map[string]string{},MatchExpressions:[],}": {
		        "http": [
		          {
		            "method": "GET",
		            "path": "/public"
		          }
		        ]
		      }
		    }
		  ],
		  "port": 80,
		  "protocol": "TCP"
		}
              }
            ],
            "ingress": []
          },
          "policy-enabled": "egress",
          "policy-revision": 48
        },
        "spec": {
          "allowed-egress-identities": [],
          "allowed-ingress-identities": [
            0,
            1
          ],
          "build": 48,
          "cidr-policy": {
            "egress": [],
            "ingress": []
          },
          "id": 62004,
          "l4": {
            "egress": [
              {
                "derived-from-rules": [
                  []
                ],
                "rule": {
		  "l7-rules": [
		    {
		      "\u0026LabelSelector{MatchLabels:map[string]string{},MatchExpressions:[],}": {
		        "http": [
		          {
		            "method": "GET",
		            "path": "/public"
		          }
		        ]
		      }
		    }
		  ],
		  "port": 80,
		  "protocol": "TCP"
		}
              }
            ],
            "ingress": []
          },
          "policy-enabled": "egress",
          "policy-revision": 48
        }
      },
      "realized": {
        "label-configuration": {},
        "options": {
          "Conntrack": "Enabled",
          "ConntrackAccounting": "Enabled",
          "Debug": "Enabled",
          "DebugLB": "Enabled",
          "DebugPolicy": "Enabled",
          "DropNotification": "Enabled",
          "MonitorAggregationLevel": "None",
          "TraceNotification": "Enabled"
        }
      },
      "state": "ready"
    }
  }
]`, res.String())

}

func TestParseTrafficString(t *testing.T) {

	validIngressCases := []string{"ingress", "Ingress", "InGrEss"}
	validEgressCases := []string{"egress", "Egress", "EGrEss"}

	invalidStr := "getItDoneMan"

	for _, validCase := range validIngressCases {
		ingressDir, err := parseTrafficString(validCase)
		require.NoError(t, err)
		require.Equal(t, trafficdirection.Ingress, ingressDir)
	}

	for _, validCase := range validEgressCases {
		egressDir, err := parseTrafficString(validCase)
		require.NoError(t, err)
		require.Equal(t, trafficdirection.Egress, egressDir)
	}

	invalid, err := parseTrafficString(invalidStr)
	require.Error(t, err)
	require.Equal(t, trafficdirection.Invalid, invalid)
}

func TestParsePolicyUpdateArgsHelper(t *testing.T) {
	sortProtos := func(ints []u8proto.U8proto) {
		slices.Sort(ints)
	}

	allProtos := []u8proto.U8proto{}
	for _, proto := range u8proto.ProtoIDs {
		allProtos = append(allProtos, proto)
	}

	tests := []struct {
		args             []string
		invalid          bool
		mapBaseName      string
		trafficDirection trafficdirection.TrafficDirection
		peerLbl          identity.NumericIdentity
		port             uint16
		protos           []u8proto.U8proto
		isDeny           bool
	}{
		{
			args:             []string{labels.IDNameHost, "ingress", "12345"},
			invalid:          false,
			mapBaseName:      "cilium_policy_v2_reserved_1",
			trafficDirection: trafficdirection.Ingress,
			peerLbl:          12345,
			port:             0,
			protos:           []u8proto.U8proto{u8proto.ANY},
		},
		{
			args:             []string{"123", "egress", "12345", "1/tcp"},
			invalid:          false,
			mapBaseName:      "cilium_policy_v2_00123",
			trafficDirection: trafficdirection.Egress,
			peerLbl:          12345,
			port:             1,
			protos:           []u8proto.U8proto{u8proto.TCP},
		},
		{
			args:             []string{"123", "ingress", "12345", "1"},
			invalid:          false,
			mapBaseName:      "cilium_policy_v2_00123",
			trafficDirection: trafficdirection.Ingress,
			peerLbl:          12345,
			port:             1,
			protos:           allProtos,
		},
		{
			// Invalid traffic direction.
			args:    []string{"123", "invalid", "12345"},
			invalid: true,
		},
		{
			// Invalid protocol.
			args:    []string{"123", "invalid", "1/udt"},
			invalid: true,
		},
		{
			args:             []string{labels.IDNameHost, "ingress", "12345"},
			invalid:          false,
			isDeny:           true,
			mapBaseName:      "cilium_policy_v2_reserved_1",
			trafficDirection: trafficdirection.Ingress,
			peerLbl:          12345,
			port:             0,
			protos:           []u8proto.U8proto{u8proto.ANY},
		},
		{
			args:             []string{"123", "egress", "12345", "1/tcp"},
			invalid:          false,
			isDeny:           true,
			mapBaseName:      "cilium_policy_v2_00123",
			trafficDirection: trafficdirection.Egress,
			peerLbl:          12345,
			port:             1,
			protos:           []u8proto.U8proto{u8proto.TCP},
		},
		{
			args:             []string{"123", "ingress", "12345", "1"},
			invalid:          false,
			isDeny:           true,
			mapBaseName:      "cilium_policy_v2_00123",
			trafficDirection: trafficdirection.Ingress,
			peerLbl:          12345,
			port:             1,
			protos:           allProtos,
		},
	}

	logger := hivetest.Logger(t)
	for _, tt := range tests {
		args, err := parsePolicyUpdateArgsHelper(logger, tt.args, tt.isDeny)

		if tt.invalid {
			require.Error(t, err)
		} else {
			require.NoError(t, err)
			require.Equal(t, args.isDeny, tt.isDeny)
			require.Equal(t, path.Base(args.path), tt.mapBaseName)
			require.Equal(t, args.trafficDirection, tt.trafficDirection)
			require.Equal(t, args.label, tt.peerLbl)
			require.Equal(t, args.port, tt.port)

			sortProtos(args.protocols)
			sortProtos(tt.protos)
			require.Equal(t, args.protocols, tt.protos)
		}
	}
}

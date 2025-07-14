// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package mcsapiCorednsCfg

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestUpdateCorefiles(t *testing.T) {
	for _, tc := range []struct {
		name             string
		corefile         string
		expectedError    bool
		expectedCorefile string
	}{
		{
			name: "normal corefile",
			corefile: `
.:53 {
    errors
    health {
       lameduck 5s
    }
    ready
    kubernetes mycluster.local in-addr.arpa ip6.arpa {
       pods insecure
       fallthrough in-addr.arpa ip6.arpa
       ttl 30
    }
    prometheus :9153
    forward . 1.1.1.1 {
       max_concurrent 1000
    }
    cache 30 {
       disable success mycluster.local
       disable denial mycluster.local
    }
    loop
    reload
    loadbalance
    log
}
`,
			expectedError: false,
			expectedCorefile: `
.:53 {
    errors
    health {
       lameduck 5s
    }
    ready
    kubernetes mycluster.local myclusterset.local in-addr.arpa ip6.arpa {
       multicluster myclusterset.local
       pods insecure
       fallthrough in-addr.arpa ip6.arpa
       ttl 30
    }
    prometheus :9153
    forward . 1.1.1.1 {
       max_concurrent 1000
    }
    cache 30 {
       disable success mycluster.local myclusterset.local
       disable denial mycluster.local myclusterset.local
    }
    loop
    reload
    loadbalance
    log
}
`,
		},
		{
			name: "corefile with wrong cluster domain",
			corefile: `
.:53 {
    errors
    health {
       lameduck 5s
    }
    ready
    kubernetes cluster.local in-addr.arpa ip6.arpa {
       pods insecure
       fallthrough in-addr.arpa ip6.arpa
       ttl 30
    }
    prometheus :9153
    forward . 1.1.1.1 {
       max_concurrent 1000
    }
    cache 30 {
       disable success cluster.local
       disable denial cluster.local
    }
    loop
    reload
    loadbalance
    log
}
`,
			expectedError: true,
		},
		{
			name: "corefile not using kubernetes plugin",
			corefile: `
.:53 {
    errors
    health {
       lameduck 5s
    }
    ready
    prometheus :9153
    forward . 1.1.1.1 {
       max_concurrent 1000
    }
    cache 30 {
       disable success cluster.local
       disable denial cluster.local
    }
    loop
    reload
    loadbalance
    log
}
`,
			expectedError: true,
		},
		{
			name: "corefile already using multicluster directive",
			corefile: `
.:53 {
    errors
    health {
       lameduck 5s
    }
    ready
    kubernetes mycluster.local in-addr.arpa ip6.arpa {
       multicluster helloworld
       pods insecure
       fallthrough in-addr.arpa ip6.arpa
       ttl 30
    }
    prometheus :9153
    forward . 1.1.1.1 {
       max_concurrent 1000
    }
    cache 30 {
       disable success cluster.local
       disable denial cluster.local
    }
    loop
    reload
    loadbalance
    log
}
`,
			expectedError: false,
		},
		{
			name: "corefile already using the clusterset domain in some way",
			corefile: `
.:53 {
    errors
    health {
       lameduck 5s
    }
    ready
    kubernetes mycluster.local myclusterset.local in-addr.arpa ip6.arpa {
       pods insecure
       fallthrough in-addr.arpa ip6.arpa
       ttl 30
    }
    prometheus :9153
    forward . 1.1.1.1 {
       max_concurrent 1000
    }
    cache 30 {
       disable success cluster.local
       disable denial cluster.local
    }
    loop
    reload
    loadbalance
    log
}
`,
			expectedError: false,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			corefile, err := updateCorefile("mycluster.local", "myclusterset.local", tc.corefile)
			if tc.expectedError {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
			require.Equal(t, tc.expectedCorefile, corefile)
		})
	}
}

func TestValideCoreDNSVersion(t *testing.T) {
	for _, tc := range []struct {
		name            string
		image           string
		expectedError   bool
		expectedWarning bool
	}{
		{
			name:            "Version not supported",
			image:           "registry.k8s.io/coredns/coredns:v1.12.0",
			expectedError:   true,
			expectedWarning: false,
		},
		{
			name:            "Exact supported version",
			image:           "registry.k8s.io/coredns/coredns:v1.12.2",
			expectedError:   false,
			expectedWarning: false,
		},
		{
			name:            "Exact supported version with digest",
			image:           "registry.k8s.io/coredns/coredns:v1.12.2@sha256:af8c8d35a5d184b386c4a6d1a012c8b218d40d1376474c7d071bb6c07201f47d",
			expectedError:   false,
			expectedWarning: false,
		},
		{
			name:            "Newer version than supported",
			image:           "registry.k8s.io/coredns/coredns:v1.13.0",
			expectedError:   false,
			expectedWarning: false,
		},
		{
			name:            "EKS image not using semantic versioning",
			image:           "public.ecr.aws/eks-distro/coredns/coredns:v1.12.2-eks-1-33-latest",
			expectedError:   false,
			expectedWarning: false,
		},
		{
			name:            "Custom version with build",
			image:           "mycompany.org/coredns:v1.12.2+1",
			expectedError:   false,
			expectedWarning: false,
		},
		{
			name:            "Custom version that we can't parse",
			image:           "mycompany.org/coredns:mycustomversion",
			expectedError:   false,
			expectedWarning: true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err, warn := validateCoreDNSVersion(tc.image)
			if tc.expectedError {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
			if tc.expectedWarning {
				require.Error(t, warn)
			} else {
				require.NoError(t, warn)
			}
		})
	}
}

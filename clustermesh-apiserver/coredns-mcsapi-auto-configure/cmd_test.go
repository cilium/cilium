// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package corednsMCSAPIAutoConfigure

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

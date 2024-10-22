// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Hubble

package watch

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"

	peerpb "github.com/cilium/cilium/api/v1/peer"
)

func Test_processResponse(t *testing.T) {
	var testCases = []struct {
		name               string
		changeNotification *peerpb.ChangeNotification
		expectedOutput     string
	}{
		{
			name: "happy path with tls",
			changeNotification: &peerpb.ChangeNotification{
				Name:    "foo.bar",
				Address: "1.2.3.4",
				Type:    peerpb.ChangeNotificationType_PEER_ADDED,
				Tls:     &peerpb.TLS{ServerName: "tls.foo.bar"},
			},
			expectedOutput: "PEER_ADDED   1.2.3.4 foo.bar (TLS.ServerName: tls.foo.bar)\n",
		},
		{
			name: "happy path with no tls",
			changeNotification: &peerpb.ChangeNotification{
				Name:    "foo.bar",
				Address: "1.2.3.4",
				Type:    peerpb.ChangeNotificationType_PEER_ADDED,
			},
			expectedOutput: "PEER_ADDED   1.2.3.4 foo.bar\n",
		},
		{
			name:           "sad path with unknown change notification",
			expectedOutput: "UNKNOWN       \n",
		},
	}

	for _, tc := range testCases {
		buf := bytes.Buffer{}
		processResponse(&buf, tc.changeNotification)
		assert.Equal(t, tc.expectedOutput, buf.String(), tc.name)
	}
}

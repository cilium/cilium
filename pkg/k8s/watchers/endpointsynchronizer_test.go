// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package watchers

import (
	"fmt"
	"testing"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	"github.com/cilium/cilium/pkg/endpoint"
	v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
)

func Test_updateCEPUID(t *testing.T) {
	epWithUID := func(uid string) *endpoint.Endpoint {
		ep := &endpoint.Endpoint{}
		ep.SetCiliumEndpointUID(types.UID(uid))
		return ep
	}
	someUID := func(s string) *types.UID {
		id := types.UID(s)
		return &id
	}
	for name, test := range map[string]struct {
		err           error
		cep           *v2.CiliumEndpoint
		ep            *endpoint.Endpoint
		expectedEPUID *types.UID
	}{
		// In this test, our CEP has a UID that is different from the local Endpoint.
		// This means that the CEP is not owned by this EP.
		// Ownership should fail due to Endpoint not having a network status.
		"no net status": {
			ep:  epWithUID("000"),
			err: fmt.Errorf("no nodeIP"),
			cep: &v2.CiliumEndpoint{
				ObjectMeta: v1.ObjectMeta{
					UID: "111", // Different UID from the local Endpoint.
				},
				Status: v2.EndpointStatus{},
			},
		},
		"CiliumEndpoint not local": {
			// The CEP is explicitly not local.
			ep:  epWithUID("1234"),
			err: fmt.Errorf("is not local"),
			cep: &v2.CiliumEndpoint{
				ObjectMeta: v1.ObjectMeta{UID: "1111"},
				Status: v2.EndpointStatus{
					Networking: &v2.EndpointNetworking{
						NodeIP: "1.2.3.4", // in testing, the node ip is returned as "<nil>"
					},
				},
			},
		},
		"CiliumEndpoint not local, but already owned": {
			// The CEP is explicitly not local. But the CEP is already owned by the endpoint.
			// So ownership should proceed without error.
			ep: epWithUID("000"), // matches CEP.
			cep: &v2.CiliumEndpoint{
				ObjectMeta: v1.ObjectMeta{UID: "000"},
				Status: v2.EndpointStatus{
					Networking: &v2.EndpointNetworking{
						NodeIP: "1.2.3.4", // in testing, the node ip is returned as "<nil>"
					},
				},
			},
		},
		"ciliumendpoint already exists": {
			// CEP already exists, on the same node, we cannot take ownership of it
			// due to differing UID ref.
			//
			// This would be the case where two endpoint sync controllers are running for
			// a Pod with the same namespace/name on the same Agent, so we'd have to wait
			// until the other controller terminates and cleans up the CEP.
			err:           fmt.Errorf("did not match CEP UID"),
			expectedEPUID: someUID("b"),
			ep:            epWithUID("b"),
			cep: &v2.CiliumEndpoint{
				ObjectMeta: v1.ObjectMeta{UID: types.UID("a")},
				Status: v2.EndpointStatus{
					Networking: &v2.EndpointNetworking{
						NodeIP: "<nil>", // in testing, the node ip is returned as "<nil>"
					},
				},
			},
		},
		"take ownership of cep due to empty CiliumEndpointUID ref": {
			ep:            &endpoint.Endpoint{},
			expectedEPUID: someUID("a"),
			cep: &v2.CiliumEndpoint{
				ObjectMeta: v1.ObjectMeta{UID: types.UID("a")},
				Status: v2.EndpointStatus{
					Networking: &v2.EndpointNetworking{
						NodeIP: "<nil>", // in testing, the node ip is returned as "<nil>"
					},
				},
			},
		},
	} {
		t.Run(name, func(t *testing.T) {
			assert := assert.New(t)
			err := updateCEPUID(logrus.StandardLogger().WithFields(logrus.Fields{}), test.ep, test.cep)
			if test.err == nil {
				assert.NoError(err)
			} else {
				assert.ErrorContains(err, test.err.Error())
			}
			if test.expectedEPUID != nil {
				assert.Equal(*test.expectedEPUID, test.ep.GetCiliumEndpointUID())
			}
		})

	}
}

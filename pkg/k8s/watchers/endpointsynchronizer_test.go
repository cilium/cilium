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
	for name, test := range map[string]struct {
		err           error
		cep           *v2.CiliumEndpoint
		ep            *endpoint.Endpoint
		expectedEPUID types.UID
	}{
		"no net status": {
			ep:  &endpoint.Endpoint{},
			err: fmt.Errorf("no nodeIP"),
			cep: &v2.CiliumEndpoint{Status: v2.EndpointStatus{}},
		},
		"non local": {
			ep:  &endpoint.Endpoint{},
			err: fmt.Errorf("is not local"),
			cep: &v2.CiliumEndpoint{
				Status: v2.EndpointStatus{
					Networking: &v2.EndpointNetworking{
						NodeIP: "1.2.3.4", // in testing, the node ip is returned as "<nil>"
					},
				},
			},
		},
		"ciliumendpoint already exists": {
			err:           fmt.Errorf("did not match CEP UID"),
			expectedEPUID: "b",
			ep: func() *endpoint.Endpoint {
				ep := &endpoint.Endpoint{}
				ep.SetCiliumEndpointUID("b")
				return ep
			}(),
			cep: &v2.CiliumEndpoint{
				ObjectMeta: v1.ObjectMeta{UID: types.UID("a")},
				Status: v2.EndpointStatus{
					Networking: &v2.EndpointNetworking{
						NodeIP: "<nil>", // in testing, the node ip is returned as "<nil>"
					},
				},
			},
		},
		"take ownership of cep": {
			ep:            &endpoint.Endpoint{},
			expectedEPUID: "a",
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
			assert.Equal(test.expectedEPUID, test.ep.GetCiliumEndpointUID())
		})

	}
}

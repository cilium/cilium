// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package endpointmanager

import (
	"fmt"
	"net"
	"testing"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	"github.com/cilium/cilium/pkg/endpoint"
	v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	"github.com/cilium/cilium/pkg/node"
)

func Test_updateCEPUID(t *testing.T) {
	podWithHostIP := func(hostIP string) *slim_corev1.Pod {
		return &slim_corev1.Pod{
			Status: slim_corev1.PodStatus{
				HostIP: hostIP,
			},
		}
	}
	epWithUID := func(uid string, pod *slim_corev1.Pod) *endpoint.Endpoint {
		ep := &endpoint.Endpoint{}
		ep.SetPod(pod)
		ep.SetCiliumEndpointUID(types.UID(uid))
		return ep
	}
	testIP := "1.2.3.4"
	someUID := func(s string) *types.UID {
		id := types.UID(s)
		return &id
	}
	for name, test := range map[string]struct {
		err           error
		cep           *v2.CiliumEndpoint
		ep            *endpoint.Endpoint
		nodeIP        string
		expectedEPUID *types.UID
	}{
		// In this test, our CEP has a UID that is different from the local Endpoint.
		// This means that the CEP is not owned by this EP.
		// Ownership should fail due to Endpoint not having a pod.
		// This condition is typically triggered when the pod is deleted.
		"no pod": {
			ep:     epWithUID("000", nil),
			err:    fmt.Errorf("no pod"),
			nodeIP: testIP,
			cep: &v2.CiliumEndpoint{
				ObjectMeta: v1.ObjectMeta{
					UID: "111", // Different UID from the local Endpoint.
				},
			},
		},
		"CiliumEndpoint not local": {
			// The CEP is explicitly not local (i.e the CEP's pod's hostIP doesn't match the nodeIP).
			ep:     epWithUID("1234", podWithHostIP(testIP)),
			nodeIP: "4.3.2.1",
			err:    fmt.Errorf("is not local"),
			cep: &v2.CiliumEndpoint{
				ObjectMeta: v1.ObjectMeta{UID: "1111"},
			},
		},
		"CiliumEndpoint not local, but already owned": {
			// The CEP is explicitly not local. But the CEP is already owned by the endpoint.
			// So ownership should proceed without error.
			ep:     epWithUID("000", podWithHostIP("4.3.2.1")), // matches CEP.
			nodeIP: testIP,
			cep: &v2.CiliumEndpoint{
				ObjectMeta: v1.ObjectMeta{UID: "000"},
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
			ep:            epWithUID("b", podWithHostIP(testIP)),
			nodeIP:        testIP,
			cep: &v2.CiliumEndpoint{
				ObjectMeta: v1.ObjectMeta{UID: types.UID("a")},
			},
		},
		// This is the normal case of taking ownership.
		// Note that this also happens when the nodeIP changes during a reboot
		// but the endpoint snapshot is lost on reboot. The endpoint UID will
		// remain empty, but the CEP object will have a UID and a wrong nodeIP.
		// It is to counter this case that we check the pods hostIP against the
		// nodeIP instead of the CEP's node IP.
		"take ownership of cep due to empty CiliumEndpointUID ref": {
			ep:            epWithUID("", podWithHostIP(testIP)),
			nodeIP:        testIP,
			expectedEPUID: someUID("a"),
			cep: &v2.CiliumEndpoint{
				ObjectMeta: v1.ObjectMeta{UID: types.UID("a")},
				Status: v2.EndpointStatus{
					Networking: &v2.EndpointNetworking{
						NodeIP: "4.5.6.7",
					},
				},
			},
		},
	} {
		t.Run(name, func(t *testing.T) {
			assert := assert.New(t)
			var err error
			node.WithTestLocalNodeStore(func() {
				node.UpdateLocalNodeInTest(func(n *node.LocalNode) {
					n.SetNodeInternalIP(net.ParseIP(test.nodeIP))
				})
				err = updateCEPUID(logrus.StandardLogger().WithFields(logrus.Fields{}), test.ep, test.cep)
			})
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

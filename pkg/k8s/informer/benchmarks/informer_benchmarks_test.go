// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package benchmarks

import (
	"context"
	"encoding/json"
	"os"
	"reflect"
	"strconv"
	"sync"
	"testing"

	. "github.com/cilium/checkmate"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/tools/cache"

	"github.com/cilium/cilium/pkg/annotation"
	"github.com/cilium/cilium/pkg/k8s"
	"github.com/cilium/cilium/pkg/k8s/informer"
)

func Test(t *testing.T) {
	TestingT(t)
}

type K8sIntegrationSuite struct{}

var _ = Suite(&K8sIntegrationSuite{})

func (k *K8sIntegrationSuite) SetUpSuite(c *C) {
}

var nodeSampleJSON = `{
    "apiVersion": "v1",
    "kind": "Node",
    "metadata": {
        "annotations": {
            "container.googleapis.com/instance_id": "111111111111111111",
            "network.cilium.io/ipv4-cilium-host": "10.0.0.1",
            "network.cilium.io/ipv4-health-ip": "10.0.0.1",
            "network.cilium.io/ipv4-pod-cidr": "10.0.0.1/27",
            "node.alpha.kubernetes.io/ttl": "30",
            "volumes.kubernetes.io/controller-managed-attach-detach": "true"
        },
        "creationTimestamp": "2019-03-07T13:35:02Z",
        "labels": {
            "kubernetes.io/arch": "amd64",
            "beta.kubernetes.io/fluentd-ds-ready": "true",
            "node.kubernetes.io/instance-type": "foo",
            "kubernetes.io/os": "linux",
            "cloud.google.com/gke-nodepool": "default-pool",
            "cloud.google.com/gke-os-distribution": "cos",
            "disktype": "ssd",
            "failure-domain.beta.kubernetes.io/region": "earth", // Remove after support for 1.17 is dropped
            "failure-domain.beta.kubernetes.io/zone": "earth", // Remove after support for 1.17 is dropped
            "topology.kubernetes.io/region": "earth",
            "topology.kubernetes.io/zone": "earth",
            "kubernetes.io/hostname": "super-node"
        },
        "name": "super-node",
        "resourceVersion": "0",
        "selfLink": "/api/v1/nodes/super-node",
        "uid": "cf66ea66-40dd-11e9-bcdf-4201ac100009"
    },
    "spec": {
        "podCIDR": "10.0.0.1/16",
        "providerID": "gce://universe/earth/super-node"
    },
    "status": {
        "addresses": [
            {
                "address": "10.0.0.1",
                "type": "InternalIP"
            },
            {
                "address": "",
                "type": "ExternalIP"
            },
            {
                "address": "super-node.c.earth.internal",
                "type": "InternalDNS"
            },
            {
                "address": "super-node.c.earth.internal",
                "type": "Hostname"
            }
        ],
        "allocatable": {
            "attachable-volumes-gce-pd": "0",
            "cpu": "0m",
            "ephemeral-storage": "0",
            "hugepages-2Mi": "0",
            "memory": "0",
            "pods": "0"
        },
        "capacity": {
            "attachable-volumes-gce-pd": "16",
            "cpu": "4",
            "ephemeral-storage": "26615568Ki",
            "hugepages-2Mi": "0",
            "memory": "8173944Ki",
            "pods": "16"
        },
        "conditions": [
            {
                "lastHeartbeatTime": "2019-03-15T10:49:17Z",
                "lastTransitionTime": "2019-03-07T13:40:03Z",
                "message": "kubelet is functioning properly",
                "reason": "FrequentKubeletRestart",
                "status": "False",
                "type": "FrequentKubeletRestart"
            },
            {
                "lastHeartbeatTime": "2019-03-15T10:49:17Z",
                "lastTransitionTime": "2019-03-07T13:40:04Z",
                "message": "docker is functioning properly",
                "reason": "FrequentDockerRestart",
                "status": "False",
                "type": "FrequentDockerRestart"
            },
            {
                "lastHeartbeatTime": "2019-03-15T10:49:17Z",
                "lastTransitionTime": "2019-03-07T13:40:05Z",
                "message": "containerd is functioning properly",
                "reason": "FrequentContainerdRestart",
                "status": "False",
                "type": "FrequentContainerdRestart"
            },
            {
                "lastHeartbeatTime": "2019-03-15T10:49:17Z",
                "lastTransitionTime": "2019-03-07T13:40:03Z",
                "message": "docker overlay2 is functioning properly",
                "reason": "CorruptDockerOverlay2",
                "status": "False",
                "type": "CorruptDockerOverlay2"
            },
            {
                "lastHeartbeatTime": "2019-03-15T10:49:17Z",
                "lastTransitionTime": "2019-03-07T13:35:01Z",
                "message": "kernel has no deadlock",
                "reason": "KernelHasNoDeadlock",
                "status": "False",
                "type": "KernelDeadlock"
            },
            {
                "lastHeartbeatTime": "2019-03-15T10:49:17Z",
                "lastTransitionTime": "2019-03-07T13:35:01Z",
                "message": "Filesystem is not read-only",
                "reason": "FilesystemIsNotReadOnly",
                "status": "False",
                "type": "ReadonlyFilesystem"
            },
            {
                "lastHeartbeatTime": "2019-03-15T10:49:17Z",
                "lastTransitionTime": "2019-03-07T13:40:03Z",
                "message": "node is functioning properly",
                "reason": "UnregisterNetDevice",
                "status": "False",
                "type": "FrequentUnregisterNetDevice"
            },
            {
                "lastHeartbeatTime": "2019-03-15T10:44:54Z",
                "lastTransitionTime": "2019-03-15T10:44:54Z",
                "message": "NodeController create implicit route",
                "reason": "RouteCreated",
                "status": "False",
                "type": "NetworkUnavailable"
            },
            {
                "lastHeartbeatTime": "2019-03-15T10:49:57Z",
                "lastTransitionTime": "2019-03-07T13:35:02Z",
                "message": "kubelet has sufficient disk space available",
                "reason": "KubeletHasSufficientDisk",
                "status": "False",
                "type": "OutOfDisk"
            },
            {
                "lastHeartbeatTime": "2019-03-15T10:49:57Z",
                "lastTransitionTime": "2019-03-07T13:35:02Z",
                "message": "kubelet has sufficient memory available",
                "reason": "KubeletHasSufficientMemory",
                "status": "False",
                "type": "MemoryPressure"
            },
            {
                "lastHeartbeatTime": "2019-03-15T10:49:57Z",
                "lastTransitionTime": "2019-03-07T13:35:02Z",
                "message": "kubelet has no disk pressure",
                "reason": "KubeletHasNoDiskPressure",
                "status": "False",
                "type": "DiskPressure"
            },
            {
                "lastHeartbeatTime": "2019-03-15T10:49:57Z",
                "lastTransitionTime": "2019-03-07T13:35:02Z",
                "message": "kubelet has sufficient PID available",
                "reason": "KubeletHasSufficientPID",
                "status": "False",
                "type": "PIDPressure"
            },
            {
                "lastHeartbeatTime": "2019-03-15T10:49:57Z",
                "lastTransitionTime": "2019-03-07T13:36:12Z",
                "message": "kubelet is posting ready status. AppArmor enabled",
                "reason": "KubeletReady",
                "status": "True",
                "type": "Ready"
            }
        ],
        "daemonEndpoints": {
            "kubeletEndpoint": {
                "Port": 10250
            }
        },
        "images": [
            {
                "names": [
                    "quay.io/cilium/cilium-dev@sha256:53e005e8ae3649412cfb5b5538916bc6c9f66c408ee6a76273e964a285cb28aa",
                    "quay.io/cilium/cilium-dev:scale-test-2019-03-13"
                ],
                "sizeBytes": 618888533
            },
            {
                "names": [
                    "quay.io/cilium/cilium@sha256:9f41fc120b2c8cf5006220bcea7ee17c573cb13f0d32b0578ea83690f6412b6e",
                    "quay.io/cilium/cilium:latest"
                ],
                "sizeBytes": 618884013
            },
            {
                "names": [
                    "quay.io/cilium/cilium-dev@sha256:41b2bc225d90a52cbf04f030fd4e4bb8235e00262e08643963dd887090d17b96",
                    "quay.io/cilium/cilium-dev:scale-test-2019-03-12"
                ],
                "sizeBytes": 618855547
            },
            {
                "names": [
                    "cilium/cilium@sha256:bb8a0507c1850f856d7c3e1ab27fa8246d666dcf5bab9040ced3d6513e730b02",
                    "cilium/cilium:latest"
                ],
                "sizeBytes": 618841491
            },
            {
                "names": [
                    "cilium/cilium@sha256:2d0ea8c2eee882c7005d5645f349f58bca57fcd8e2e682a517c400ccd045f9c2"
                ],
                "sizeBytes": 618821939
            },
            {
                "names": [
                    "cilium/cilium-dev@sha256:c55141a813d30123c34372b87d75c3b8ff4eaf955ff0531f93ec2a8fbd2d6dff",
                    "cilium/cilium-dev:tgraf-scale-fixes2"
                ],
                "sizeBytes": 618670939
            },
            {
                "names": [
                    "registry.k8s.io/node-problem-detector@sha256:f95cab985c26b2f46e9bd43283e0bfa88860c14e0fb0649266babe8b65e9eb2b",
                    "registry.k8s.io/node-problem-detector:v0.4.1"
                ],
                "sizeBytes": 286572743
            },
            {
                "names": [
                    "grafana/grafana@sha256:b5098a06dc59d28b11120eab01d8d0147b526a175aa606f9978934b6b2224138",
                    "grafana/grafana:6.0.0"
                ],
                "sizeBytes": 256099268
            },
            {
                "names": [
                    "quay.io/coreos/etcd-operator@sha256:3633b6d103e9efc2798e4214c8ee6d9b78f262eca65f085d76f5b4aee77e1e95",
                    "quay.io/coreos/etcd-operator:v0.9.3"
                ],
                "sizeBytes": 150833530
            },
            {
                "names": [
                    "registry.k8s.io/fluentd-elasticsearch@sha256:a54e7a450c0bdd19f49f56e487427a08c50f99ea8f8846179acf7d4182ce1fc0",
                    "registry.k8s.io/fluentd-elasticsearch:v2.2.0"
                ],
                "sizeBytes": 138313727
            },
            {
                "names": [
                    "registry.k8s.io/fluentd-gcp-scaler@sha256:457a13df66534b94bab627c4c2dc2df0ee5153a5d0f0afd27502bd46bd8da81d",
                    "registry.k8s.io/fluentd-gcp-scaler:0.5"
                ],
                "sizeBytes": 103488147
            },
            {
                "names": [
                    "registry.k8s.io/kubernetes-dashboard-amd64@sha256:dc4026c1b595435ef5527ca598e1e9c4343076926d7d62b365c44831395adbd0",
                    "registry.k8s.io/kubernetes-dashboard-amd64:v1.8.3"
                ],
                "sizeBytes": 102319441
            },
            {
                "names": [
                    "gcr.io/google_containers/kube-proxy:v1.12.5-gke.10",
                    "registry.k8s.io/kube-proxy:v1.12.5-gke.10"
                ],
                "sizeBytes": 101370340
            },
            {
                "names": [
                    "registry.k8s.io/event-exporter@sha256:7f9cd7cb04d6959b0aa960727d04fa86759008048c785397b7b0d9dff0007516",
                    "registry.k8s.io/event-exporter:v0.2.3"
                ],
                "sizeBytes": 94171943
            },
            {
                "names": [
                    "gcr.io/google-containers/prometheus-to-sd@sha256:6c0c742475363d537ff059136e5d5e4ab1f512ee0fd9b7ca42ea48bc309d1662",
                    "registry.k8s.io/prometheus-to-sd@sha256:6c0c742475363d537ff059136e5d5e4ab1f512ee0fd9b7ca42ea48bc309d1662",
                    "gcr.io/google-containers/prometheus-to-sd:v0.3.1",
                    "registry.k8s.io/prometheus-to-sd:v0.3.1"
                ],
                "sizeBytes": 88077694
            },
            {
                "names": [
                    "registry.k8s.io/heapster-amd64@sha256:9fae0af136ce0cf4f88393b3670f7139ffc464692060c374d2ae748e13144521",
                    "registry.k8s.io/heapster-amd64:v1.6.0-beta.1"
                ],
                "sizeBytes": 76016169
            },
            {
                "names": [
                    "registry.k8s.io/ingress-gce-glbc-amd64@sha256:14f14351a03038b238232e60850a9cfa0dffbed0590321ef84216a432accc1ca",
                    "registry.k8s.io/ingress-gce-glbc-amd64:v1.2.3"
                ],
                "sizeBytes": 71797285
            },
            {
                "names": [
                    "quay.io/cilium/cilium-dev@sha256:d8bb81b46f9e10e40ca106bc6a9ac0f3365e5310bbb5bfba1f52d1d8c8b64740",
                    "quay.io/cilium/cilium-dev:vetcd-v3.3.11-hf1-aanm"
                ],
                "sizeBytes": 64108258
            },
            {
                "names": [
                    "registry.k8s.io/kube-addon-manager@sha256:d53486c3a0b49ebee019932878dc44232735d5622a51dbbdcec7124199020d09",
                    "registry.k8s.io/kube-addon-manager:v8.7"
                ],
                "sizeBytes": 63322109
            },
            {
                "names": [
                    "registry.k8s.io/cpvpa-amd64@sha256:cfe7b0a11c9c8e18c87b1eb34fef9a7cbb8480a8da11fc2657f78dbf4739f869",
                    "registry.k8s.io/cpvpa-amd64:v0.6.0"
                ],
                "sizeBytes": 51785854
            },
            {
                "names": [
                    "registry.k8s.io/k8s-dns-kube-dns-amd64@sha256:618a82fa66cf0c75e4753369a6999032372be7308866fc9afb381789b1e5ad52",
                    "registry.k8s.io/k8s-dns-kube-dns@sha256:c54a527a4ba8f1bc15e4796b09bf5d69313c7f42af9911dc437e056c0264a2fe",
                    "registry.k8s.io/k8s-dns-kube-dns-amd64:1.14.13",
                    "registry.k8s.io/k8s-dns-kube-dns:1.14.13"
                ],
                "sizeBytes": 51157394
            },
            {
                "names": [
                    "registry.k8s.io/cluster-proportional-autoscaler-amd64@sha256:36359630278b119e7dd78f5437be1c667080108fa59ecba1b81cda3610dcf4d7",
                    "registry.k8s.io/cluster-proportional-autoscaler-amd64:1.2.0"
                ],
                "sizeBytes": 50258329
            },
            {
                "names": [
                    "registry.k8s.io/cluster-proportional-autoscaler-amd64@sha256:003f98d9f411ddfa6ff6d539196355e03ddd69fa4ed38c7ffb8fec6f729afe2d",
                    "registry.k8s.io/cluster-proportional-autoscaler-amd64:1.1.2-r2"
                ],
                "sizeBytes": 49648481
            },
            {
                "names": [
                    "registry.k8s.io/ip-masq-agent-amd64@sha256:1ffda57d87901bc01324c82ceb2145fe6a0448d3f0dd9cb65aa76a867cd62103",
                    "registry.k8s.io/ip-masq-agent-amd64:v2.1.1"
                ],
                "sizeBytes": 49612505
            },
            {
                "names": [
                    "quay.io/cilium/operator-dev@sha256:ab697ec83f8e3da7e64630c67252a5cf2ac4017ce2414c6c1d5476e165a844c6",
                    "quay.io/cilium/operator-dev:scale-test-2019-03-12"
                ],
                "sizeBytes": 48754920
            }
        ],
        "nodeInfo": {
            "architecture": "amd64",
            "bootID": "999999999999999999999999999",
            "containerRuntimeVersion": "docker://17.3.2",
            "kernelVersion": "4.14.91+",
            "kubeProxyVersion": "v1.12.5",
            "kubeletVersion": "v1.12.5",
            "machineID": "999999999999999999999999999",
            "operatingSystem": "linux",
            "osImage": "Container-Optimized OS from Google",
            "systemUUID": "999999999999999999999999999"
        }
    }
}
`

func (k *K8sIntegrationSuite) benchmarkInformer(ctx context.Context, nCycles int, newInformer bool, c *C) {
	n := v1.Node{}
	err := json.Unmarshal([]byte(nodeSampleJSON), &n)
	n.ResourceVersion = "1"
	c.Assert(err, IsNil)
	w := watch.NewFakeWithChanSize(nCycles, false)
	wg := sync.WaitGroup{}

	lw := &cache.ListWatch{
		ListFunc: func(_ metav1.ListOptions) (runtime.Object, error) {
			return &v1.NodeList{
				Items: []v1.Node{n},
			}, nil
		},
		WatchFunc: func(_ metav1.ListOptions) (watch.Interface, error) {
			return w, nil
		},
	}

	if newInformer {
		_, controller := informer.NewInformer(
			lw,
			&v1.Node{},
			0,
			cache.ResourceEventHandlerFuncs{
				AddFunc: func(obj interface{}) {},
				UpdateFunc: func(oldObj, newObj interface{}) {
					if oldK8sNP := k8s.ObjToV1Node(oldObj); oldK8sNP != nil {
						if newK8sNP := k8s.ObjToV1Node(newObj); newK8sNP != nil {
							if reflect.DeepEqual(oldK8sNP, newK8sNP) {
								return
							}
						}
					}
				},
				DeleteFunc: func(obj interface{}) {
					k8sNP := k8s.ObjToV1Node(obj)
					if k8sNP == nil {
						deletedObj, ok := obj.(cache.DeletedFinalStateUnknown)
						if !ok {
							return
						}
						// Delete was not observed by the watcher but is
						// removed from kube-apiserver. This is the last
						// known state and the object no longer exists.
						k8sNP = k8s.ObjToV1Node(deletedObj.Obj)
						if k8sNP == nil {
							return
						}
					}
					wg.Done()
				},
			},
			k8s.ConvertToNode,
		)
		go controller.Run(ctx.Done())
	} else {
		_, controller := cache.NewInformer(
			lw,
			&v1.Node{},
			0,
			cache.ResourceEventHandlerFuncs{
				AddFunc: func(obj interface{}) {},
				UpdateFunc: func(oldObj, newObj interface{}) {
					if oldK8sNP := OldCopyObjToV1Node(oldObj); oldK8sNP != nil {
						if newK8sNP := OldCopyObjToV1Node(newObj); newK8sNP != nil {
							if OldEqualV1Node(oldK8sNP, newK8sNP) {
								return
							}
						}
					}
				},
				DeleteFunc: func(obj interface{}) {
					k8sNP := OldCopyObjToV1Node(obj)
					if k8sNP == nil {
						deletedObj, ok := obj.(cache.DeletedFinalStateUnknown)
						if !ok {
							return
						}
						// Delete was not observed by the watcher but is
						// removed from kube-apiserver. This is the last
						// known state and the object no longer exists.
						k8sNP = OldCopyObjToV1Node(deletedObj.Obj)
						if k8sNP == nil {
							return
						}
					}
					wg.Done()
				},
			},
		)
		go controller.Run(ctx.Done())
	}

	wg.Add(1)
	c.ResetTimer()
	for i := 2; i <= nCycles; i++ {
		n.ResourceVersion = strconv.Itoa(i)
		w.Action(watch.Modified, &n)
	}
	w.Action(watch.Deleted, &n)
	wg.Wait()
	c.StopTimer()
}

func OldEqualV1Node(node1, node2 *v1.Node) bool {
	// The only information we care about the node is it's annotations, in
	// particularly the CiliumHostIP annotation.
	return node1.GetObjectMeta().GetName() == node2.GetObjectMeta().GetName() &&
		node1.GetAnnotations()[annotation.CiliumHostIP] == node2.GetAnnotations()[annotation.CiliumHostIP]
}

func OldCopyObjToV1Node(obj interface{}) *v1.Node {
	node, ok := obj.(*v1.Node)
	if !ok {
		return nil
	}
	return node.DeepCopy()
}

func (k *K8sIntegrationSuite) Benchmark_Informer(ctx context.Context, c *C) {
	nCycles, err := strconv.Atoi(os.Getenv("CYCLES"))
	if err != nil {
		nCycles = c.N
	}

	k.benchmarkInformer(ctx, nCycles, true, c)
}

func (k *K8sIntegrationSuite) Benchmark_K8sInformer(ctx context.Context, c *C) {
	nCycles, err := strconv.Atoi(os.Getenv("CYCLES"))
	if err != nil {
		nCycles = c.N
	}

	k.benchmarkInformer(ctx, nCycles, false, c)
}

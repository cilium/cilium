## Cilium Network Driver

Cilium Network Driver is a module that allows cilium-agent to expose
unmanaged network devices directly to pods. The Network Driver
registers itself as a DRA plugin and publishes resources to the Kubernetes api,
so pods can claim them as per the [DRA framework](https://kubernetes.io/docs/tasks/configure-pod-container/assign-resources/allocate-devices-dra/)

## Requirements

Kubernetes v1.34+

## Device Managers

A Device Manager implements the `types.DeviceManager` interface.
As of the time of writing, the only device manager with a working implementation
is for legacy SR-IOV VFs and Dummy devices. 

## Use cases

Applications that benefit from direct network device access and 
do not require participating in the cilium fabric (ex: separate network plane),
such as:

- dpdk based applications (ex: VNFs)
- low latency applications (ex: HFT)

## How to use the Network Driver

### Enabling the feature

The DRA framework, CRI integration hook and SR-IOV device
discovery & configuration require certain mounts from the host.
These mounts are not needed for any other existing feature,
and to avoid making such mounts a hard requirement to
all deployments, the Network Driver needs to be explicitly
enabled via the `networkDriver.enabled` helm flag.

### Provide an agent configuration

Once enabled, Cilium can be passed a configuration
by deploying a `CiliumNetworkDriverNodeConfig` CRD specifying the managers to be enabled:

```
---
apiVersion: cilium.io/v2alpha1
kind: CiliumNetworkDriverNodeConfig
metadata:
  name: examplenode
spec:
  driverName: "sriov.cilium.k8s.io"
  deviceManagerConfigs:
      dummy:
        enabled: true

```

Note that the cilium agent will look for a configuration with a `metadata.name` field matching
the hostname of the node.

In order to publish ResourceSlices, the pools need to be specified along with a filter to match devices:
```
---
apiVersion: cilium.io/v2alpha1
kind: CiliumNetworkDriverNodeConfig
metadata:
  name:  examplenode
spec:
  driverName: "sriov.cilium.k8s.io"
  pools:
    - name: a-side
      filter:
        ifNames:
          - dummy0
          - dummy1
  deviceManagerConfigs:
      dummy:
        enabled: true
```

### Verify the published devices

Each node publishes the devices found matching any of the
pool filters specified in the configuration as
`ResourceSlice` resources in the Kubernetes cluster.
The currently advertised pools can be seen with
```
$ kubectl get resourceslice
NAME                                                 NODE                       DRIVER                POOL     AGE
examplenode-sriov.cilium.k8s.io-mwm2t   examplenode   sriov.cilium.k8s.io   a-side   6s
```

### Prepare the device requests

A `DeviceClass` resource can be used to express a device
matching logic. This matching can be reused across multiple
`ResourceClaims` for workloads with similar device requirements.

```
---
apiVersion: resource.k8s.io/v1
kind: DeviceClass
metadata:
  name: a-side.sriov.cilium.k8s.io
  namespace: kube-system
spec:
  selectors:
  - cel:
      expression: device.driver == "sriov.cilium.k8s.io" && device.attributes["sriov.cilium.k8s.io"].pool == "a-side"

---
apiVersion: resource.k8s.io/v1
kind: DeviceClass
metadata:
  name: b-side.sriov.cilium.k8s.io
  namespace: kube-system
spec:
  selectors:
  - cel:
      expression: device.driver == "sriov.cilium.k8s.io" && device.attributes["sriov.cilium.k8s.io"].pool == "b-side"
```

A device request can be expressed by creating a
`ResourceClaim` or `ResourceClaimTemplate` that reference
a `DeviceClass`

```
---
apiVersion: resource.k8s.io/v1
kind: ResourceClaimTemplate
metadata:
  name: sriov
spec:
  spec:
    devices:
      config:
        - requests:
            - a-side
          opaque:
            driver: sriov.cilium.k8s.io
            parameters:
              vlan: 1001
              ipv4Addr: 192.168.1.1/24
      requests:
      - name: a-side
        exactly:
          deviceClassName: a-side.sriov.cilium.k8s.io
```

Alternatively, a `ResourceClaim` (or its template counterpart)
can match a device directly without a `DeviceClass`
reference.

```
---
apiVersion: resource.k8s.io/v1
kind: ResourceClaimTemplate
metadata:
  name: sriov2
spec:
  spec:
    devices:
      config:
        - requests:
            - a-side
          opaque:
            driver: sriov.cilium.k8s.io
            parameters:
              vlan: 1001
              ipv4Addr: 192.168.1.1/24
        - requests:
            - b-side
          opaque:
            driver: sriov.cilium.k8s.io
            parameters:
              vlan: 1002
              ipv4Addr: 192.168.2.1/24
      requests:
      - name: a-side
        exactly:
          deviceClassName: sriov.cilium.k8s.io
          selectors:
          - cel:
              expression: device.driver == "sriov.cilium.k8s.io" && device.attributes["sriov.cilium.k8s.io"].pool == "a-side"
      - name: b-side
        exactly:
          deviceClassName: sriov.cilium.k8s.io
          selectors:
          - cel:
              expression: device.driver == "sriov.cilium.k8s.io" && device.attributes["sriov.cilium.k8s.io"].pool == "b-side"
```

The configuration for the device is passed as an opaque
config in the resource request. The list of currently 
supported configuration options can be found in `types/types.go`

### Resource request

To have a workload requesting a device, simply reference
a `ResourceClaim` or `ResourceClaimTemplate` in the manifest.

```
---
apiVersion: v1
kind: Pod
metadata:
  name: alpine
spec:
  containers:
  ...
  resourceClaims:
  - name: sriov
    resourceClaimTemplateName: sriov
```

## References

## Feature status

Very experimental. Might not work flawlessly all the time.
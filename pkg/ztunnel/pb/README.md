# Protocol Documentation
<a name="top"></a>

## Table of Contents

- [ca_ztunnel.proto](#ca_ztunnel-proto)
    - [IstioCertificateRequest](#istio-v1-auth-IstioCertificateRequest)
    - [IstioCertificateResponse](#istio-v1-auth-IstioCertificateResponse)
  
    - [IstioCertificateService](#istio-v1-auth-IstioCertificateService)
  
- [workload_ztunnel.proto](#workload_ztunnel-proto)
    - [Address](#istio-workload-Address)
    - [ApplicationTunnel](#istio-workload-ApplicationTunnel)
    - [Extension](#istio-workload-Extension)
    - [GatewayAddress](#istio-workload-GatewayAddress)
    - [LoadBalancing](#istio-workload-LoadBalancing)
    - [Locality](#istio-workload-Locality)
    - [NamespacedHostname](#istio-workload-NamespacedHostname)
    - [NetworkAddress](#istio-workload-NetworkAddress)
    - [Port](#istio-workload-Port)
    - [PortList](#istio-workload-PortList)
    - [Service](#istio-workload-Service)
    - [Workload](#istio-workload-Workload)
    - [Workload.ServicesEntry](#istio-workload-Workload-ServicesEntry)
  
    - [ApplicationTunnel.Protocol](#istio-workload-ApplicationTunnel-Protocol)
    - [IPFamilies](#istio-workload-IPFamilies)
    - [LoadBalancing.HealthPolicy](#istio-workload-LoadBalancing-HealthPolicy)
    - [LoadBalancing.Mode](#istio-workload-LoadBalancing-Mode)
    - [LoadBalancing.Scope](#istio-workload-LoadBalancing-Scope)
    - [NetworkMode](#istio-workload-NetworkMode)
    - [TunnelProtocol](#istio-workload-TunnelProtocol)
    - [WorkloadStatus](#istio-workload-WorkloadStatus)
    - [WorkloadType](#istio-workload-WorkloadType)
  
- [zds_ztunnel.proto](#zds_ztunnel-proto)
    - [Ack](#istio-workload-zds-Ack)
    - [AddWorkload](#istio-workload-zds-AddWorkload)
    - [DelWorkload](#istio-workload-zds-DelWorkload)
    - [KeepWorkload](#istio-workload-zds-KeepWorkload)
    - [SnapshotSent](#istio-workload-zds-SnapshotSent)
    - [WorkloadInfo](#istio-workload-zds-WorkloadInfo)
    - [WorkloadRequest](#istio-workload-zds-WorkloadRequest)
    - [WorkloadResponse](#istio-workload-zds-WorkloadResponse)
    - [ZdsHello](#istio-workload-zds-ZdsHello)
  
    - [Version](#istio-workload-zds-Version)
  
- [Scalar Value Types](#scalar-value-types)



<a name="ca_ztunnel-proto"></a>
<p align="right"><a href="#top">Top</a></p>

## ca_ztunnel.proto



<a name="istio-v1-auth-IstioCertificateRequest"></a>

### IstioCertificateRequest
Certificate request message. The authentication should be based on:
1. Bearer tokens carried in the side channel;
2. Client-side certificate via Mutual TLS handshake.
Note: the service implementation is REQUIRED to verify the authenticated caller is authorize to
all SANs in the CSR. The server side may overwrite any requested certificate field based on its
policies.


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| csr | [string](#string) |  | PEM-encoded certificate request. The public key in the CSR is used to generate the certificate, and other fields in the generated certificate may be overwritten by the CA. |
| validity_duration | [int64](#int64) |  | Optional: requested certificate validity period, in seconds. |
| metadata | [google.protobuf.Struct](#google-protobuf-Struct) |  | $hide_from_docs Optional: Opaque metadata provided by the XDS node to Istio. Supported metadata: WorkloadName, WorkloadIP, ClusterID |






<a name="istio-v1-auth-IstioCertificateResponse"></a>

### IstioCertificateResponse
Certificate response message.


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| cert_chain | [string](#string) | repeated | PEM-encoded certificate chain. The leaf cert is the first element, and the root cert is the last element. |





 

 

 


<a name="istio-v1-auth-IstioCertificateService"></a>

### IstioCertificateService
Service for managing certificates issued by the CA.

| Method Name | Request Type | Response Type | Description |
| ----------- | ------------ | ------------- | ------------|
| CreateCertificate | [IstioCertificateRequest](#istio-v1-auth-IstioCertificateRequest) | [IstioCertificateResponse](#istio-v1-auth-IstioCertificateResponse) | Using provided CSR, returns a signed certificate. |

 



<a name="workload_ztunnel-proto"></a>
<p align="right"><a href="#top">Top</a></p>

## workload_ztunnel.proto



<a name="istio-workload-Address"></a>

### Address
Address represents a unique address.

Address joins two sub-resources, Workload and Service, to support querying by IP address.
Address is intended to be able to be looked up on-demand, allowing a client
to answer a question like &#34;what is this IP address&#34;, similar to a reverse DNS lookup.

Each resource will have a mesh-wide unique opaque name, defined in the individual messages.
In addition, to support lookup by IP address, they will have *alias* names for each IP the resource represents.
There may be multiple aliases for the same resource (examples: service in multiple networks, or a dual-stack workload).
Aliases are keyed by network/IP address. Example: &#34;default/1.2.3.4&#34;.

In some cases, we do not know the IP address of a Workload. For instance, we may simply know
that there is a workload behind a gateway, and rely on the gateway to handle the rest.
In this case, the key format will be &#34;resource-uid&#34;. The resource can be a Pod, WorkloadEntry, etc.
These resources cannot be looked up on-demand.

In some cases, we do not know the IP address of a Service. These services cannot be used for matching
outbound traffic, as we only have L4 attributes to route based on. However,
they can be used for Gateways.
In this case, the key format will be &#34;network/hostname&#34;.
These resources cannot be looked up on-demand.


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| workload | [Workload](#istio-workload-Workload) |  | Workload represents an individual workload. This could be a single Pod, a VM instance, etc. |
| service | [Service](#istio-workload-Service) |  | Service represents a service - a group of workloads that can be accessed together. |






<a name="istio-workload-ApplicationTunnel"></a>

### ApplicationTunnel
ApplicationProtocol specifies a workload  (application or gateway) can
consume tunnel information.


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| protocol | [ApplicationTunnel.Protocol](#istio-workload-ApplicationTunnel-Protocol) |  | A target natively handles this type of traffic. |
| port | [uint32](#uint32) |  | optional: if set, traffic should be sent to this port after the last zTunnel hop |






<a name="istio-workload-Extension"></a>

### Extension
Extension provides a mechanism to attach arbitrary additional configuration to an object.


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| name | [string](#string) |  | name provides an opaque name for the extension. This may have semantic meaning or used for debugging. This should be unique amongst all extensions attached to an item. |
| config | [google.protobuf.Any](#google-protobuf-Any) |  | config provides some opaque configuration. |






<a name="istio-workload-GatewayAddress"></a>

### GatewayAddress
GatewayAddress represents the address of a gateway


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| hostname | [NamespacedHostname](#istio-workload-NamespacedHostname) |  | TODO: add support for hostname lookup |
| address | [NetworkAddress](#istio-workload-NetworkAddress) |  |  |
| hbone_mtls_port | [uint32](#uint32) |  | port to reach the gateway at for mTLS HBONE connections |






<a name="istio-workload-LoadBalancing"></a>

### LoadBalancing



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| routing_preference | [LoadBalancing.Scope](#istio-workload-LoadBalancing-Scope) | repeated | routing_preference defines what scopes we want to keep traffic within. The `mode` determines how these routing preferences are handled |
| mode | [LoadBalancing.Mode](#istio-workload-LoadBalancing-Mode) |  | mode defines how we should handle the routing preferences. |
| health_policy | [LoadBalancing.HealthPolicy](#istio-workload-LoadBalancing-HealthPolicy) |  | health_policy defines how we should filter endpoints |






<a name="istio-workload-Locality"></a>

### Locality



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| region | [string](#string) |  |  |
| zone | [string](#string) |  |  |
| subzone | [string](#string) |  |  |






<a name="istio-workload-NamespacedHostname"></a>

### NamespacedHostname
NamespacedHostname represents a service bound to a specific namespace.


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| namespace | [string](#string) |  | The namespace the service is in. |
| hostname | [string](#string) |  | hostname (ex: gateway.example.com) |






<a name="istio-workload-NetworkAddress"></a>

### NetworkAddress
NetworkAddress represents an address bound to a specific network.


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| network | [string](#string) |  | Network represents the network this address is on. |
| address | [bytes](#bytes) |  | Address presents the IP (v4 or v6). |






<a name="istio-workload-Port"></a>

### Port



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| service_port | [uint32](#uint32) |  | Port the service is reached at (frontend). |
| target_port | [uint32](#uint32) |  | Port the service forwards to (backend). |






<a name="istio-workload-PortList"></a>

### PortList
PorList represents the ports for a service


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| ports | [Port](#istio-workload-Port) | repeated |  |






<a name="istio-workload-Service"></a>

### Service
Service represents a service - a group of workloads that can be accessed together.
The xds primary key is &#34;namespace/hostname&#34;.
Secondary (alias) keys are the unique `network/IP` pairs that the service can be reached at.


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| name | [string](#string) |  | Name represents the name for the service. For Kubernetes, this is the Service name. |
| namespace | [string](#string) |  | Namespace represents the namespace for the service. |
| hostname | [string](#string) |  | Hostname represents the FQDN of the service. For Kubernetes, this would be &lt;name&gt;.&lt;namespace&gt;.svc.&lt;cluster domain&gt;. |
| addresses | [NetworkAddress](#istio-workload-NetworkAddress) | repeated | Address represents the addresses the service can be reached at. There may be multiple addresses for a single service if it resides in multiple networks, multiple clusters, and/or if it&#39;s dual stack. For a headless kubernetes service, this list will be empty. |
| ports | [Port](#istio-workload-Port) | repeated | Ports for the service. The target_port may be overridden on a per-workload basis. |
| subject_alt_names | [string](#string) | repeated | Optional; if set, the SAN to verify for TLS connections. Typically, this is not set and per-workload identity is used to verify |
| waypoint | [GatewayAddress](#istio-workload-GatewayAddress) |  | Waypoint is the waypoint proxy for this service. When set, all incoming requests must go through the waypoint. |
| load_balancing | [LoadBalancing](#istio-workload-LoadBalancing) |  | Load balancing policy for selecting endpoints. Note: this applies only to connecting directly to the workload; when waypoints are used, the waypoint&#39;s load_balancing configuration is used. |
| ip_families | [IPFamilies](#istio-workload-IPFamilies) |  | IP families provides configuration about the IP families this service supports. |
| extensions | [Extension](#istio-workload-Extension) | repeated | Extension provides a mechanism to attach arbitrary additional configuration to an object. |






<a name="istio-workload-Workload"></a>

### Workload
Workload represents a workload - an endpoint (or collection behind a hostname).
The xds primary key is &#34;uid&#34; as defined on the workload below.
Secondary (alias) keys are the unique `network/IP` pairs that the workload can be reached at.


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| uid | [string](#string) |  | UID represents a globally unique opaque identifier for this workload. For k8s resources, it is recommended to use the more readable format:

cluster/group/kind/namespace/name/section-name

As an example, a ServiceEntry with two WorkloadEntries inlined could become two Workloads with the following UIDs: - cluster1/networking.istio.io/v1alpha3/ServiceEntry/default/external-svc/endpoint1 - cluster1/networking.istio.io/v1alpha3/ServiceEntry/default/external-svc/endpoint2

For VMs and other workloads other formats are also supported; for example, a single UID string: &#34;0ae5c03d-5fb3-4eb9-9de8-2bd4b51606ba&#34; |
| name | [string](#string) |  | Name represents the name for the workload. For Kubernetes, this is the pod name. This is just for debugging and may be elided as an optimization. |
| namespace | [string](#string) |  | Namespace represents the namespace for the workload. This is just for debugging and may be elided as an optimization. |
| addresses | [bytes](#bytes) | repeated | Address represents the IPv4/IPv6 address for the workload. This should be globally unique. This should not have a port number. Each workload must have at least either an address or hostname; not both. |
| hostname | [string](#string) |  | The hostname for the workload to be resolved by the ztunnel. DNS queries are sent on-demand by default. If the resolved DNS query has several endpoints, the request will be forwarded to the first response.

At a minimum, each workload must have either an address or hostname. For example, a workload that backs a Kubernetes service will typically have only endpoints. A workload that backs a headless Kubernetes service, however, will have both addresses as well as a hostname used for direct access to the headless endpoint. |
| network | [string](#string) |  | Network represents the network this workload is on. This may be elided for the default network. A (network,address) pair makeup a unique key for a workload *at a point in time*. |
| tunnel_protocol | [TunnelProtocol](#istio-workload-TunnelProtocol) |  | Protocol that should be used to connect to this workload. |
| trust_domain | [string](#string) |  | The SPIFFE identity of the workload. The identity is joined to form spiffe://&lt;trust_domain&gt;/ns/&lt;namespace&gt;/sa/&lt;service_account&gt;. TrustDomain of the workload. May be elided if this is the mesh wide default (typically cluster.local) |
| service_account | [string](#string) |  | ServiceAccount of the workload. May be elided if this is &#34;default&#34; |
| waypoint | [GatewayAddress](#istio-workload-GatewayAddress) |  | If present, the waypoint proxy for this workload. All incoming requests must go through the waypoint. |
| network_gateway | [GatewayAddress](#istio-workload-GatewayAddress) |  | If present, East West network gateway this workload can be reached through. Requests from remote networks should traverse this gateway. |
| node | [string](#string) |  | Name of the node the workload runs on |
| canonical_name | [string](#string) |  | CanonicalName for the workload. Used for telemetry. |
| canonical_revision | [string](#string) |  | CanonicalRevision for the workload. Used for telemetry. |
| workload_type | [WorkloadType](#istio-workload-WorkloadType) |  | WorkloadType represents the type of the workload. Used for telemetry. |
| workload_name | [string](#string) |  | WorkloadName represents the name for the workload (of type WorkloadType). Used for telemetry. |
| native_tunnel | [bool](#bool) |  | If set, this indicates a workload expects to directly receive tunnel traffic. In ztunnel, this means: * Requests *from* this workload do not need to be tunneled if they already are tunneled by the tunnel_protocol. * Requests *to* this workload, via the tunnel_protocol, do not need to be de-tunneled. |
| application_tunnel | [ApplicationTunnel](#istio-workload-ApplicationTunnel) |  | If an application, such as a sandwiched waypoint proxy, supports directly receiving information from zTunnel they can set application_protocol. |
| services | [Workload.ServicesEntry](#istio-workload-Workload-ServicesEntry) | repeated | The services for which this workload is an endpoint. The key is the NamespacedHostname string of the format namespace/hostname. |
| authorization_policies | [string](#string) | repeated | A list of authorization policies applicable to this workload. NOTE: this *only* includes Selector based policies. Namespace and global polices are returned out of band. Authorization policies are only valid for workloads with `addresses` rather than `hostname`. |
| status | [WorkloadStatus](#istio-workload-WorkloadStatus) |  |  |
| cluster_id | [string](#string) |  | The cluster ID that the workload instance belongs to |
| locality | [Locality](#istio-workload-Locality) |  | The Locality defines information about where a workload is geographically deployed |
| network_mode | [NetworkMode](#istio-workload-NetworkMode) |  |  |
| extensions | [Extension](#istio-workload-Extension) | repeated | Extension provides a mechanism to attach arbitrary additional configuration to an object. |
| capacity | [google.protobuf.UInt32Value](#google-protobuf-UInt32Value) |  | Capacity for this workload. This represents the amount of traffic the workload can handle, relative to other workloads If unset, the capacity is default to 1. |






<a name="istio-workload-Workload-ServicesEntry"></a>

### Workload.ServicesEntry



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| key | [string](#string) |  |  |
| value | [PortList](#istio-workload-PortList) |  |  |





 


<a name="istio-workload-ApplicationTunnel-Protocol"></a>

### ApplicationTunnel.Protocol


| Name | Number | Description |
| ---- | ------ | ----------- |
| NONE | 0 | Bytes are copied from the inner stream without modification. |
| PROXY | 1 | Prepend PROXY protocol headers before copying bytes Standard PROXY source and destination information is included, along with potential extra TLV headers: 0xD0 - The SPIFFE identity of the source workload 0xD1 - The FQDN or Hostname of the targeted Service |



<a name="istio-workload-IPFamilies"></a>

### IPFamilies


| Name | Number | Description |
| ---- | ------ | ----------- |
| AUTOMATIC | 0 | AUTOMATIC is inferred from the configured addresses. |
| IPV4_ONLY | 1 | Only IPv4 is supported |
| IPV6_ONLY | 2 | Only IPv6 is supported |
| DUAL | 3 | Both IPv4 and IPv6 is supported |



<a name="istio-workload-LoadBalancing-HealthPolicy"></a>

### LoadBalancing.HealthPolicy


| Name | Number | Description |
| ---- | ------ | ----------- |
| ONLY_HEALTHY | 0 | Only select healthy endpoints |
| ALLOW_ALL | 1 | Include all endpoints, even if they are unhealthy. |



<a name="istio-workload-LoadBalancing-Mode"></a>

### LoadBalancing.Mode


| Name | Number | Description |
| ---- | ------ | ----------- |
| UNSPECIFIED_MODE | 0 |  |
| STRICT | 1 | In STRICT mode, only endpoints that meets all of the routing preferences will be considered. This can be used, for instance, to keep traffic ONLY within the same cluster/node/region. This should be used with caution, as it can result in all traffic being dropped if there is no matching endpoints, even if there are endpoints outside of the preferences. |
| FAILOVER | 2 | In FAILOVER mode, endpoint selection will prefer endpoints that match all preferences, but failover to groups of endpoints that match less (or, eventually, none) preferences. For instance, with `[NETWORK, REGION, ZONE]`, we will send to: 1. Endpoints matching `[NETWORK, REGION, ZONE]` 2. Endpoints matching `[NETWORK, REGION]` 3. Endpoints matching `[NETWORK]` 4. Any endpoints |



<a name="istio-workload-LoadBalancing-Scope"></a>

### LoadBalancing.Scope


| Name | Number | Description |
| ---- | ------ | ----------- |
| UNSPECIFIED_SCOPE | 0 |  |
| REGION | 1 | Prefer traffic in the same region. |
| ZONE | 2 | Prefer traffic in the same zone. |
| SUBZONE | 3 | Prefer traffic in the same subzone. |
| NODE | 4 | Prefer traffic on the same node. |
| CLUSTER | 5 | Prefer traffic in the same cluster. |
| NETWORK | 6 | Prefer traffic in the same network. |



<a name="istio-workload-NetworkMode"></a>

### NetworkMode
NetworkMode indicates how the addresses of the workload should be treated.

| Name | Number | Description |
| ---- | ------ | ----------- |
| STANDARD | 0 | STANDARD means that the workload is uniquely identified by its address (within its network). |
| HOST_NETWORK | 1 | HOST_NETWORK means the workload has an IP address that is shared by many workloads. The data plane should avoid attempting to lookup these workloads by IP address (which could return the wrong result). |



<a name="istio-workload-TunnelProtocol"></a>

### TunnelProtocol
TunnelProtocol indicates the tunneling protocol for requests.

| Name | Number | Description |
| ---- | ------ | ----------- |
| NONE | 0 | NONE means requests should be forwarded as-is, without tunneling. |
| HBONE | 1 | HBONE means requests should be tunneled over HTTP. This does not dictate HTTP/1.1 vs HTTP/2; ALPN should be used for that purpose.

Future options may include things like QUIC/HTTP3, etc. |



<a name="istio-workload-WorkloadStatus"></a>

### WorkloadStatus


| Name | Number | Description |
| ---- | ------ | ----------- |
| HEALTHY | 0 | Workload is healthy and ready to serve traffic. |
| UNHEALTHY | 1 | Workload is unhealthy and NOT ready to serve traffic. |



<a name="istio-workload-WorkloadType"></a>

### WorkloadType


| Name | Number | Description |
| ---- | ------ | ----------- |
| DEPLOYMENT | 0 |  |
| CRONJOB | 1 |  |
| POD | 2 |  |
| JOB | 3 |  |


 

 

 



<a name="zds_ztunnel-proto"></a>
<p align="right"><a href="#top">Top</a></p>

## zds_ztunnel.proto



<a name="istio-workload-zds-Ack"></a>

### Ack
Ztunnel ack message. If error is not empty, this is an error message.


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| error | [string](#string) |  |  |






<a name="istio-workload-zds-AddWorkload"></a>

### AddWorkload
Add a workload to the ztunnel. This will be accompanied by ancillary data containing
the workload&#39;s netns file descriptor.


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| uid | [string](#string) |  |  |
| workload_info | [WorkloadInfo](#istio-workload-zds-WorkloadInfo) |  |  |






<a name="istio-workload-zds-DelWorkload"></a>

### DelWorkload
Delete a workload from the ztunnel. Ztunnel should shutdown the workload&#39;s proxy.


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| uid | [string](#string) |  |  |






<a name="istio-workload-zds-KeepWorkload"></a>

### KeepWorkload
Keep workload that we can&#39;t find in the fd cache. This can only be sent before SnapshotSent is sent
to signal ztunnel to not delete the workload if it has it.


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| uid | [string](#string) |  |  |






<a name="istio-workload-zds-SnapshotSent"></a>

### SnapshotSent
Let ztunnel know that a full snapshot was sent. Ztunnel should reconcile its internal state
and remove internal entries that were not sent.






<a name="istio-workload-zds-WorkloadInfo"></a>

### WorkloadInfo



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| name | [string](#string) |  |  |
| namespace | [string](#string) |  |  |
| service_account | [string](#string) |  |  |






<a name="istio-workload-zds-WorkloadRequest"></a>

### WorkloadRequest
Sent from CNI to ztunnel


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| add | [AddWorkload](#istio-workload-zds-AddWorkload) |  |  |
| keep | [KeepWorkload](#istio-workload-zds-KeepWorkload) |  |  |
| del | [DelWorkload](#istio-workload-zds-DelWorkload) |  |  |
| snapshot_sent | [SnapshotSent](#istio-workload-zds-SnapshotSent) |  |  |






<a name="istio-workload-zds-WorkloadResponse"></a>

### WorkloadResponse
Sent from ztunnel to CNI


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| ack | [Ack](#istio-workload-zds-Ack) |  |  |






<a name="istio-workload-zds-ZdsHello"></a>

### ZdsHello



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| version | [Version](#istio-workload-zds-Version) |  |  |





 


<a name="istio-workload-zds-Version"></a>

### Version


| Name | Number | Description |
| ---- | ------ | ----------- |
| NOT_USED | 0 |  |
| V1 | 1 |  |


 

 

 



## Scalar Value Types

| .proto Type | Notes | C++ | Java | Python | Go | C# | PHP | Ruby |
| ----------- | ----- | --- | ---- | ------ | -- | -- | --- | ---- |
| <a name="double" /> double |  | double | double | float | float64 | double | float | Float |
| <a name="float" /> float |  | float | float | float | float32 | float | float | Float |
| <a name="int32" /> int32 | Uses variable-length encoding. Inefficient for encoding negative numbers – if your field is likely to have negative values, use sint32 instead. | int32 | int | int | int32 | int | integer | Bignum or Fixnum (as required) |
| <a name="int64" /> int64 | Uses variable-length encoding. Inefficient for encoding negative numbers – if your field is likely to have negative values, use sint64 instead. | int64 | long | int/long | int64 | long | integer/string | Bignum |
| <a name="uint32" /> uint32 | Uses variable-length encoding. | uint32 | int | int/long | uint32 | uint | integer | Bignum or Fixnum (as required) |
| <a name="uint64" /> uint64 | Uses variable-length encoding. | uint64 | long | int/long | uint64 | ulong | integer/string | Bignum or Fixnum (as required) |
| <a name="sint32" /> sint32 | Uses variable-length encoding. Signed int value. These more efficiently encode negative numbers than regular int32s. | int32 | int | int | int32 | int | integer | Bignum or Fixnum (as required) |
| <a name="sint64" /> sint64 | Uses variable-length encoding. Signed int value. These more efficiently encode negative numbers than regular int64s. | int64 | long | int/long | int64 | long | integer/string | Bignum |
| <a name="fixed32" /> fixed32 | Always four bytes. More efficient than uint32 if values are often greater than 2^28. | uint32 | int | int | uint32 | uint | integer | Bignum or Fixnum (as required) |
| <a name="fixed64" /> fixed64 | Always eight bytes. More efficient than uint64 if values are often greater than 2^56. | uint64 | long | int/long | uint64 | ulong | integer/string | Bignum |
| <a name="sfixed32" /> sfixed32 | Always four bytes. | int32 | int | int | int32 | int | integer | Bignum or Fixnum (as required) |
| <a name="sfixed64" /> sfixed64 | Always eight bytes. | int64 | long | int/long | int64 | long | integer/string | Bignum |
| <a name="bool" /> bool |  | bool | boolean | boolean | bool | bool | boolean | TrueClass/FalseClass |
| <a name="string" /> string | A string must always contain UTF-8 encoded or 7-bit ASCII text. | string | String | str/unicode | string | string | string | String (UTF-8) |
| <a name="bytes" /> bytes | May contain any arbitrary sequence of bytes. | string | ByteString | str | []byte | ByteString | string | String (ASCII-8BIT) |


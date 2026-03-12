# Protocol Documentation
<a name="top"></a>

## Table of Contents

- [datapathplugins/datapathplugins.proto](#datapathplugins_datapathplugins-proto)
    - [AttachmentContext](#datapathplugins-AttachmentContext)
    - [AttachmentContext.Host](#datapathplugins-AttachmentContext-Host)
    - [AttachmentContext.InterfaceInfo](#datapathplugins-AttachmentContext-InterfaceInfo)
    - [AttachmentContext.LXC](#datapathplugins-AttachmentContext-LXC)
    - [AttachmentContext.Overlay](#datapathplugins-AttachmentContext-Overlay)
    - [AttachmentContext.PodInfo](#datapathplugins-AttachmentContext-PodInfo)
    - [AttachmentContext.Socket](#datapathplugins-AttachmentContext-Socket)
    - [AttachmentContext.Wireguard](#datapathplugins-AttachmentContext-Wireguard)
    - [AttachmentContext.XDP](#datapathplugins-AttachmentContext-XDP)
    - [InstrumentCollectionRequest](#datapathplugins-InstrumentCollectionRequest)
    - [InstrumentCollectionRequest.Collection](#datapathplugins-InstrumentCollectionRequest-Collection)
    - [InstrumentCollectionRequest.Collection.Map](#datapathplugins-InstrumentCollectionRequest-Collection-Map)
    - [InstrumentCollectionRequest.Collection.MapsEntry](#datapathplugins-InstrumentCollectionRequest-Collection-MapsEntry)
    - [InstrumentCollectionRequest.Collection.Program](#datapathplugins-InstrumentCollectionRequest-Collection-Program)
    - [InstrumentCollectionRequest.Collection.ProgramsEntry](#datapathplugins-InstrumentCollectionRequest-Collection-ProgramsEntry)
    - [InstrumentCollectionRequest.Hook](#datapathplugins-InstrumentCollectionRequest-Hook)
    - [InstrumentCollectionRequest.Hook.AttachTarget](#datapathplugins-InstrumentCollectionRequest-Hook-AttachTarget)
    - [InstrumentCollectionResponse](#datapathplugins-InstrumentCollectionResponse)
    - [PrepareCollectionRequest](#datapathplugins-PrepareCollectionRequest)
    - [PrepareCollectionRequest.CollectionSpec](#datapathplugins-PrepareCollectionRequest-CollectionSpec)
    - [PrepareCollectionRequest.CollectionSpec.MapSpec](#datapathplugins-PrepareCollectionRequest-CollectionSpec-MapSpec)
    - [PrepareCollectionRequest.CollectionSpec.MapsEntry](#datapathplugins-PrepareCollectionRequest-CollectionSpec-MapsEntry)
    - [PrepareCollectionRequest.CollectionSpec.ProgramSpec](#datapathplugins-PrepareCollectionRequest-CollectionSpec-ProgramSpec)
    - [PrepareCollectionRequest.CollectionSpec.ProgramsEntry](#datapathplugins-PrepareCollectionRequest-CollectionSpec-ProgramsEntry)
    - [PrepareCollectionResponse](#datapathplugins-PrepareCollectionResponse)
    - [PrepareCollectionResponse.HookSpec](#datapathplugins-PrepareCollectionResponse-HookSpec)
    - [PrepareCollectionResponse.HookSpec.OrderingConstraint](#datapathplugins-PrepareCollectionResponse-HookSpec-OrderingConstraint)
  
    - [HookType](#datapathplugins-HookType)
    - [PrepareCollectionResponse.HookSpec.OrderingConstraint.Order](#datapathplugins-PrepareCollectionResponse-HookSpec-OrderingConstraint-Order)
  
    - [DatapathPlugin](#datapathplugins-DatapathPlugin)
  
- [Scalar Value Types](#scalar-value-types)



<a name="datapathplugins_datapathplugins-proto"></a>
<p align="right"><a href="#top">Top</a></p>

## datapathplugins/datapathplugins.proto



<a name="datapathplugins-AttachmentContext"></a>

### AttachmentContext
AttachmentContext contains the context about the attachment point in
question. It may carry endpoint-specific information used to determine which
hooks to load or how to configure them.


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| host | [AttachmentContext.Host](#datapathplugins-AttachmentContext-Host) |  |  |
| lxc | [AttachmentContext.LXC](#datapathplugins-AttachmentContext-LXC) |  |  |
| overlay | [AttachmentContext.Overlay](#datapathplugins-AttachmentContext-Overlay) |  |  |
| socket | [AttachmentContext.Socket](#datapathplugins-AttachmentContext-Socket) |  |  |
| wireguard | [AttachmentContext.Wireguard](#datapathplugins-AttachmentContext-Wireguard) |  |  |
| xdp | [AttachmentContext.XDP](#datapathplugins-AttachmentContext-XDP) |  |  |






<a name="datapathplugins-AttachmentContext-Host"></a>

### AttachmentContext.Host
attachment context for bpf_host (netdev, cilium_host, cilium_net).


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| iface | [AttachmentContext.InterfaceInfo](#datapathplugins-AttachmentContext-InterfaceInfo) |  | interface that is being configured. |






<a name="datapathplugins-AttachmentContext-InterfaceInfo"></a>

### AttachmentContext.InterfaceInfo
InterfaceInfo contains information about a network interface.


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| name | [string](#string) |  | name of the network interface. |






<a name="datapathplugins-AttachmentContext-LXC"></a>

### AttachmentContext.LXC
attachment context for bpf_lxc (containers).


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| iface | [AttachmentContext.InterfaceInfo](#datapathplugins-AttachmentContext-InterfaceInfo) |  | interface that is being configured. |
| pod_info | [AttachmentContext.PodInfo](#datapathplugins-AttachmentContext-PodInfo) |  | pod that is being configured. |






<a name="datapathplugins-AttachmentContext-Overlay"></a>

### AttachmentContext.Overlay
attachment context for bpf_overlay (vxlan/geneve).


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| iface | [AttachmentContext.InterfaceInfo](#datapathplugins-AttachmentContext-InterfaceInfo) |  | interface that is being configured. |






<a name="datapathplugins-AttachmentContext-PodInfo"></a>

### AttachmentContext.PodInfo
PodInfo contains information about a pod.


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| namespace | [string](#string) |  | pod namespace. |
| name | [string](#string) |  | pod name. |
| container_name | [string](#string) |  | container name. |






<a name="datapathplugins-AttachmentContext-Socket"></a>

### AttachmentContext.Socket
attachment context for bpf_sock (connect4,bind4,...)






<a name="datapathplugins-AttachmentContext-Wireguard"></a>

### AttachmentContext.Wireguard
attachment context for bpf_wireguard (cilium_wg)


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| iface | [AttachmentContext.InterfaceInfo](#datapathplugins-AttachmentContext-InterfaceInfo) |  | interface that is being configured. |






<a name="datapathplugins-AttachmentContext-XDP"></a>

### AttachmentContext.XDP
attachment context for bpf_xdp (netdev)


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| iface | [AttachmentContext.InterfaceInfo](#datapathplugins-AttachmentContext-InterfaceInfo) |  | interface that is being configured. |






<a name="datapathplugins-InstrumentCollectionRequest"></a>

### InstrumentCollectionRequest
Phase 2: Cilium has constructed and loaded the collection along with any
dispatcher programs that are meant to replace existing entrypoints in the
collection. Cilium sends a round of requests to any plugins that wanted to
inject hooks in the prepare phase.


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| collection | [InstrumentCollectionRequest.Collection](#datapathplugins-InstrumentCollectionRequest-Collection) |  |  |
| attachment_context | [AttachmentContext](#datapathplugins-AttachmentContext) |  |  |
| config | [google.protobuf.Any](#google-protobuf-Any) |  | config contains datapath configuration for this collection. |
| hooks | [InstrumentCollectionRequest.Hook](#datapathplugins-InstrumentCollectionRequest-Hook) | repeated | list of hooks corresponding with those specified by the plugin in its PrepareHooks response. |
| pins | [string](#string) |  | an ephemeral per-request bpffs directory where a plugin can pin an arbitrary set of objects. The lifecycle of these pins will be bound to that of the attachment context. This is useful especially in cases where the plugin loads its own set of tail call programs accessible from the entrypoint hook program and want to make sure a PROG_ARRAY and the programs it contains remain intact even after the InstrumentCollection request returns. |
| cookie | [string](#string) |  | cookie matches the cookie provided in the plugin&#39;s PrepareHooks response. |






<a name="datapathplugins-InstrumentCollectionRequest-Collection"></a>

### InstrumentCollectionRequest.Collection
Program and map IDs in the collection


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| programs | [InstrumentCollectionRequest.Collection.ProgramsEntry](#datapathplugins-InstrumentCollectionRequest-Collection-ProgramsEntry) | repeated | program details for each programs in the collection. |
| maps | [InstrumentCollectionRequest.Collection.MapsEntry](#datapathplugins-InstrumentCollectionRequest-Collection-MapsEntry) | repeated | map details for each map in the collection. |






<a name="datapathplugins-InstrumentCollectionRequest-Collection-Map"></a>

### InstrumentCollectionRequest.Collection.Map



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| id | [uint32](#uint32) |  |  |






<a name="datapathplugins-InstrumentCollectionRequest-Collection-MapsEntry"></a>

### InstrumentCollectionRequest.Collection.MapsEntry



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| key | [string](#string) |  |  |
| value | [InstrumentCollectionRequest.Collection.Map](#datapathplugins-InstrumentCollectionRequest-Collection-Map) |  |  |






<a name="datapathplugins-InstrumentCollectionRequest-Collection-Program"></a>

### InstrumentCollectionRequest.Collection.Program



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| id | [uint32](#uint32) |  |  |






<a name="datapathplugins-InstrumentCollectionRequest-Collection-ProgramsEntry"></a>

### InstrumentCollectionRequest.Collection.ProgramsEntry



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| key | [string](#string) |  |  |
| value | [InstrumentCollectionRequest.Collection.Program](#datapathplugins-InstrumentCollectionRequest-Collection-Program) |  |  |






<a name="datapathplugins-InstrumentCollectionRequest-Hook"></a>

### InstrumentCollectionRequest.Hook



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| type | [HookType](#datapathplugins-HookType) |  | position of the hook relative to the target program. |
| target | [string](#string) |  | name of the program that should be instrumented. |
| attach_target | [InstrumentCollectionRequest.Hook.AttachTarget](#datapathplugins-InstrumentCollectionRequest-Hook-AttachTarget) |  | info necessary for loading freplace programs. |
| pin_path | [string](#string) |  | plugin must pin the hook program to this pin path before responding to Cilium. |






<a name="datapathplugins-InstrumentCollectionRequest-Hook-AttachTarget"></a>

### InstrumentCollectionRequest.Hook.AttachTarget



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| program_id | [uint32](#uint32) |  | id of the target program. |
| subprog_name | [string](#string) |  | name of the hook&#39;s subprogram inside the target program. |






<a name="datapathplugins-InstrumentCollectionResponse"></a>

### InstrumentCollectionResponse







<a name="datapathplugins-PrepareCollectionRequest"></a>

### PrepareCollectionRequest
Phase 1: As Cilium loads and prepares a collection for a particular
attachment point, it sends a PrepareHooksRequest to each plugin with context
about the attachment point, collection, and its configuration. The plugin
decides which hooks it would like to insert, where it would like to insert
them, and informs Cilium in the PrepareHooksResponse.


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| collection | [PrepareCollectionRequest.CollectionSpec](#datapathplugins-PrepareCollectionRequest-CollectionSpec) |  |  |
| attachment_context | [AttachmentContext](#datapathplugins-AttachmentContext) |  |  |
| config | [google.protobuf.Any](#google-protobuf-Any) |  | config contains datapath configuration for this collection. |






<a name="datapathplugins-PrepareCollectionRequest-CollectionSpec"></a>

### PrepareCollectionRequest.CollectionSpec



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| programs | [PrepareCollectionRequest.CollectionSpec.ProgramsEntry](#datapathplugins-PrepareCollectionRequest-CollectionSpec-ProgramsEntry) | repeated | program details for each programs in the collection. |
| maps | [PrepareCollectionRequest.CollectionSpec.MapsEntry](#datapathplugins-PrepareCollectionRequest-CollectionSpec-MapsEntry) | repeated | map details for each map in the collection. |






<a name="datapathplugins-PrepareCollectionRequest-CollectionSpec-MapSpec"></a>

### PrepareCollectionRequest.CollectionSpec.MapSpec



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| type | [uint32](#uint32) |  |  |
| key_size | [uint32](#uint32) |  |  |
| value_size | [uint32](#uint32) |  |  |
| max_entries | [uint32](#uint32) |  |  |
| flags | [uint32](#uint32) |  |  |
| pin_type | [uint32](#uint32) |  |  |






<a name="datapathplugins-PrepareCollectionRequest-CollectionSpec-MapsEntry"></a>

### PrepareCollectionRequest.CollectionSpec.MapsEntry



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| key | [string](#string) |  |  |
| value | [PrepareCollectionRequest.CollectionSpec.MapSpec](#datapathplugins-PrepareCollectionRequest-CollectionSpec-MapSpec) |  |  |






<a name="datapathplugins-PrepareCollectionRequest-CollectionSpec-ProgramSpec"></a>

### PrepareCollectionRequest.CollectionSpec.ProgramSpec



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| type | [uint32](#uint32) |  |  |
| attach_type | [uint32](#uint32) |  |  |
| section_name | [string](#string) |  |  |
| license | [string](#string) |  |  |






<a name="datapathplugins-PrepareCollectionRequest-CollectionSpec-ProgramsEntry"></a>

### PrepareCollectionRequest.CollectionSpec.ProgramsEntry



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| key | [string](#string) |  |  |
| value | [PrepareCollectionRequest.CollectionSpec.ProgramSpec](#datapathplugins-PrepareCollectionRequest-CollectionSpec-ProgramSpec) |  |  |






<a name="datapathplugins-PrepareCollectionResponse"></a>

### PrepareCollectionResponse



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| hooks | [PrepareCollectionResponse.HookSpec](#datapathplugins-PrepareCollectionResponse-HookSpec) | repeated | list of hooks that should be added to the collection. |
| cookie | [string](#string) |  | cookie is an opaque string that will be passed in the subsequent InstrumentCollectionRequest related to this PrepareCollectionRequest. It may be used by plugins to associate the two requests or carry metadata between them. |






<a name="datapathplugins-PrepareCollectionResponse-HookSpec"></a>

### PrepareCollectionResponse.HookSpec



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| type | [HookType](#datapathplugins-HookType) |  | position of the hook relative to the target program. |
| target | [string](#string) |  | name of the program that should be instrumented. |
| constraints | [PrepareCollectionResponse.HookSpec.OrderingConstraint](#datapathplugins-PrepareCollectionResponse-HookSpec-OrderingConstraint) | repeated | constraints is a list of ordering constraints for this hook. If other plugins want to place a hook at this same hook point, hooks from various plugins will be arranged in an order that respects all ordering constraints. |






<a name="datapathplugins-PrepareCollectionResponse-HookSpec-OrderingConstraint"></a>

### PrepareCollectionResponse.HookSpec.OrderingConstraint
An OrderingConstraint is a constraint about where this hook should
go at this hook point relative to other plugins&#39; hooks.


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| order | [PrepareCollectionResponse.HookSpec.OrderingConstraint.Order](#datapathplugins-PrepareCollectionResponse-HookSpec-OrderingConstraint-Order) |  |  |
| plugin | [string](#string) |  |  |





 


<a name="datapathplugins-HookType"></a>

### HookType


| Name | Number | Description |
| ---- | ------ | ----------- |
| UNKNOWN | 0 |  |
| PRE | 1 | pre hooks run before the main Cilium program. |
| POST | 2 | post hooks run after the main Cilium program. |



<a name="datapathplugins-PrepareCollectionResponse-HookSpec-OrderingConstraint-Order"></a>

### PrepareCollectionResponse.HookSpec.OrderingConstraint.Order


| Name | Number | Description |
| ---- | ------ | ----------- |
| UNKNOWN | 0 |  |
| BEFORE | 1 |  |
| AFTER | 2 |  |


 

 


<a name="datapathplugins-DatapathPlugin"></a>

### DatapathPlugin
A DatapathPlugin interacts with Cilium&#39;s loader to augment or modify BPF
collections as they are prepared for an attachment point.

| Method Name | Request Type | Response Type | Description |
| ----------- | ------------ | ------------- | ------------|
| PrepareCollection | [PrepareCollectionRequest](#datapathplugins-PrepareCollectionRequest) | [PrepareCollectionResponse](#datapathplugins-PrepareCollectionResponse) | PrepareCollection happens before the BPF collection is loaded into the kernel. Cilium passes BPF collection details to the plugin and the plugin tells Cilium how it would like to modify the collection. |
| InstrumentCollection | [InstrumentCollectionRequest](#datapathplugins-InstrumentCollectionRequest) | [InstrumentCollectionResponse](#datapathplugins-InstrumentCollectionResponse) | InstrumentCollection happens after the BPF collection is loaded into the kernel. Cilium passes BPF collection details to the plugin along with details about hook attachment points it created in the prepare phase. The plugin loads its BPF programs and passes them back to Cilium to be attached to these hook points. |

 



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


# Protocol Documentation
<a name="top"></a>

## Table of Contents

- [datapathplugins/datapathplugins.proto](#datapathplugins_datapathplugins-proto)
    - [AttachmentContext](#datapathplugins-AttachmentContext)
    - [AttachmentContext.Host](#datapathplugins-AttachmentContext-Host)
    - [AttachmentContext.InterfaceInfo](#datapathplugins-AttachmentContext-InterfaceInfo)
    - [AttachmentContext.LXC](#datapathplugins-AttachmentContext-LXC)
    - [AttachmentContext.Network](#datapathplugins-AttachmentContext-Network)
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
    - [LocalNodeConfig](#datapathplugins-LocalNodeConfig)
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
| network | [AttachmentContext.Network](#datapathplugins-AttachmentContext-Network) |  |  |
| overlay | [AttachmentContext.Overlay](#datapathplugins-AttachmentContext-Overlay) |  |  |
| socket | [AttachmentContext.Socket](#datapathplugins-AttachmentContext-Socket) |  |  |
| wireguard | [AttachmentContext.Wireguard](#datapathplugins-AttachmentContext-Wireguard) |  |  |
| xdp | [AttachmentContext.XDP](#datapathplugins-AttachmentContext-XDP) |  |  |






<a name="datapathplugins-AttachmentContext-Host"></a>

### AttachmentContext.Host



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| iface | [AttachmentContext.InterfaceInfo](#datapathplugins-AttachmentContext-InterfaceInfo) |  |  |






<a name="datapathplugins-AttachmentContext-InterfaceInfo"></a>

### AttachmentContext.InterfaceInfo



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| name | [string](#string) |  |  |






<a name="datapathplugins-AttachmentContext-LXC"></a>

### AttachmentContext.LXC



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| iface | [AttachmentContext.InterfaceInfo](#datapathplugins-AttachmentContext-InterfaceInfo) |  |  |
| pod_info | [AttachmentContext.PodInfo](#datapathplugins-AttachmentContext-PodInfo) |  |  |






<a name="datapathplugins-AttachmentContext-Network"></a>

### AttachmentContext.Network







<a name="datapathplugins-AttachmentContext-Overlay"></a>

### AttachmentContext.Overlay



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| iface | [AttachmentContext.InterfaceInfo](#datapathplugins-AttachmentContext-InterfaceInfo) |  |  |






<a name="datapathplugins-AttachmentContext-PodInfo"></a>

### AttachmentContext.PodInfo



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| namespace | [string](#string) |  |  |
| pod_name | [string](#string) |  |  |
| container_name | [string](#string) |  |  |






<a name="datapathplugins-AttachmentContext-Socket"></a>

### AttachmentContext.Socket







<a name="datapathplugins-AttachmentContext-Wireguard"></a>

### AttachmentContext.Wireguard



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| iface | [AttachmentContext.InterfaceInfo](#datapathplugins-AttachmentContext-InterfaceInfo) |  |  |






<a name="datapathplugins-AttachmentContext-XDP"></a>

### AttachmentContext.XDP



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| iface | [AttachmentContext.InterfaceInfo](#datapathplugins-AttachmentContext-InterfaceInfo) |  |  |






<a name="datapathplugins-InstrumentCollectionRequest"></a>

### InstrumentCollectionRequest
Phase 2: Cilium has constructed and loaded the collection along with any
dispatcher programs that are meant to replace existing entrypoints in the
collection. Cilium sends a round of requests to any plugins that wanted to
inject hooks.


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| collection | [InstrumentCollectionRequest.Collection](#datapathplugins-InstrumentCollectionRequest-Collection) |  |  |
| local_node_config | [LocalNodeConfig](#datapathplugins-LocalNodeConfig) |  |  |
| attachment_context | [AttachmentContext](#datapathplugins-AttachmentContext) |  |  |
| hooks | [InstrumentCollectionRequest.Hook](#datapathplugins-InstrumentCollectionRequest-Hook) | repeated |  |
| pins | [string](#string) |  |  |
| cookie | [string](#string) |  |  |






<a name="datapathplugins-InstrumentCollectionRequest-Collection"></a>

### InstrumentCollectionRequest.Collection
Program and map IDs in the collection


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| programs | [InstrumentCollectionRequest.Collection.ProgramsEntry](#datapathplugins-InstrumentCollectionRequest-Collection-ProgramsEntry) | repeated |  |
| maps | [InstrumentCollectionRequest.Collection.MapsEntry](#datapathplugins-InstrumentCollectionRequest-Collection-MapsEntry) | repeated |  |






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
Would contain information about programs and maps in this collection
such as names, IDs, etc. This could be consumed by plugin programs
themselves, e.g., for sharing map state.


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
| type | [HookType](#datapathplugins-HookType) |  |  |
| target | [string](#string) |  |  |
| attach_target | [InstrumentCollectionRequest.Hook.AttachTarget](#datapathplugins-InstrumentCollectionRequest-Hook-AttachTarget) |  | Contains target metadata necessary for freplace program load. |
| pin_path | [string](#string) |  | The plugin must pin the program to this pin path before responding to Cilium. |






<a name="datapathplugins-InstrumentCollectionRequest-Hook-AttachTarget"></a>

### InstrumentCollectionRequest.Hook.AttachTarget



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| program_id | [uint32](#uint32) |  |  |
| subprog_name | [string](#string) |  |  |






<a name="datapathplugins-InstrumentCollectionResponse"></a>

### InstrumentCollectionResponse







<a name="datapathplugins-LocalNodeConfig"></a>

### LocalNodeConfig
LocalNodeConfig is Cilium&#39;s current config for this node. It may be used
by plugins to decide which hooks to load, how to configure them, etc.

TBD






<a name="datapathplugins-PrepareCollectionRequest"></a>

### PrepareCollectionRequest
Phase 1: As Cilium loads and prepares a collection for a particular
attachment point, it sends a PrepareHooksRequest to each plugin with context
about the attachment point, collection, and local node config. The plugin
decides which hooks it would like to insert, where it would like to insert
them, and informs Cilium in the PrepareHooksResponse.


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| collection | [PrepareCollectionRequest.CollectionSpec](#datapathplugins-PrepareCollectionRequest-CollectionSpec) |  |  |
| local_node_config | [LocalNodeConfig](#datapathplugins-LocalNodeConfig) |  |  |
| attachment_context | [AttachmentContext](#datapathplugins-AttachmentContext) |  |  |






<a name="datapathplugins-PrepareCollectionRequest-CollectionSpec"></a>

### PrepareCollectionRequest.CollectionSpec



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| programs | [PrepareCollectionRequest.CollectionSpec.ProgramsEntry](#datapathplugins-PrepareCollectionRequest-CollectionSpec-ProgramsEntry) | repeated |  |
| maps | [PrepareCollectionRequest.CollectionSpec.MapsEntry](#datapathplugins-PrepareCollectionRequest-CollectionSpec-MapsEntry) | repeated |  |






<a name="datapathplugins-PrepareCollectionRequest-CollectionSpec-MapSpec"></a>

### PrepareCollectionRequest.CollectionSpec.MapSpec







<a name="datapathplugins-PrepareCollectionRequest-CollectionSpec-MapsEntry"></a>

### PrepareCollectionRequest.CollectionSpec.MapsEntry



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| key | [string](#string) |  |  |
| value | [PrepareCollectionRequest.CollectionSpec.MapSpec](#datapathplugins-PrepareCollectionRequest-CollectionSpec-MapSpec) |  |  |






<a name="datapathplugins-PrepareCollectionRequest-CollectionSpec-ProgramSpec"></a>

### PrepareCollectionRequest.CollectionSpec.ProgramSpec







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
| hooks | [PrepareCollectionResponse.HookSpec](#datapathplugins-PrepareCollectionResponse-HookSpec) | repeated |  |
| cookie | [string](#string) |  | repeated MapReplacement map_replacements = 2; ... May be used by a plugin to associate a LoadHooksRequest with its preceding PrepareHooksRequest or carry other metadata between phases that may be helpful. |






<a name="datapathplugins-PrepareCollectionResponse-HookSpec"></a>

### PrepareCollectionResponse.HookSpec



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| type | [HookType](#datapathplugins-HookType) |  | PRE/POST (for now) |
| target | [string](#string) |  | Which program are we instrumenting? |
| constraints | [PrepareCollectionResponse.HookSpec.OrderingConstraint](#datapathplugins-PrepareCollectionResponse-HookSpec-OrderingConstraint) | repeated |  |






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
| PRE | 0 |  |
| POST | 1 |  |



<a name="datapathplugins-PrepareCollectionResponse-HookSpec-OrderingConstraint-Order"></a>

### PrepareCollectionResponse.HookSpec.OrderingConstraint.Order


| Name | Number | Description |
| ---- | ------ | ----------- |
| BEFORE | 0 |  |
| AFTER | 1 |  |


 

 


<a name="datapathplugins-DatapathPlugin"></a>

### DatapathPlugin


| Method Name | Request Type | Response Type | Description |
| ----------- | ------------ | ------------- | ------------|
| PrepareCollection | [PrepareCollectionRequest](#datapathplugins-PrepareCollectionRequest) | [PrepareCollectionResponse](#datapathplugins-PrepareCollectionResponse) |  |
| InstrumentCollection | [InstrumentCollectionRequest](#datapathplugins-InstrumentCollectionRequest) | [InstrumentCollectionResponse](#datapathplugins-InstrumentCollectionResponse) |  |

 



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


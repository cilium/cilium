# Protocol Documentation
<a name="top"></a>

## Table of Contents

- [datapathplugins/datapathplugins.proto](#datapathplugins_datapathplugins-proto)
    - [AttachmentPoint](#peer-AttachmentPoint)
    - [EndpointConfig](#peer-EndpointConfig)
    - [LoadSKBProgramRequest](#peer-LoadSKBProgramRequest)
    - [LoadSKBProgramResponse](#peer-LoadSKBProgramResponse)
    - [LocalNodeConfig](#peer-LocalNodeConfig)
    - [Maps](#peer-Maps)
  
    - [Anchor](#peer-Anchor)
    - [DeviceType](#peer-DeviceType)
    - [Direction](#peer-Direction)
  
    - [DatapathPlugin](#peer-DatapathPlugin)
  
- [Scalar Value Types](#scalar-value-types)



<a name="datapathplugins_datapathplugins-proto"></a>
<p align="right"><a href="#top">Top</a></p>

## datapathplugins/datapathplugins.proto



<a name="peer-AttachmentPoint"></a>

### AttachmentPoint
AttachmentPoint is a unique identifier for a program.


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| direction | [Direction](#peer-Direction) |  | Ingress or egress. |
| anchor | [Anchor](#peer-Anchor) |  | Before or after the main Cilium program. |
| device_name | [string](#string) |  | Name of the interface. |






<a name="peer-EndpointConfig"></a>

### EndpointConfig



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| id | [uint64](#uint64) |  |  |
| k8s_namespace | [string](#string) |  |  |
| k8s_pod_name | [string](#string) |  |  |
| container_name | [string](#string) |  |  |






<a name="peer-LoadSKBProgramRequest"></a>

### LoadSKBProgramRequest



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| attachment_point | [AttachmentPoint](#peer-AttachmentPoint) |  |  |
| device_type | [DeviceType](#peer-DeviceType) |  |  |
| endpoint_config | [EndpointConfig](#peer-EndpointConfig) |  |  |
| local_node_config | [LocalNodeConfig](#peer-LocalNodeConfig) |  |  |
| maps | [Maps](#peer-Maps) |  |  |






<a name="peer-LoadSKBProgramResponse"></a>

### LoadSKBProgramResponse



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| program_pin_path | [string](#string) |  |  |






<a name="peer-LocalNodeConfig"></a>

### LocalNodeConfig







<a name="peer-Maps"></a>

### Maps
Maps contains a list of map IDs pointing to Cilium-managed maps that may
be consumed by a plugin&#39;s programs as well.


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| cilium_return_map_id | [uint32](#uint32) |  | For AFTER programs, this contains the main Cilium program&#39;s return code. |





 


<a name="peer-Anchor"></a>

### Anchor


| Name | Number | Description |
| ---- | ------ | ----------- |
| UNKNOWN_ANCHOR | 0 |  |
| BEFORE | 1 |  |
| AFTER | 2 |  |



<a name="peer-DeviceType"></a>

### DeviceType


| Name | Number | Description |
| ---- | ------ | ----------- |
| UNKNOWN_DEVICE_TYPE | 0 |  |
| LXC | 1 |  |
| NETDEV | 2 |  |
| CILIUM_HOST | 3 |  |
| CILIUM_NET | 4 |  |
| CILIUM_OVERLAY | 5 |  |
| CILIUM_WIREGUARD | 6 |  |



<a name="peer-Direction"></a>

### Direction


| Name | Number | Description |
| ---- | ------ | ----------- |
| UNKNOWN_DIRECTION | 0 |  |
| INGRESS | 1 |  |
| EGRESS | 2 |  |


 

 


<a name="peer-DatapathPlugin"></a>

### DatapathPlugin


| Method Name | Request Type | Response Type | Description |
| ----------- | ------------ | ------------- | ------------|
| LoadSKBProgram | [LoadSKBProgramRequest](#peer-LoadSKBProgramRequest) | [LoadSKBProgramResponse](#peer-LoadSKBProgramResponse) |  |

 



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


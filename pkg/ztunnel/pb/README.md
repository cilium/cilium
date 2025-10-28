# Protocol Documentation
<a name="top"></a>

## Table of Contents

- [zds.proto](#zds-proto)
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



<a name="zds-proto"></a>
<p align="right"><a href="#top">Top</a></p>

## zds.proto



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


# Protocol Documentation
<a name="top"></a>

## Table of Contents

- [peer/peer.proto](#peer_peer-proto)
    - [ChangeNotification](#peer-ChangeNotification)
    - [NotifyRequest](#peer-NotifyRequest)
    - [TLS](#peer-TLS)
  
    - [ChangeNotificationType](#peer-ChangeNotificationType)
  
    - [Peer](#peer-Peer)
  
- [Scalar Value Types](#scalar-value-types)



<a name="peer_peer-proto"></a>
<p align="right"><a href="#top">Top</a></p>

## peer/peer.proto



<a name="peer-ChangeNotification"></a>

### ChangeNotification
ChangeNotification indicates a change regarding a hubble peer.


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| name | [string](#string) |  | Name is the name of the peer, typically the hostname. The name includes the cluster name if a value other than default has been specified. This value can be used to uniquely identify the host. When the cluster name is not the default, the cluster name is prepended to the peer name and a forward slash is added.

Examples: - runtime1 - testcluster/runtime1 |
| address | [string](#string) |  | Address is the address of the peer&#39;s gRPC service. |
| type | [ChangeNotificationType](#peer-ChangeNotificationType) |  | ChangeNotificationType indicates the type of change, ie whether the peer was added, deleted or updated. |
| tls | [TLS](#peer-TLS) |  | TLS provides information to connect to the Address with TLS enabled. If not set, TLS shall be assumed to be disabled. |






<a name="peer-NotifyRequest"></a>

### NotifyRequest







<a name="peer-TLS"></a>

### TLS
TLS provides information to establish a TLS connection to the peer.


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| server_name | [string](#string) |  | ServerName is used to verify the hostname on the returned certificate. |





 


<a name="peer-ChangeNotificationType"></a>

### ChangeNotificationType
ChangeNotificationType defines the peer change notification type.

| Name | Number | Description |
| ---- | ------ | ----------- |
| UNKNOWN | 0 |  |
| PEER_ADDED | 1 |  |
| PEER_DELETED | 2 |  |
| PEER_UPDATED | 3 |  |


 

 


<a name="peer-Peer"></a>

### Peer
Peer lists  hubble peers and notifies of changes.

| Method Name | Request Type | Response Type | Description |
| ----------- | ------------ | ------------- | ------------|
| Notify | [NotifyRequest](#peer-NotifyRequest) | [ChangeNotification](#peer-ChangeNotification) stream | Notify sends information about hubble peers in the cluster. When Notify is called, it sends information about all the peers that are already part of the cluster (with the type as PEER_ADDED). It subsequently notifies of any change. |

 



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


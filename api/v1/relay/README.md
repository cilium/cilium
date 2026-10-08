# Protocol Documentation
<a name="top"></a>

## Table of Contents

- [relay/relay.proto](#relay_relay-proto)
    - [NodeStatusEvent](#relay-NodeStatusEvent)
  
    - [NodeState](#relay-NodeState)
  
- [Scalar Value Types](#scalar-value-types)



<a name="relay_relay-proto"></a>
<p align="right"><a href="#top">Top</a></p>

## relay/relay.proto



<a name="relay-NodeStatusEvent"></a>

### NodeStatusEvent
NodeStatusEvent is a message sent by hubble-relay to inform clients about
the state of a particular node.


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| state_change | [NodeState](#relay-NodeState) |  | state_change contains the new node state |
| node_names | [string](#string) | repeated | node_names is the list of nodes for which the above state changes applies |
| message | [string](#string) |  | message is an optional message attached to the state change (e.g. an error message). The message applies to all nodes in node_names. |





 


<a name="relay-NodeState"></a>

### NodeState


| Name | Number | Description |
| ---- | ------ | ----------- |
| UNKNOWN_NODE_STATE | 0 | UNKNOWN_NODE_STATE indicates that the state of this node is unknown. |
| NODE_CONNECTED | 1 | NODE_CONNECTED indicates that we have established a connection to this node. The client can expect to observe flows from this node. |
| NODE_UNAVAILABLE | 2 | NODE_UNAVAILABLE indicates that the connection to this node is currently unavailable. The client can expect to not see any flows from this node until either the connection is re-established or the node is gone. |
| NODE_GONE | 3 | NODE_GONE indicates that a node has been removed from the cluster. No reconnection attempts will be made. |
| NODE_ERROR | 4 | NODE_ERROR indicates that a node has reported an error while processing the request. No reconnection attempts will be made. |


 

 

 



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


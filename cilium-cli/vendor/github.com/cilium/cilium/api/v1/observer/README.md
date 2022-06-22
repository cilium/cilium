# Protocol Documentation
<a name="top"></a>

## Table of Contents

- [observer/observer.proto](#observer_observer-proto)
    - [ExportEvent](#observer-ExportEvent)
    - [GetAgentEventsRequest](#observer-GetAgentEventsRequest)
    - [GetAgentEventsResponse](#observer-GetAgentEventsResponse)
    - [GetDebugEventsRequest](#observer-GetDebugEventsRequest)
    - [GetDebugEventsResponse](#observer-GetDebugEventsResponse)
    - [GetFlowsRequest](#observer-GetFlowsRequest)
    - [GetFlowsResponse](#observer-GetFlowsResponse)
    - [GetNodesRequest](#observer-GetNodesRequest)
    - [GetNodesResponse](#observer-GetNodesResponse)
    - [Node](#observer-Node)
    - [ServerStatusRequest](#observer-ServerStatusRequest)
    - [ServerStatusResponse](#observer-ServerStatusResponse)
    - [TLS](#observer-TLS)
  
    - [Observer](#observer-Observer)
  
- [Scalar Value Types](#scalar-value-types)



<a name="observer_observer-proto"></a>
<p align="right"><a href="#top">Top</a></p>

## observer/observer.proto



<a name="observer-ExportEvent"></a>

### ExportEvent
ExportEvent contains an event to be exported. Not to be used outside of the
exporter feature.


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| flow | [flow.Flow](#flow-Flow) |  |  |
| node_status | [relay.NodeStatusEvent](#relay-NodeStatusEvent) |  | node_status informs clients about the state of the nodes participating in this particular GetFlows request. |
| lost_events | [flow.LostEvent](#flow-LostEvent) |  | lost_events informs clients about events which got dropped due to a Hubble component being unavailable |
| agent_event | [flow.AgentEvent](#flow-AgentEvent) |  | agent_event informs clients about an event received from the Cilium agent. |
| debug_event | [flow.DebugEvent](#flow-DebugEvent) |  | debug_event contains Cilium datapath debug events |
| node_name | [string](#string) |  | Name of the node where this event was observed. |
| time | [google.protobuf.Timestamp](#google-protobuf-Timestamp) |  | Timestamp at which this event was observed. |






<a name="observer-GetAgentEventsRequest"></a>

### GetAgentEventsRequest



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| number | [uint64](#uint64) |  | Number of flows that should be returned. Incompatible with `since/until`. Defaults to the most recent (last) `number` events, unless `first` is true, then it will return the earliest `number` events. |
| first | [bool](#bool) |  | first specifies if we should look at the first `number` events or the last `number` of events. Incompatible with `follow`. |
| follow | [bool](#bool) |  | follow sets when the server should continue to stream agent events after printing the last N agent events. |
| since | [google.protobuf.Timestamp](#google-protobuf-Timestamp) |  | Since this time for returned agent events. Incompatible with `number`. |
| until | [google.protobuf.Timestamp](#google-protobuf-Timestamp) |  | Until this time for returned agent events. Incompatible with `number`. |






<a name="observer-GetAgentEventsResponse"></a>

### GetAgentEventsResponse
GetAgentEventsResponse contains an event received from the Cilium agent.


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| agent_event | [flow.AgentEvent](#flow-AgentEvent) |  |  |
| node_name | [string](#string) |  | Name of the node where this event was observed. |
| time | [google.protobuf.Timestamp](#google-protobuf-Timestamp) |  | Timestamp at which this event was observed. |






<a name="observer-GetDebugEventsRequest"></a>

### GetDebugEventsRequest



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| number | [uint64](#uint64) |  | Number of events that should be returned. Incompatible with `since/until`. Defaults to the most recent (last) `number` events, unless `first` is true, then it will return the earliest `number` events. |
| first | [bool](#bool) |  | first specifies if we should look at the first `number` events or the last `number` of events. Incompatible with `follow`. |
| follow | [bool](#bool) |  | follow sets when the server should continue to stream debug events after printing the last N debug events. |
| since | [google.protobuf.Timestamp](#google-protobuf-Timestamp) |  | Since this time for returned debug events. Incompatible with `number`. |
| until | [google.protobuf.Timestamp](#google-protobuf-Timestamp) |  | Until this time for returned debug events. Incompatible with `number`. |






<a name="observer-GetDebugEventsResponse"></a>

### GetDebugEventsResponse
GetDebugEventsResponse contains a Cilium datapath debug events.


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| debug_event | [flow.DebugEvent](#flow-DebugEvent) |  |  |
| node_name | [string](#string) |  | Name of the node where this event was observed. |
| time | [google.protobuf.Timestamp](#google-protobuf-Timestamp) |  | Timestamp at which this event was observed. |






<a name="observer-GetFlowsRequest"></a>

### GetFlowsRequest



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| number | [uint64](#uint64) |  | Number of flows that should be returned. Incompatible with `since/until`. Defaults to the most recent (last) `number` flows, unless `first` is true, then it will return the earliest `number` flows. |
| first | [bool](#bool) |  | first specifies if we should look at the first `number` flows or the last `number` of flows. Incompatible with `follow`. |
| follow | [bool](#bool) |  | follow sets when the server should continue to stream flows after printing the last N flows. |
| blacklist | [flow.FlowFilter](#flow-FlowFilter) | repeated | blacklist defines a list of filters which have to match for a flow to be excluded from the result. If multiple blacklist filters are specified, only one of them has to match for a flow to be excluded. |
| whitelist | [flow.FlowFilter](#flow-FlowFilter) | repeated | whitelist defines a list of filters which have to match for a flow to be included in the result. If multiple whitelist filters are specified, only one of them has to match for a flow to be included. The whitelist and blacklist can both be specified. In such cases, the set of the returned flows is the set difference `whitelist - blacklist`. In other words, the result will contain all flows matched by the whitelist that are not also simultaneously matched by the blacklist. |
| since | [google.protobuf.Timestamp](#google-protobuf-Timestamp) |  | Since this time for returned flows. Incompatible with `number`. |
| until | [google.protobuf.Timestamp](#google-protobuf-Timestamp) |  | Until this time for returned flows. Incompatible with `number`. |






<a name="observer-GetFlowsResponse"></a>

### GetFlowsResponse
GetFlowsResponse contains either a flow or a protocol message.


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| flow | [flow.Flow](#flow-Flow) |  |  |
| node_status | [relay.NodeStatusEvent](#relay-NodeStatusEvent) |  | node_status informs clients about the state of the nodes participating in this particular GetFlows request. |
| lost_events | [flow.LostEvent](#flow-LostEvent) |  | lost_events informs clients about events which got dropped due to a Hubble component being unavailable |
| node_name | [string](#string) |  | Name of the node where this event was observed. |
| time | [google.protobuf.Timestamp](#google-protobuf-Timestamp) |  | Timestamp at which this event was observed. |






<a name="observer-GetNodesRequest"></a>

### GetNodesRequest







<a name="observer-GetNodesResponse"></a>

### GetNodesResponse
GetNodesResponse contains the list of nodes.


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| nodes | [Node](#observer-Node) | repeated | Nodes is an exhaustive list of nodes. |






<a name="observer-Node"></a>

### Node
Node represents a cluster node.


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| name | [string](#string) |  | Name is the name of the node. |
| version | [string](#string) |  | Version is the version of Cilium/Hubble as reported by the node. |
| address | [string](#string) |  | Address is the network address of the API endpoint. |
| state | [relay.NodeState](#relay-NodeState) |  | State represents the known state of the node. |
| tls | [TLS](#observer-TLS) |  | TLS reports TLS related information. |
| uptime_ns | [uint64](#uint64) |  | UptimeNS is the uptime of this instance in nanoseconds |
| num_flows | [uint64](#uint64) |  | number of currently captured flows |
| max_flows | [uint64](#uint64) |  | maximum capacity of the ring buffer |
| seen_flows | [uint64](#uint64) |  | total amount of flows observed since the observer was started |






<a name="observer-ServerStatusRequest"></a>

### ServerStatusRequest







<a name="observer-ServerStatusResponse"></a>

### ServerStatusResponse



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| num_flows | [uint64](#uint64) |  | number of currently captured flows In a multi-node context, this is the cumulative count of all captured flows. |
| max_flows | [uint64](#uint64) |  | maximum capacity of the ring buffer In a multi-node context, this is the aggregation of all ring buffers capacities. |
| seen_flows | [uint64](#uint64) |  | total amount of flows observed since the observer was started In a multi-node context, this is the aggregation of all flows that have been seen. |
| uptime_ns | [uint64](#uint64) |  | uptime of this observer instance in nanoseconds In a multi-node context, this field corresponds to the uptime of the longest living instance. |
| num_connected_nodes | [google.protobuf.UInt32Value](#google-protobuf-UInt32Value) |  | number of nodes for which a connection is established |
| num_unavailable_nodes | [google.protobuf.UInt32Value](#google-protobuf-UInt32Value) |  | number of nodes for which a connection cannot be established |
| unavailable_nodes | [string](#string) | repeated | list of nodes that are unavailable This list may not be exhaustive. |
| version | [string](#string) |  | Version is the version of Cilium/Hubble. |






<a name="observer-TLS"></a>

### TLS
TLS represents TLS information.


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| enabled | [bool](#bool) |  | Enabled reports whether TLS is enabled or not. |
| server_name | [string](#string) |  | ServerName is the TLS server name that can be used as part of the TLS cert validation process. |





 

 

 


<a name="observer-Observer"></a>

### Observer
Observer returns a stream of Flows depending on which filter the user want
to observe.

| Method Name | Request Type | Response Type | Description |
| ----------- | ------------ | ------------- | ------------|
| GetFlows | [GetFlowsRequest](#observer-GetFlowsRequest) | [GetFlowsResponse](#observer-GetFlowsResponse) stream | GetFlows returning structured data, meant to eventually obsolete GetLastNFlows. |
| GetAgentEvents | [GetAgentEventsRequest](#observer-GetAgentEventsRequest) | [GetAgentEventsResponse](#observer-GetAgentEventsResponse) stream | GetAgentEvents returns Cilium agent events. |
| GetDebugEvents | [GetDebugEventsRequest](#observer-GetDebugEventsRequest) | [GetDebugEventsResponse](#observer-GetDebugEventsResponse) stream | GetDebugEvents returns Cilium datapath debug events. |
| GetNodes | [GetNodesRequest](#observer-GetNodesRequest) | [GetNodesResponse](#observer-GetNodesResponse) | GetNodes returns information about nodes in a cluster. |
| ServerStatus | [ServerStatusRequest](#observer-ServerStatusRequest) | [ServerStatusResponse](#observer-ServerStatusResponse) | ServerStatus returns some details about the running hubble server. |

 



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


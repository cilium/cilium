# Protocol Documentation
<a name="top"></a>

## Table of Contents

- [recorder/recorder.proto](#recorder_recorder-proto)
    - [FileSinkConfiguration](#recorder-FileSinkConfiguration)
    - [FileSinkResult](#recorder-FileSinkResult)
    - [Filter](#recorder-Filter)
    - [RecordRequest](#recorder-RecordRequest)
    - [RecordResponse](#recorder-RecordResponse)
    - [RecordingRunningResponse](#recorder-RecordingRunningResponse)
    - [RecordingStatistics](#recorder-RecordingStatistics)
    - [RecordingStoppedResponse](#recorder-RecordingStoppedResponse)
    - [StartRecording](#recorder-StartRecording)
    - [StopCondition](#recorder-StopCondition)
    - [StopRecording](#recorder-StopRecording)
  
    - [Protocol](#recorder-Protocol)
  
    - [Recorder](#recorder-Recorder)
  
- [Scalar Value Types](#scalar-value-types)



<a name="recorder_recorder-proto"></a>
<p align="right"><a href="#top">Top</a></p>

## recorder/recorder.proto



<a name="recorder-FileSinkConfiguration"></a>

### FileSinkConfiguration
FileSinkConfiguration configures the file output. Possible future additions
might be the selection of the output volume. The initial implementation will
only support a single volume which is configured as a cilium-agent CLI flag.


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| file_prefix | [string](#string) |  | file_prefix is an optional prefix for the file name. Defaults to `hubble` if empty. Must match the following regex if not empty: ^[a-z][a-z0-9]{0,19}$ The generated filename will be of format &lt;file_prefix&gt;_&lt;unixtime&gt;_&lt;unique_random&gt;_&lt;node_name&gt;.pcap |






<a name="recorder-FileSinkResult"></a>

### FileSinkResult



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| file_path | [string](#string) |  | file_path is the absolute path to the captured pcap file |






<a name="recorder-Filter"></a>

### Filter



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| source_cidr | [string](#string) |  | source_cidr. Must not be empty. Set to 0.0.0.0/0 to match any IPv4 source address (::/0 for IPv6). |
| source_port | [uint32](#uint32) |  | source_port. Matches any source port if empty. |
| destination_cidr | [string](#string) |  | destination_cidr. Must not be empty. Set to 0.0.0.0/0 to match any IPv4 destination address (::/0 for IPv6). |
| destination_port | [uint32](#uint32) |  | destination_port. Matches any destination port if empty. |
| protocol | [Protocol](#recorder-Protocol) |  | protocol. Matches any protocol if empty. |






<a name="recorder-RecordRequest"></a>

### RecordRequest



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| start | [StartRecording](#recorder-StartRecording) |  | start starts a new recording with the given parameters. |
| stop | [StopRecording](#recorder-StopRecording) |  | stop stops the running recording. |






<a name="recorder-RecordResponse"></a>

### RecordResponse



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| node_name | [string](#string) |  | name of the node where this recording is happening |
| time | [google.protobuf.Timestamp](#google-protobuf-Timestamp) |  | time at which this event was observed on the above node |
| running | [RecordingRunningResponse](#recorder-RecordingRunningResponse) |  | running means that the recording is capturing packets. This is emitted in regular intervals |
| stopped | [RecordingStoppedResponse](#recorder-RecordingStoppedResponse) |  | stopped means the recording has stopped |






<a name="recorder-RecordingRunningResponse"></a>

### RecordingRunningResponse



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| stats | [RecordingStatistics](#recorder-RecordingStatistics) |  | stats for the running recording |






<a name="recorder-RecordingStatistics"></a>

### RecordingStatistics



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| bytes_captured | [uint64](#uint64) |  | bytes_captured is the total amount of bytes captured in the recording |
| packets_captured | [uint64](#uint64) |  | packets_captured is the total amount of packets captured the recording |
| packets_lost | [uint64](#uint64) |  | packets_lost is the total amount of packets matching the filter during the recording, but never written to the sink because it was overloaded. |
| bytes_lost | [uint64](#uint64) |  | bytes_lost is the total amount of bytes matching the filter during the recording, but never written to the sink because it was overloaded. |






<a name="recorder-RecordingStoppedResponse"></a>

### RecordingStoppedResponse



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| stats | [RecordingStatistics](#recorder-RecordingStatistics) |  | stats for the recording |
| filesink | [FileSinkResult](#recorder-FileSinkResult) |  | filesink contains the path to the captured file |






<a name="recorder-StartRecording"></a>

### StartRecording



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| filesink | [FileSinkConfiguration](#recorder-FileSinkConfiguration) |  | filesink configures the outfile of this recording Future alternative sink configurations may be added as a backwards-compatible change by moving this field into a oneof. |
| include | [Filter](#recorder-Filter) | repeated | include list for this recording. Packets matching any of the provided filters will be recorded. |
| max_capture_length | [uint32](#uint32) |  | max_capture_length specifies the maximum packet length. Full packet length will be captured if absent/zero. |
| stop_condition | [StopCondition](#recorder-StopCondition) |  | stop_condition defines conditions which will cause the recording to stop early after any of the stop conditions has been hit |






<a name="recorder-StopCondition"></a>

### StopCondition
StopCondition defines one or more conditions which cause the recording to
stop after they have been hit. Stop conditions are ignored if they are
absent or zero-valued. If multiple conditions are defined, the recording
stops after the first one is hit.


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| bytes_captured_count | [uint64](#uint64) |  | bytes_captured_count stops the recording after at least this many bytes have been captured. Note: The resulting file might be slightly larger due to added pcap headers. |
| packets_captured_count | [uint64](#uint64) |  | packets_captured_count stops the recording after at least this many packets have been captured. |
| time_elapsed | [google.protobuf.Duration](#google-protobuf-Duration) |  | time_elapsed stops the recording after this duration has elapsed. |






<a name="recorder-StopRecording"></a>

### StopRecording






 


<a name="recorder-Protocol"></a>

### Protocol
Protocol is a one of the supported protocols for packet capture

| Name | Number | Description |
| ---- | ------ | ----------- |
| PROTOCOL_ANY | 0 |  |
| PROTOCOL_TCP | 6 |  |
| PROTOCOL_UDP | 17 |  |


 

 


<a name="recorder-Recorder"></a>

### Recorder
Recorder implements the Hubble module for capturing network packets

| Method Name | Request Type | Response Type | Description |
| ----------- | ------------ | ------------- | ------------|
| Record | [RecordRequest](#recorder-RecordRequest) stream | [RecordResponse](#recorder-RecordResponse) stream | Record can start and stop a single recording. The recording is automatically stopped if the client aborts this rpc call. |

 



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


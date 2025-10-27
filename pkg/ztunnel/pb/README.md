# Protocol Documentation
<a name="top"></a>

## Table of Contents

- [ca.proto](#ca-proto)
    - [IstioCertificateRequest](#istio-v1-auth-IstioCertificateRequest)
    - [IstioCertificateResponse](#istio-v1-auth-IstioCertificateResponse)
  
    - [IstioCertificateService](#istio-v1-auth-IstioCertificateService)
  
- [Scalar Value Types](#scalar-value-types)



<a name="ca-proto"></a>
<p align="right"><a href="#top">Top</a></p>

## ca.proto



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


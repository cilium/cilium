// Package v4 implements signing for AWS V4 signer
//
// Provides request signing for request that need to be signed with
// AWS V4 Signatures.
//
// Standalone Signer
//
// Generally using the signer outside of the SDK should not require any additional
// logic when using Go v1.5 or higher. The signer does this by taking advantage
// of the URL.EscapedPath method. If your request URI requires additional escaping
// you many need to use the URL.Opaque to define what the raw URI should be sent
// to the service as.
//
// The signer will first check the URL.Opaque field, and use its value if set.
// The signer does require the URL.Opaque field to be set in the form of:
//
//     "//<hostname>/<path>"
//
//     // e.g.
//     "//example.com/some/path"
//
// The leading "//" and hostname are required or the URL.Opaque escaping will
// not work correctly.
//
// If URL.Opaque is not set the signer will fallback to the URL.EscapedPath()
// method and using the returned value. If you're using Go v1.4 you must set
// URL.Opaque if the URI path needs escaping. If URL.Opaque is not set with
// Go v1.5 the signer will fallback to URL.Path.
//
// AWS v4 signature validation requires that the canonical string's URI path
// element must be the URI escaped form of the HTTP request's path.
// http://docs.aws.amazon.com/general/latest/gr/sigv4-create-canonical-request.html
//
// The Go HTTP client will perform escaping automatically on the request. Some
// of these escaping may cause signature validation errors because the HTTP
// request differs from the URI path or query that the signature was generated.
// https://golang.org/pkg/net/url/#URL.EscapedPath
//
// Because of this, it is recommended that when using the signer outside of the
// SDK that explicitly escaping the request prior to being signed is preferable,
// and will help prevent signature validation errors. This can be done by setting
// the URL.Opaque or URL.RawPath. The SDK will use URL.Opaque first and then
// call URL.EscapedPath() if Opaque is not set.
//
// If signing a request intended for HTTP2 server, and you're using Go 1.6.2
// through 1.7.4 you should use the URL.RawPath as the pre-escaped form of the
// request URL. https://github.com/golang/go/issues/16847 points to a bug in
// Go pre 1.8 that fails to make HTTP2 requests using absolute URL in the HTTP
// message. URL.Opaque generally will force Go to make requests with absolute URL.
// URL.RawPath does not do this, but RawPath must be a valid escaping of Path
// or url.EscapedPath will ignore the RawPath escaping.
//
// Test `TestStandaloneSign` provides a complete example of using the signer
// outside of the SDK and pre-escaping the URI path.
package v4

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"hash"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	v4Internal "github.com/aws/aws-sdk-go-v2/aws/signer/internal/v4"
	"github.com/aws/aws-sdk-go-v2/internal/sdk"
	"github.com/aws/aws-sdk-go-v2/private/protocol/rest"
)

const (
	signingAlgorithm = "AWS4-HMAC-SHA256"
)

// HTTPSigner is an interface to a SigV4 signer that can sign HTTP requests
type HTTPSigner interface {
	SignHTTP(ctx context.Context, r *http.Request, payloadHash string, service string, region string, signingTime time.Time) error
}

// Signer applies AWS v4 signing to given request. Use this to sign requests
// that need to be signed with AWS V4 Signatures.
type Signer struct {
	// The authentication credentials the request will be signed against.
	// This value must be set to sign requests.
	Credentials aws.CredentialsProvider

	// Sets the log level the signer should use when reporting information to
	// the logger. If the logger is nil nothing will be logged. See
	// aws.LogLevel for more information on available logging levels
	//
	// By default nothing will be logged.
	Debug aws.LogLevel

	// The logger loging information will be written to. If there the logger
	// is nil, nothing will be logged.
	Logger aws.Logger

	// Disables the Signer's moving HTTP header key/value pairs from the HTTP
	// request header to the request's query string. This is most commonly used
	// with pre-signed requests preventing headers from being added to the
	// request's query string.
	DisableHeaderHoisting bool

	// Disables the automatic escaping of the URI path of the request for the
	// siganture's canonical string's path. For services that do not need additional
	// escaping then use this to disable the signer escaping the path.
	//
	// S3 is an example of a service that does not need additional escaping.
	//
	// http://docs.aws.amazon.com/general/latest/gr/sigv4-create-canonical-request.html
	DisableURIPathEscaping bool

	// Disales the automatical setting of the HTTP request's Body field with the
	// io.ReadSeeker passed in to the signer. This is useful if you're using a
	// custom wrapper around the body for the io.ReadSeeker and want to preserve
	// the Body value on the Request.Body.
	//
	// This does run the risk of signing a request with a body that will not be
	// sent in the request. Need to ensure that the underlying data of the Body
	// values are the same.
	//
	// deprecated: Option not used when calling SignHTTP or PresignHTTP
	DisableRequestBodyOverwrite bool

	// UnsignedPayload will prevent signing of the payload. This will only
	// work for services that have support for this.
	//
	// deprecated: Option not used when calling SignHTTP or PresignHTTP
	UnsignedPayload bool
}

// NewSigner returns a Signer pointer configured with the credentials and optional
// option values provided. If not options are provided the Signer will use its
// default configuration.
func NewSigner(credsProvider aws.CredentialsProvider, options ...func(*Signer)) *Signer {
	v4 := &Signer{
		Credentials: credsProvider,
	}

	for _, option := range options {
		option(v4)
	}

	return v4
}

type httpSigner struct {
	Request     *http.Request
	ServiceName string
	Region      string
	Time        time.Time
	ExpireTime  time.Duration
	Credentials aws.Credentials
	IsPreSign   bool

	// PayloadHash is the hex encoded SHA-256 hash of the request payload
	// If len(PayloadHash) == 0 the signer will attempt to send the request
	// as an unsigned payload. Note: Unsigned payloads only work for a subset of services.
	PayloadHash string

	DisableHeaderHoisting  bool
	DisableURIPathEscaping bool
}

func (s *httpSigner) Build() (signedRequest, error) {
	req := s.Request.Clone(s.Request.Context())

	query := req.URL.Query()
	headers := req.Header

	s.setRequiredSigningFields(headers, query)

	// Sort Each Query Key's Values
	for key := range query {
		sort.Strings(query[key])
	}

	aws.SanitizeHostForHeader(req)

	credentialScope := s.buildCredentialScope()
	credentialStr := s.Credentials.AccessKeyID + "/" + credentialScope
	if s.IsPreSign {
		query.Set(v4Internal.AmzCredentialKey, credentialStr)
	}

	unsignedHeaders := headers
	if s.IsPreSign && !s.DisableHeaderHoisting {
		urlValues := url.Values{}
		urlValues, unsignedHeaders = buildQuery(v4Internal.AllowedQueryHoisting, unsignedHeaders)
		for k := range urlValues {
			query[k] = urlValues[k]
		}
	}

	host := req.URL.Host
	if len(req.Host) > 0 {
		host = req.Host
	}

	signedHeaders, signedHeadersStr, canonicalHeaderStr := s.buildCanonicalHeaders(host, v4Internal.IgnoredHeaders, unsignedHeaders)

	if s.IsPreSign {
		query.Set(v4Internal.AmzSignedHeadersKey, signedHeadersStr)
	}

	rawQuery := strings.Replace(query.Encode(), "+", "%20", -1)

	canonicalURI := v4Internal.GetURIPath(req.URL)
	if !s.DisableURIPathEscaping {
		canonicalURI = rest.EscapePath(canonicalURI, false)
	}

	canonicalString := s.buildCanonicalString(
		req.Method,
		canonicalURI,
		rawQuery,
		signedHeadersStr,
		canonicalHeaderStr,
	)

	strToSign := s.buildStringToSign(credentialScope, canonicalString)
	signingSignature := s.buildSignature(strToSign)

	if s.IsPreSign {
		rawQuery += "&X-Amz-Signature=" + signingSignature
	} else {
		parts := []string{
			"Credential=" + credentialStr,
			"SignedHeaders=" + signedHeadersStr,
			"Signature=" + signingSignature,
		}
		headers.Set("Authorization", signingAlgorithm+" "+strings.Join(parts, ", "))
	}

	req.URL.RawQuery = rawQuery

	return signedRequest{
		Request:         req,
		SignedHeaders:   signedHeaders,
		CanonicalString: canonicalString,
		StringToSign:    strToSign,
		PreSigned:       s.IsPreSign,
	}, nil
}

// Sign signs AWS v4 requests with the provided body, service name, region the
// request is made to, and time the request is signed at. The signTime allows
// you to specify that a request is signed for the future, and cannot be
// used until then.
//
// Returns a list of HTTP headers that were included in the signature or an
// error if signing the request failed. Generally for signed requests this value
// is not needed as the full request context will be captured by the http.Request
// value. It is included for reference though.
//
// Sign will set the request's Body to be the `body` parameter passed in. If
// the body is not already an io.ReadCloser, it will be wrapped within one. If
// a `nil` body parameter passed to Sign, the request's Body field will be
// also set to nil. Its important to note that this functionality will not
// change the request's ContentLength of the request.
//
// Sign differs from Presign in that it will sign the request using HTTP
// header values. This type of signing is intended for http.Request values that
// will not be shared, or are shared in a way the header values on the request
// will not be lost.
//
// The requests body is an io.ReadSeeker so the SHA256 of the body can be
// generated. To bypass the signer computing the hash you can set the
// "X-Amz-Content-Sha256" header with a precomputed value. The signer will
// only compute the hash if the request header value is empty.
//
// deprecated: This method will be removed before GA, usage should be migrated to SignHTTP
func (v4 Signer) Sign(ctx context.Context, r *http.Request, body io.ReadSeeker, service, region string, signTime time.Time) (http.Header, error) {
	return v4.signWithBody(ctx, r, body, service, region, 0, signTime)
}

// SignHTTP takes the provided http.Request, payload hash, service, region, and time and signs using SigV4.
// The passed in request will be modified in place.
func (v4 Signer) SignHTTP(ctx context.Context, r *http.Request, payloadHash string, service string, region string, signingTime time.Time) error {
	credentials, err := v4.Credentials.Retrieve(ctx)
	if err != nil {
		return err
	}

	signer := &httpSigner{
		Request:                r,
		PayloadHash:            payloadHash,
		ServiceName:            service,
		Region:                 region,
		Credentials:            credentials,
		Time:                   signingTime.UTC(),
		DisableHeaderHoisting:  v4.DisableHeaderHoisting,
		DisableURIPathEscaping: v4.DisableURIPathEscaping,
	}

	signedRequest, err := signer.Build()
	if err != nil {
		return err
	}

	v4.logHTTPSigningInfo(signedRequest)

	*r = *signedRequest.Request

	return nil
}

// PresignHTTP takes the provided http.Request, payload hash, service, region, and time and presigns using SigV4
// Returns the presigned URL along with the headers that were signed with the request.
func (v4 *Signer) PresignHTTP(ctx context.Context, r *http.Request, payloadHash string, service string, region string, expireTime time.Duration, signingTime time.Time) (signedURI string, signedHeaders http.Header, err error) {
	credentials, err := v4.Credentials.Retrieve(ctx)
	if err != nil {
		return "", nil, err
	}

	signer := &httpSigner{
		Request:                r,
		PayloadHash:            payloadHash,
		ServiceName:            service,
		Region:                 region,
		Credentials:            credentials,
		Time:                   signingTime.UTC(),
		IsPreSign:              true,
		ExpireTime:             expireTime,
		DisableHeaderHoisting:  v4.DisableHeaderHoisting,
		DisableURIPathEscaping: v4.DisableURIPathEscaping,
	}

	signedRequest, err := signer.Build()
	if err != nil {
		return "", nil, err
	}

	v4.logHTTPSigningInfo(signedRequest)

	return signedRequest.Request.URL.String(), signedRequest.SignedHeaders, nil
}

// Presign signs AWS v4 requests with the provided body, service name, region
// the request is made to, and time the request is signed at. The signTime
// allows you to specify that a request is signed for the future, and cannot
// be used until then.
//
// Returns a list of HTTP headers that were included in the signature or an
// error if signing the request failed. For presigned requests these headers
// and their values must be included on the HTTP request when it is made. This
// is helpful to know what header values need to be shared with the party the
// presigned request will be distributed to.
//
// Presign differs from Sign in that it will sign the request using query string
// instead of header values. This allows you to share the Presigned Request's
// URL with third parties, or distribute it throughout your system with minimal
// dependencies.
//
// Presign also takes an exp value which is the duration the
// signed request will be valid after the signing time. This is allows you to
// set when the request will expire.
//
// The requests body is an io.ReadSeeker so the SHA256 of the body can be
// generated. To bypass the signer computing the hash you can set the
// "X-Amz-Content-Sha256" header with a precomputed value. The signer will
// only compute the hash if the request header value is empty.
//
// Presigning a S3 request will not compute the body's SHA256 hash by default.
// This is done due to the general use case for S3 presigned URLs is to share
// PUT/GET capabilities. If you would like to include the body's SHA256 in the
// presigned request's signature you can set the "X-Amz-Content-Sha256"
// HTTP header and that will be included in the request's signature.
//
// deprecated: Usage should be migrated to PresignHTTP
func (v4 Signer) Presign(ctx context.Context, r *http.Request, body io.ReadSeeker, service, region string, exp time.Duration, signTime time.Time) (http.Header, error) {
	return v4.signWithBody(ctx, r, body, service, region, exp, signTime)
}

// deprecated: usage should be migrated to SignHTTP or PresignHTTP
func (v4 Signer) signWithBody(ctx context.Context, r *http.Request, body io.ReadSeeker, service, region string, exp time.Duration, signTime time.Time) (http.Header, error) {
	isPresign := exp != 0

	if isRequestSigned(isPresign, r.URL.Query(), r.Header) {
		signTime = sdk.NowTime()
		handlePresignRemoval(r)
	}

	credentials, err := v4.Credentials.Retrieve(ctx)
	if err != nil {
		return http.Header{}, err
	}

	bodyDigest, err := buildBodyDigest(r, body, service, v4.UnsignedPayload, isPresign)
	if err != nil {
		return http.Header{}, err
	}

	signer := &httpSigner{
		Request:                r,
		ServiceName:            service,
		Region:                 region,
		Time:                   signTime.UTC(),
		ExpireTime:             exp,
		Credentials:            credentials,
		IsPreSign:              isPresign,
		PayloadHash:            bodyDigest,
		DisableHeaderHoisting:  v4.DisableHeaderHoisting,
		DisableURIPathEscaping: v4.DisableURIPathEscaping,
	}

	signedRequest, err := signer.Build()
	if err != nil {
		return http.Header{}, err
	}

	*r = *signedRequest.Request

	// If the request is not presigned the body should be attached to it. This
	// prevents the confusion of wanting to send a signed request without
	// the body the request was signed for attached.
	if !(v4.DisableRequestBodyOverwrite || isPresign) {
		var reader io.ReadCloser
		if body != nil {
			var ok bool
			if reader, ok = body.(io.ReadCloser); !ok {
				reader = ioutil.NopCloser(body)
			}
		}
		r.Body = reader
	}

	return signedRequest.SignedHeaders, nil
}

func handlePresignRemoval(r *http.Request) {
	query := r.URL.Query()

	// The credentials have expired for this request. The current signing
	// is invalid, and needs to be request because the request will fail.
	removePresign(query)

	// Update the request's query string to ensure the values stays in
	// sync in the case retrieving the new credentials fails.
	r.URL.RawQuery = query.Encode()
}

// SignRequestHandler is a named request handler the SDK will use to sign
// service client request with using the V4 signature.
var SignRequestHandler = aws.NamedHandler{
	Name: "v4.SignRequestHandler", Fn: func(r *aws.Request) { SignSDKRequest(r) },
}

// BuildNamedHandler will build a generic handler for signing.
func BuildNamedHandler(name string, opts ...func(*Signer)) aws.NamedHandler {
	return aws.NamedHandler{
		Name: name,
		Fn: func(req *aws.Request) {
			SignSDKRequest(req, opts...)
		},
	}
}

// SignSDKRequest signs an AWS request with the V4 signature. This
// request handler should only be used with the SDK's built in service client's
// API operation requests.
//
// This function should not be used on its on its own, but in conjunction with
// an AWS service client's API operation call. To sign a standalone request
// not created by a service client's API operation method use the "Sign" or
// "Presign" functions of the "Signer" type.
//
// If the credentials of the request's config are set to
// aws.AnonymousCredentials the request will not be signed.
func SignSDKRequest(req *aws.Request, opts ...func(*Signer)) {
	// If the request does not need to be signed ignore the signing of the
	// request if the AnonymousCredentials object is used.
	if req.Config.Credentials == aws.AnonymousCredentials {
		return
	}

	region := req.Endpoint.SigningRegion
	if region == "" {
		region = req.Metadata.SigningRegion
	}

	name := req.Endpoint.SigningName
	if name == "" {
		name = req.Metadata.SigningName
	}

	v4 := NewSigner(req.Config.Credentials, func(v4 *Signer) {
		v4.Debug = req.Config.LogLevel
		v4.Logger = req.Config.Logger
		v4.DisableHeaderHoisting = req.NotHoist
		if name == "s3" {
			// S3 service should not have any escaping applied
			v4.DisableURIPathEscaping = true
		}
		// Prevents setting the HTTPRequest's Body. Since the Body could be
		// wrapped in a custom io.Closer that we do not want to be stompped
		// on top of by the signer.
		v4.DisableRequestBodyOverwrite = true
	})

	for _, opt := range opts {
		opt(v4)
	}

	signingTime := req.Time
	if !req.LastSignedAt.IsZero() {
		signingTime = req.LastSignedAt
	}

	signedHeaders, err := v4.signWithBody(req.Context(), req.HTTPRequest, req.GetBody(),
		name, region, req.ExpireTime, signingTime,
	)
	if err != nil {
		req.Error = err
		req.SignedHeaderVals = nil
		return
	}

	req.SignedHeaderVals = signedHeaders
	req.LastSignedAt = sdk.NowTime()
}

const logSignInfoMsg = `DEBUG: Request Signature:
---[ CANONICAL STRING  ]-----------------------------
%s
---[ STRING TO SIGN ]--------------------------------
%s%s
-----------------------------------------------------`
const logSignedURLMsg = `
---[ SIGNED URL ]------------------------------------
%s`

func (v4 Signer) logHTTPSigningInfo(r signedRequest) {
	if !v4.Debug.Matches(aws.LogDebugWithSigning) || v4.Logger == nil {
		return
	}

	signedURLMsg := ""
	if r.PreSigned {
		signedURLMsg = fmt.Sprintf(logSignedURLMsg, r.Request.URL.String())
	}
	msg := fmt.Sprintf(logSignInfoMsg, r.CanonicalString, r.StringToSign, signedURLMsg)
	v4.Logger.Log(msg)
}

func (s *httpSigner) buildCredentialScope() string {
	return strings.Join([]string{
		s.Time.Format(v4Internal.ShortTimeFormat),
		s.Region,
		s.ServiceName,
		"aws4_request",
	}, "/")
}

func buildQuery(r v4Internal.Rule, header http.Header) (url.Values, http.Header) {
	query := url.Values{}
	unsignedHeaders := http.Header{}
	for k, h := range header {
		if r.IsValid(k) {
			query[k] = h
		} else {
			unsignedHeaders[k] = h
		}
	}

	return query, unsignedHeaders
}

func (s *httpSigner) buildCanonicalHeaders(host string, rule v4Internal.Rule, header http.Header) (signed http.Header, signedHeaders, canonicalHeaders string) {
	signed = make(http.Header)

	var headers []string
	headers = append(headers, "host")
	for k, v := range header {
		canonicalKey := http.CanonicalHeaderKey(k)
		if !rule.IsValid(canonicalKey) {
			continue // ignored header
		}

		lowerCaseKey := strings.ToLower(k)
		if _, ok := signed[lowerCaseKey]; ok {
			// include additional values
			signed[lowerCaseKey] = append(signed[lowerCaseKey], v...)
			continue
		}

		headers = append(headers, lowerCaseKey)
		signed[lowerCaseKey] = v
	}
	sort.Strings(headers)

	signedHeaders = strings.Join(headers, ";")

	headerValues := make([]string, len(headers))
	for i, k := range headers {
		if k == "host" {
			headerValues[i] = "host:" + host
		} else {
			headerValues[i] = k + ":" + strings.Join(signed[k], ",")
		}
	}
	v4Internal.StripExcessSpaces(headerValues)
	canonicalHeaders = strings.Join(headerValues, "\n")

	return signed, signedHeaders, canonicalHeaders
}

func (s *httpSigner) buildCanonicalString(method, uri, query, signedHeaders, canonicalHeaders string) string {
	return strings.Join([]string{
		method,
		uri,
		query,
		canonicalHeaders + "\n",
		signedHeaders,
		s.PayloadHash,
	}, "\n")
}

func (s *httpSigner) buildStringToSign(credentialScope, canonicalRequestString string) string {
	return strings.Join([]string{
		signingAlgorithm,
		s.Time.Format(v4Internal.TimeFormat),
		credentialScope,
		hex.EncodeToString(makeHash(sha256.New(), []byte(canonicalRequestString))),
	}, "\n")
}

func makeHash(hash hash.Hash, b []byte) []byte {
	hash.Reset()
	hash.Write(b)
	return hash.Sum(nil)
}

func (s *httpSigner) buildSignature(strToSign string) string {
	secret := s.Credentials.SecretAccessKey
	date := makeHmacSha256([]byte("AWS4"+secret), []byte(s.Time.Format(v4Internal.ShortTimeFormat)))
	region := makeHmacSha256(date, []byte(s.Region))
	service := makeHmacSha256(region, []byte(s.ServiceName))
	credentials := makeHmacSha256(service, []byte("aws4_request"))
	signature := makeHmacSha256(credentials, []byte(strToSign))
	return hex.EncodeToString(signature)
}

func buildBodyDigest(r *http.Request, body io.ReadSeeker, service string, unsigned, presigned bool) (string, error) {
	hash := r.Header.Get("X-Amz-Content-Sha256")
	if hash == "" {
		includeSHA256Header := unsigned ||
			service == "s3" ||
			service == "glacier"

		s3Presign := presigned && service == "s3"

		if unsigned || s3Presign {
			hash = v4Internal.UnsignedPayload
			includeSHA256Header = !s3Presign
		} else if body == nil {
			hash = v4Internal.EmptyStringSHA256
		} else {
			if !aws.IsReaderSeekable(body) {
				return "", fmt.Errorf("cannot use unseekable request body %T, for signed request with body", body)
			}
			hashBytes, err := makeSha256Reader(body)
			if err != nil {
				return "", err
			}
			hash = hex.EncodeToString(hashBytes)
		}

		if includeSHA256Header {
			r.Header.Set("X-Amz-Content-Sha256", hash)
		}
	}
	return hash, nil
}

func (s *httpSigner) setRequiredSigningFields(headers http.Header, query url.Values) {
	amzDate := s.Time.Format(v4Internal.TimeFormat)

	if s.IsPreSign {
		query.Set(v4Internal.AmzAlgorithmKey, signingAlgorithm)
		if sessionToken := s.Credentials.SessionToken; len(sessionToken) > 0 {
			query.Set("X-Amz-Security-Token", sessionToken)
		}

		duration := int64(s.ExpireTime / time.Second)
		query.Set(v4Internal.AmzDateKey, amzDate)
		query.Set(v4Internal.AmzExpiresKey, strconv.FormatInt(duration, 10))
		return
	}

	headers.Set(v4Internal.AmzDateKey, amzDate)

	if len(s.Credentials.SessionToken) > 0 {
		headers.Set(v4Internal.AmzSecurityTokenKey, s.Credentials.SessionToken)
	}
}

func makeHmacSha256(key []byte, data []byte) []byte {
	hash := hmac.New(sha256.New, key)
	hash.Write(data)
	return hash.Sum(nil)
}

func makeSha256Reader(reader io.ReadSeeker) (hashBytes []byte, err error) {
	hash := sha256.New()
	start, err := reader.Seek(0, io.SeekCurrent)
	if err != nil {
		return nil, err
	}
	defer func() {
		// ensure error is return if unable to seek back to start if payload
		_, err = reader.Seek(start, io.SeekStart)
	}()

	io.Copy(hash, reader)
	return hash.Sum(nil), nil
}

// isRequestSigned returns if the request is currently signed or presigned
func isRequestSigned(isPresign bool, query url.Values, header http.Header) bool {
	if query.Get(v4Internal.AmzSignatureKey) != "" {
		return true
	}

	if header.Get("Authorization") != "" {
		return true
	}

	return false
}

// removePresign removes signing flags for both signed and presigned requests.
func removePresign(query url.Values) {
	query.Del(v4Internal.AmzAlgorithmKey)
	query.Del(v4Internal.AmzSignatureKey)
	query.Del(v4Internal.AmzSecurityTokenKey)
	query.Del(v4Internal.AmzDateKey)
	query.Del(v4Internal.AmzExpiresKey)
	query.Del(v4Internal.AmzCredentialKey)
	query.Del(v4Internal.AmzSignedHeadersKey)
}

type signedRequest struct {
	Request         *http.Request
	SignedHeaders   http.Header
	CanonicalString string
	StringToSign    string
	PreSigned       bool
}

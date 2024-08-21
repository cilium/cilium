package credentials

import (
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/aliyun/alibaba-cloud-sdk-go/sdk/errors"
	"github.com/aliyun/alibaba-cloud-sdk-go/sdk/utils"
)

type assumedRoleUser struct {
}

type credentials struct {
	SecurityToken   *string `json:"SecurityToken"`
	Expiration      *string `json:"Expiration"`
	AccessKeySecret *string `json:"AccessKeySecret"`
	AccessKeyId     *string `json:"AccessKeyId"`
}

type ecsRAMRoleCredentials struct {
	SecurityToken   *string `json:"SecurityToken"`
	Expiration      *string `json:"Expiration"`
	AccessKeySecret *string `json:"AccessKeySecret"`
	AccessKeyId     *string `json:"AccessKeyId"`
	LastUpdated     *string `json:"LastUpdated"`
	Code            *string `json:"Code"`
}

type assumeRoleResponse struct {
	RequestID       *string          `json:"RequestId"`
	AssumedRoleUser *assumedRoleUser `json:"AssumedRoleUser"`
	Credentials     *credentials     `json:"Credentials"`
}

type generateSessionAccessKeyResponse struct {
	RequestID        *string           `json:"RequestId"`
	SessionAccessKey *sessionAccessKey `json:"SessionAccessKey"`
}

type sessionAccessKey struct {
	SessionAccessKeyId     *string `json:"SessionAccessKeyId"`
	SessionAccessKeySecret *string `json:"SessionAccessKeySecret"`
	Expiration             *string `json:"Expiration"`
}

type SessionCredentials struct {
	AccessKeyId     string
	AccessKeySecret string
	SecurityToken   string
	Expiration      string
}

type Credentials struct {
	AccessKeyId     string
	AccessKeySecret string
	SecurityToken   string
	BearerToken     string
}

type do func(req *http.Request) (*http.Response, error)

var hookDo = func(fn do) do {
	return fn
}

type newReuqest func(method, url string, body io.Reader) (*http.Request, error)

var hookNewRequest = func(fn newReuqest) newReuqest {
	return fn
}

type CredentialsProvider interface {
	GetCredentials() (cc *Credentials, err error)
}

type StaticAKCredentialsProvider struct {
	accessKeyId     string
	accessKeySecret string
}

func NewStaticAKCredentialsProvider(accessKeyId, accessKeySecret string) *StaticAKCredentialsProvider {
	return &StaticAKCredentialsProvider{
		accessKeyId:     accessKeyId,
		accessKeySecret: accessKeySecret,
	}
}

func (provider *StaticAKCredentialsProvider) GetCredentials() (cc *Credentials, err error) {
	cc = &Credentials{
		AccessKeyId:     provider.accessKeyId,
		AccessKeySecret: provider.accessKeySecret,
	}
	return
}

type StaticSTSCredentialsProvider struct {
	accessKeyId     string
	accessKeySecret string
	securityToken   string
}

func NewStaticSTSCredentialsProvider(accessKeyId, accessKeySecret, securityToken string) *StaticSTSCredentialsProvider {
	return &StaticSTSCredentialsProvider{
		accessKeyId:     accessKeyId,
		accessKeySecret: accessKeySecret,
		securityToken:   securityToken,
	}
}

func (provider *StaticSTSCredentialsProvider) GetCredentials() (cc *Credentials, err error) {
	cc = &Credentials{
		AccessKeyId:     provider.accessKeyId,
		AccessKeySecret: provider.accessKeySecret,
		SecurityToken:   provider.securityToken,
	}
	return
}

type BearerTokenCredentialsProvider struct {
	bearerToken string
}

func NewBearerTokenCredentialsProvider(bearerToken string) *BearerTokenCredentialsProvider {
	return &BearerTokenCredentialsProvider{
		bearerToken: bearerToken,
	}
}

func (provider *BearerTokenCredentialsProvider) GetCredentials() (cc *Credentials, err error) {
	cc = &Credentials{
		BearerToken: provider.bearerToken,
	}
	return
}

// Deprecated: the RSA key pair credentials is deprecated
type RSAKeyPairCredentialsProvider struct {
	PublicKeyId         string
	PrivateKeyId        string
	durationSeconds     int
	sessionAccessKey    *sessionAccessKey
	lastUpdateTimestamp int64
	expirationTimestamp int64
}

// Deprecated: the RSA key pair credentials is deprecated
func NewRSAKeyPairCredentialsProvider(publicKeyId, privateKeyId string, durationSeconds int) (provider *RSAKeyPairCredentialsProvider, err error) {
	provider = &RSAKeyPairCredentialsProvider{
		PublicKeyId:  publicKeyId,
		PrivateKeyId: privateKeyId,
	}

	if durationSeconds > 0 {
		if durationSeconds >= 900 && durationSeconds <= 3600 {
			provider.durationSeconds = durationSeconds
		} else {
			err = errors.NewClientError(errors.InvalidParamErrorCode, "Key Pair session duration should be in the range of 15min - 1hr", nil)
		}
	} else {
		// set to default value
		provider.durationSeconds = 3600
	}
	return
}

// Deprecated: the RSA key pair credentials is deprecated
func (provider *RSAKeyPairCredentialsProvider) GetCredentials() (cc *Credentials, err error) {
	if provider.sessionAccessKey == nil || provider.needUpdateCredential() {
		sessionAccessKey, err := provider.getCredentials()
		if err != nil {
			return nil, err
		}

		expirationTime, err := time.Parse("2006-01-02T15:04:05Z", *sessionAccessKey.Expiration)
		if err != nil {
			return nil, err
		}

		provider.sessionAccessKey = sessionAccessKey
		provider.lastUpdateTimestamp = time.Now().Unix()
		provider.expirationTimestamp = expirationTime.Unix()
	}

	cc = &Credentials{
		AccessKeyId:     *provider.sessionAccessKey.SessionAccessKeyId,
		AccessKeySecret: *provider.sessionAccessKey.SessionAccessKeySecret,
	}
	return
}

func (provider *RSAKeyPairCredentialsProvider) needUpdateCredential() bool {
	if provider.expirationTimestamp == 0 {
		return true
	}

	return provider.expirationTimestamp-time.Now().Unix() <= 180
}

func (provider *RSAKeyPairCredentialsProvider) getCredentials() (sessionAK *sessionAccessKey, err error) {
	method := "POST"
	host := "sts.ap-northeast-1.aliyuncs.com"

	queries := make(map[string]string)
	queries["Version"] = "2015-04-01"
	queries["Action"] = "GenerateSessionAccessKey"
	queries["Format"] = "JSON"
	queries["Timestamp"] = utils.GetTimeInFormatISO8601()
	queries["SignatureMethod"] = "SHA256withRSA"
	queries["SignatureVersion"] = "1.0"
	queries["SignatureNonce"] = utils.GetNonce()
	queries["PublicKeyId"] = provider.PublicKeyId
	queries["SignatureType"] = "PRIVATEKEY"

	bodyForm := make(map[string]string)
	bodyForm["DurationSeconds"] = strconv.Itoa(provider.durationSeconds)

	// caculate signature
	signParams := make(map[string]string)
	for key, value := range queries {
		signParams[key] = value
	}
	for key, value := range bodyForm {
		signParams[key] = value
	}

	stringToSign := utils.GetUrlFormedMap(signParams)
	stringToSign = strings.Replace(stringToSign, "+", "%20", -1)
	stringToSign = strings.Replace(stringToSign, "*", "%2A", -1)
	stringToSign = strings.Replace(stringToSign, "%7E", "~", -1)
	stringToSign = url.QueryEscape(stringToSign)
	stringToSign = method + "&%2F&" + stringToSign

	queries["Signature"] = utils.Sha256WithRsa(stringToSign, provider.PrivateKeyId)

	querystring := utils.GetUrlFormedMap(queries)
	// do request
	httpUrl := fmt.Sprintf("https://%s/?%s", host, querystring)

	body := utils.GetUrlFormedMap(bodyForm)

	httpRequest, err := hookNewRequest(http.NewRequest)(method, httpUrl, strings.NewReader(body))
	if err != nil {
		return
	}

	// set headers
	httpRequest.Header["Accept-Encoding"] = []string{"identity"}
	httpRequest.Header["Content-Type"] = []string{"application/x-www-form-urlencoded"}
	httpClient := &http.Client{}

	httpResponse, err := hookDo(httpClient.Do)(httpRequest)
	if err != nil {
		return
	}

	defer httpResponse.Body.Close()

	responseBody, err := ioutil.ReadAll(httpResponse.Body)
	if err != nil {
		return
	}

	if httpResponse.StatusCode != http.StatusOK {
		message := "refresh temp ak failed"
		err = errors.NewServerError(httpResponse.StatusCode, string(responseBody), message)
		return
	}

	var data generateSessionAccessKeyResponse
	err = json.Unmarshal(responseBody, &data)
	if err != nil {
		err = fmt.Errorf("refresh temp ak err, json.Unmarshal fail: %s", err.Error())
		return
	}

	if data.SessionAccessKey == nil {
		err = fmt.Errorf("refresh temp ak token err, fail to get credentials")
		return
	}

	if data.SessionAccessKey.SessionAccessKeyId == nil || data.SessionAccessKey.SessionAccessKeySecret == nil {
		err = fmt.Errorf("refresh temp ak token err, fail to get credentials")
		return
	}

	sessionAK = data.SessionAccessKey
	return
}

type RAMRoleARNCredentialsProvider struct {
	credentialsProvider CredentialsProvider
	roleArn             string
	roleSessionName     string
	durationSeconds     int
	policy              string
	stsRegion           string
	externalId          string
	expirationTimestamp int64
	lastUpdateTimestamp int64
	sessionCredentials  *SessionCredentials
}

func NewRAMRoleARNCredentialsProvider(credentialsProvider CredentialsProvider, roleArn, roleSessionName string, durationSeconds int, policy, stsRegion, externalId string) (provider *RAMRoleARNCredentialsProvider, err error) {
	provider = &RAMRoleARNCredentialsProvider{
		credentialsProvider: credentialsProvider,
		roleArn:             roleArn,
		durationSeconds:     durationSeconds,
		policy:              policy,
		stsRegion:           stsRegion,
		externalId:          externalId,
	}

	if len(roleSessionName) > 0 {
		provider.roleSessionName = roleSessionName
	} else {
		provider.roleSessionName = "aliyun-go-sdk-" + strconv.FormatInt(time.Now().UnixNano()/1000, 10)
	}

	if durationSeconds > 0 {
		if durationSeconds >= 900 && durationSeconds <= 3600 {
			provider.durationSeconds = durationSeconds
		} else {
			err = errors.NewClientError(errors.InvalidParamErrorCode, "Assume Role session duration should be in the range of 15min - 1hr", nil)
		}
	} else {
		// default to 3600
		provider.durationSeconds = 3600
	}

	return
}

func (provider *RAMRoleARNCredentialsProvider) getCredentials(cc *Credentials) (sessionCredentials *SessionCredentials, err error) {
	method := "POST"
	var host string
	if provider.stsRegion != "" {
		host = fmt.Sprintf("sts.%s.aliyuncs.com", provider.stsRegion)
	} else {
		host = "sts.aliyuncs.com"
	}

	queries := make(map[string]string)
	queries["Version"] = "2015-04-01"
	queries["Action"] = "AssumeRole"
	queries["Format"] = "JSON"
	queries["Timestamp"] = utils.GetTimeInFormatISO8601()
	queries["SignatureMethod"] = "HMAC-SHA1"
	queries["SignatureVersion"] = "1.0"
	queries["SignatureNonce"] = utils.GetNonce()
	queries["AccessKeyId"] = cc.AccessKeyId
	if cc.SecurityToken != "" {
		queries["SecurityToken"] = cc.SecurityToken
	}

	bodyForm := make(map[string]string)
	bodyForm["RoleArn"] = provider.roleArn
	if provider.policy != "" {
		bodyForm["Policy"] = provider.policy
	}
	if provider.externalId != "" {
		bodyForm["ExternalId"] = provider.externalId
	}
	bodyForm["RoleSessionName"] = provider.roleSessionName
	bodyForm["DurationSeconds"] = strconv.Itoa(provider.durationSeconds)

	// caculate signature
	signParams := make(map[string]string)
	for key, value := range queries {
		signParams[key] = value
	}
	for key, value := range bodyForm {
		signParams[key] = value
	}

	stringToSign := utils.GetUrlFormedMap(signParams)
	stringToSign = strings.Replace(stringToSign, "+", "%20", -1)
	stringToSign = strings.Replace(stringToSign, "*", "%2A", -1)
	stringToSign = strings.Replace(stringToSign, "%7E", "~", -1)
	stringToSign = url.QueryEscape(stringToSign)
	stringToSign = method + "&%2F&" + stringToSign
	secret := cc.AccessKeySecret + "&"
	queries["Signature"] = utils.ShaHmac1(stringToSign, secret)

	querystring := utils.GetUrlFormedMap(queries)
	// do request
	httpUrl := fmt.Sprintf("https://%s/?%s", host, querystring)

	body := utils.GetUrlFormedMap(bodyForm)

	httpRequest, err := hookNewRequest(http.NewRequest)(method, httpUrl, strings.NewReader(body))
	if err != nil {
		return
	}

	// set headers
	httpRequest.Header["Accept-Encoding"] = []string{"identity"}
	httpRequest.Header["Content-Type"] = []string{"application/x-www-form-urlencoded"}
	httpClient := &http.Client{}

	httpResponse, err := hookDo(httpClient.Do)(httpRequest)
	if err != nil {
		return
	}

	defer httpResponse.Body.Close()

	responseBody, err := ioutil.ReadAll(httpResponse.Body)
	if err != nil {
		return
	}

	if httpResponse.StatusCode != http.StatusOK {
		message := "refresh session token failed"
		err = errors.NewServerError(httpResponse.StatusCode, string(responseBody), message)
		return
	}
	var data assumeRoleResponse
	err = json.Unmarshal(responseBody, &data)
	if err != nil {
		err = fmt.Errorf("refresh RoleArn sts token err, json.Unmarshal fail: %s", err.Error())
		return
	}
	if data.Credentials == nil {
		err = fmt.Errorf("refresh RoleArn sts token err, fail to get credentials")
		return
	}

	if data.Credentials.AccessKeyId == nil || data.Credentials.AccessKeySecret == nil || data.Credentials.SecurityToken == nil {
		err = fmt.Errorf("refresh RoleArn sts token err, fail to get credentials")
		return
	}

	sessionCredentials = &SessionCredentials{
		AccessKeyId:     *data.Credentials.AccessKeyId,
		AccessKeySecret: *data.Credentials.AccessKeySecret,
		SecurityToken:   *data.Credentials.SecurityToken,
		Expiration:      *data.Credentials.Expiration,
	}
	return
}

func (provider *RAMRoleARNCredentialsProvider) needUpdateCredential() (result bool) {
	if provider.expirationTimestamp == 0 {
		return true
	}

	return provider.expirationTimestamp-time.Now().Unix() <= 180
}

func (provider *RAMRoleARNCredentialsProvider) GetCredentials() (cc *Credentials, err error) {
	if provider.sessionCredentials == nil || provider.needUpdateCredential() {
		// 获取前置凭证
		previousCredentials, err1 := provider.credentialsProvider.GetCredentials()
		if err1 != nil {
			return nil, err1
		}
		sessionCredentials, err2 := provider.getCredentials(previousCredentials)
		if err2 != nil {
			return nil, err2
		}

		expirationTime, err := time.Parse("2006-01-02T15:04:05Z", sessionCredentials.Expiration)
		if err != nil {
			return nil, err
		}

		provider.expirationTimestamp = expirationTime.Unix()
		provider.lastUpdateTimestamp = time.Now().Unix()
		provider.sessionCredentials = sessionCredentials
	}

	cc = &Credentials{
		AccessKeyId:     provider.sessionCredentials.AccessKeyId,
		AccessKeySecret: provider.sessionCredentials.AccessKeySecret,
		SecurityToken:   provider.sessionCredentials.SecurityToken,
	}
	return
}

type ECSRAMRoleCredentialsProvider struct {
	roleName            string
	sessionCredentials  *SessionCredentials
	expirationTimestamp int64
}

func NewECSRAMRoleCredentialsProvider(roleName string) *ECSRAMRoleCredentialsProvider {
	return &ECSRAMRoleCredentialsProvider{
		roleName: roleName,
	}
}

func (provider *ECSRAMRoleCredentialsProvider) needUpdateCredential() bool {
	if provider.expirationTimestamp == 0 {
		return true
	}

	return provider.expirationTimestamp-time.Now().Unix() <= 180
}

func (provider *ECSRAMRoleCredentialsProvider) getRoleName() (roleName string, err error) {
	var securityCredURL = "http://100.100.100.200/latest/meta-data/ram/security-credentials/"
	httpRequest, err := hookNewRequest(http.NewRequest)("GET", securityCredURL, strings.NewReader(""))
	if err != nil {
		err = fmt.Errorf("get role name failed: %s", err.Error())
		return
	}
	httpClient := &http.Client{
		Timeout: 5 * time.Second,
	}
	httpResponse, err := hookDo(httpClient.Do)(httpRequest)
	if err != nil {
		err = fmt.Errorf("get role name failed: %s", err.Error())
		return
	}

	if httpResponse.StatusCode != http.StatusOK {
		err = fmt.Errorf("get role name failed: request %s %d", securityCredURL, httpResponse.StatusCode)
		return
	}

	defer httpResponse.Body.Close()

	responseBody, err := ioutil.ReadAll(httpResponse.Body)
	if err != nil {
		return
	}

	roleName = strings.TrimSpace(string(responseBody))
	return
}

func (provider *ECSRAMRoleCredentialsProvider) getCredentials() (sessionCredentials *SessionCredentials, err error) {
	roleName := provider.roleName
	if roleName == "" {
		roleName, err = provider.getRoleName()
		if err != nil {
			return
		}
	}

	var requestUrl = "http://100.100.100.200/latest/meta-data/ram/security-credentials/" + roleName
	httpRequest, err := hookNewRequest(http.NewRequest)("GET", requestUrl, strings.NewReader(""))
	if err != nil {
		err = fmt.Errorf("refresh Ecs sts token err: %s", err.Error())
		return
	}
	httpClient := &http.Client{
		Timeout: 5 * time.Second,
	}
	httpResponse, err := hookDo(httpClient.Do)(httpRequest)
	if err != nil {
		err = fmt.Errorf("refresh Ecs sts token err: %s", err.Error())
		return
	}

	defer httpResponse.Body.Close()

	responseBody, err := ioutil.ReadAll(httpResponse.Body)
	if err != nil {
		return
	}

	if httpResponse.StatusCode != http.StatusOK {
		err = fmt.Errorf("refresh Ecs sts token err, httpStatus: %d, message = %s", httpResponse.StatusCode, string(responseBody))
		return
	}

	var data ecsRAMRoleCredentials
	err = json.Unmarshal(responseBody, &data)
	if err != nil {
		err = fmt.Errorf("refresh Ecs sts token err, json.Unmarshal fail: %s", err.Error())
		return
	}

	if data.AccessKeyId == nil || data.AccessKeySecret == nil || data.SecurityToken == nil {
		err = fmt.Errorf("refresh Ecs sts token err, fail to get credentials")
		return
	}

	if *data.Code != "Success" {
		err = fmt.Errorf("refresh Ecs sts token err, Code is not Success")
		return
	}

	sessionCredentials = &SessionCredentials{
		AccessKeyId:     *data.AccessKeyId,
		AccessKeySecret: *data.AccessKeySecret,
		SecurityToken:   *data.SecurityToken,
		Expiration:      *data.Expiration,
	}
	return
}

func (provider *ECSRAMRoleCredentialsProvider) GetCredentials() (cc *Credentials, err error) {
	if provider.sessionCredentials == nil || provider.needUpdateCredential() {
		sessionCredentials, err1 := provider.getCredentials()
		if err1 != nil {
			return nil, err1
		}

		provider.sessionCredentials = sessionCredentials
		expirationTime, err2 := time.Parse("2006-01-02T15:04:05Z", sessionCredentials.Expiration)
		if err2 != nil {
			return nil, err2
		}
		provider.expirationTimestamp = expirationTime.Unix()
	}

	cc = &Credentials{
		AccessKeyId:     provider.sessionCredentials.AccessKeyId,
		AccessKeySecret: provider.sessionCredentials.AccessKeySecret,
		SecurityToken:   provider.sessionCredentials.SecurityToken,
	}
	return
}

type OIDCCredentialsProvider struct {
	oidcProviderARN     string
	oidcTokenFilePath   string
	roleArn             string
	roleSessionName     string
	durationSeconds     int
	policy              string
	stsRegion           string
	lastUpdateTimestamp int64
	expirationTimestamp int64
	sessionCredentials  *SessionCredentials
}

type OIDCCredentialsProviderBuilder struct {
	provider *OIDCCredentialsProvider
}

func NewOIDCCredentialsProviderBuilder() *OIDCCredentialsProviderBuilder {
	return &OIDCCredentialsProviderBuilder{
		provider: &OIDCCredentialsProvider{},
	}
}

func (b *OIDCCredentialsProviderBuilder) WithOIDCProviderARN(oidcProviderArn string) *OIDCCredentialsProviderBuilder {
	b.provider.oidcProviderARN = oidcProviderArn
	return b
}

func (b *OIDCCredentialsProviderBuilder) WithOIDCTokenFilePath(oidcTokenFilePath string) *OIDCCredentialsProviderBuilder {
	b.provider.oidcTokenFilePath = oidcTokenFilePath
	return b
}

func (b *OIDCCredentialsProviderBuilder) WithRoleArn(roleArn string) *OIDCCredentialsProviderBuilder {
	b.provider.roleArn = roleArn
	return b
}

func (b *OIDCCredentialsProviderBuilder) WithRoleSessionName(roleSessionName string) *OIDCCredentialsProviderBuilder {
	b.provider.roleSessionName = roleSessionName
	return b
}

func (b *OIDCCredentialsProviderBuilder) WithDurationSeconds(durationSeconds int) *OIDCCredentialsProviderBuilder {
	b.provider.durationSeconds = durationSeconds
	return b
}

func (b *OIDCCredentialsProviderBuilder) WithStsRegion(region string) *OIDCCredentialsProviderBuilder {
	b.provider.stsRegion = region
	return b
}

func (b *OIDCCredentialsProviderBuilder) WithPolicy(policy string) *OIDCCredentialsProviderBuilder {
	b.provider.policy = policy
	return b
}

func (b *OIDCCredentialsProviderBuilder) Build() (provider *OIDCCredentialsProvider, err error) {
	provider = b.provider

	if provider.roleSessionName == "" {
		provider.roleSessionName = "aliyun-go-sdk-" + strconv.FormatInt(time.Now().UnixNano()/1000, 10)
	}

	if provider.oidcTokenFilePath == "" {
		provider.oidcTokenFilePath = os.Getenv("ALIBABA_CLOUD_OIDC_TOKEN_FILE")
	}

	if provider.oidcTokenFilePath == "" {
		err = errors.NewClientError(errors.InvalidParamErrorCode, "OIDCTokenFilePath can not be empty", nil)
		return
	}

	if provider.oidcProviderARN == "" {
		provider.oidcProviderARN = os.Getenv("ALIBABA_CLOUD_OIDC_PROVIDER_ARN")
	}

	if provider.oidcProviderARN == "" {
		err = errors.NewClientError(errors.InvalidParamErrorCode, "OIDCProviderARN can not be empty", nil)
		return
	}

	if provider.roleArn == "" {
		provider.roleArn = os.Getenv("ALIBABA_CLOUD_ROLE_ARN")
	}

	if provider.roleArn == "" {
		err = errors.NewClientError(errors.InvalidParamErrorCode, "RoleArn can not be empty", nil)
		return
	}

	if provider.durationSeconds == 0 {
		provider.durationSeconds = 3600
	}

	if provider.durationSeconds < 900 || provider.durationSeconds > 3600 {
		err = errors.NewClientError(errors.InvalidParamErrorCode, "Assume Role session duration should be in the range of 15min - 1hr", nil)
	}

	return
}

func (provider *OIDCCredentialsProvider) getCredentials() (sessionCredentials *SessionCredentials, err error) {
	method := "POST"
	var host string
	if provider.stsRegion != "" {
		host = fmt.Sprintf("sts.%s.aliyuncs.com", provider.stsRegion)
	} else {
		host = "sts.aliyuncs.com"
	}

	queries := make(map[string]string)
	queries["Version"] = "2015-04-01"
	queries["Action"] = "AssumeRoleWithOIDC"
	queries["Format"] = "JSON"
	queries["Timestamp"] = utils.GetTimeInFormatISO8601()

	bodyForm := make(map[string]string)
	bodyForm["RoleArn"] = provider.roleArn
	bodyForm["OIDCProviderArn"] = provider.oidcProviderARN
	token, err := ioutil.ReadFile(provider.oidcTokenFilePath)
	if err != nil {
		return
	}

	bodyForm["OIDCToken"] = string(token)
	if provider.policy != "" {
		bodyForm["Policy"] = provider.policy
	}

	bodyForm["RoleSessionName"] = provider.roleSessionName
	bodyForm["DurationSeconds"] = strconv.Itoa(provider.durationSeconds)

	// caculate signature
	signParams := make(map[string]string)
	for key, value := range queries {
		signParams[key] = value
	}
	for key, value := range bodyForm {
		signParams[key] = value
	}

	querystring := utils.GetUrlFormedMap(queries)
	// do request
	httpUrl := fmt.Sprintf("https://%s/?%s", host, querystring)

	body := utils.GetUrlFormedMap(bodyForm)

	httpRequest, err := hookNewRequest(http.NewRequest)(method, httpUrl, strings.NewReader(body))
	if err != nil {
		return
	}

	// set headers
	httpRequest.Header["Accept-Encoding"] = []string{"identity"}
	httpRequest.Header["Content-Type"] = []string{"application/x-www-form-urlencoded"}
	httpClient := &http.Client{}

	httpResponse, err := hookDo(httpClient.Do)(httpRequest)
	if err != nil {
		return
	}

	defer httpResponse.Body.Close()

	responseBody, err := ioutil.ReadAll(httpResponse.Body)
	if err != nil {
		return
	}

	if httpResponse.StatusCode != http.StatusOK {
		message := "get session token failed"
		err = errors.NewServerError(httpResponse.StatusCode, string(responseBody), message)
		return
	}
	var data assumeRoleResponse
	err = json.Unmarshal(responseBody, &data)
	if err != nil {
		err = fmt.Errorf("get oidc sts token err, json.Unmarshal fail: %s", err.Error())
		return
	}
	if data.Credentials == nil {
		err = fmt.Errorf("get oidc sts token err, fail to get credentials")
		return
	}

	if data.Credentials.AccessKeyId == nil || data.Credentials.AccessKeySecret == nil || data.Credentials.SecurityToken == nil {
		err = fmt.Errorf("refresh RoleArn sts token err, fail to get credentials")
		return
	}

	sessionCredentials = &SessionCredentials{
		AccessKeyId:     *data.Credentials.AccessKeyId,
		AccessKeySecret: *data.Credentials.AccessKeySecret,
		SecurityToken:   *data.Credentials.SecurityToken,
		Expiration:      *data.Credentials.Expiration,
	}
	return
}

func (provider *OIDCCredentialsProvider) needUpdateCredential() (result bool) {
	if provider.expirationTimestamp == 0 {
		return true
	}

	return provider.expirationTimestamp-time.Now().Unix() <= 180
}

func (provider *OIDCCredentialsProvider) GetCredentials() (cc *Credentials, err error) {
	if provider.sessionCredentials == nil || provider.needUpdateCredential() {
		sessionCredentials, err1 := provider.getCredentials()
		if err1 != nil {
			return nil, err1
		}

		provider.sessionCredentials = sessionCredentials
		expirationTime, err2 := time.Parse("2006-01-02T15:04:05Z", sessionCredentials.Expiration)
		if err2 != nil {
			return nil, err2
		}

		provider.lastUpdateTimestamp = time.Now().Unix()
		provider.expirationTimestamp = expirationTime.Unix()
	}

	cc = &Credentials{
		AccessKeyId:     provider.sessionCredentials.AccessKeyId,
		AccessKeySecret: provider.sessionCredentials.AccessKeySecret,
		SecurityToken:   provider.sessionCredentials.SecurityToken,
	}
	return
}

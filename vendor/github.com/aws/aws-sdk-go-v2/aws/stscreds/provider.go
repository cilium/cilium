/*
Package stscreds are credential Providers to retrieve STS AWS credentials.

STS provides multiple ways to retrieve credentials which can be used when making
future AWS service API operation calls.

The SDK will ensure that per instance of credentials.Credentials all requests
to refresh the credentials will be synchronized. But, the SDK is unable to
ensure synchronous usage of the AssumeRoleProvider if the value is shared
between multiple Credentials or service clients.

Assume Role

To assume an IAM role using STS with the SDK you can create a new Credentials
with the SDKs's stscreds package.

	// Initial credentials loaded from SDK's default credential chain. Such as
	// the environment, shared credentials (~/.aws/credentials), or EC2 Instance
	// Role. These credentials will be used to to make the STS Assume Role API.
	cfg, err := external.LoadDefaultAWSConfig()

	// Create the credentials from AssumeRoleProvider to assume the role
	// referenced by the "myRoleARN" ARN.
	stsSvc := sts.New(cfg)
	stsCredProvider := stscreds.NewAssumeRoleProvider(stsSvc, "myRoleArn")

	cfg.Credentials = aws.NewCredentials(stsCredProvider)

	// Create service client value configured for credentials
	// from assumed role.
	svc := s3.New(cfg)

Assume Role with static MFA Token

To assume an IAM role with a MFA token you can either specify a MFA token code
directly or provide a function to prompt the user each time the credentials
need to refresh the role's credentials. Specifying the TokenCode should be used
for short lived operations that will not need to be refreshed, and when you do
not want to have direct control over the user provides their MFA token.

With TokenCode the AssumeRoleProvider will be not be able to refresh the role's
credentials.

	// Create the credentials from AssumeRoleProvider to assume the role
	// referenced by the "myRoleARN" ARN using the MFA token code provided.
	creds := stscreds.NewCredentials(sess, "myRoleArn", func(p *stscreds.AssumeRoleProvider) {
		p.SerialNumber = aws.String("myTokenSerialNumber")
		p.TokenCode = aws.String("00000000")
	})

	// Create service client value configured for credentials
	// from assumed role.
	svc := s3.New(sess, &aws.Config{Credentials: creds})

Assume Role with MFA Token Provider

To assume an IAM role with MFA for longer running tasks where the credentials
may need to be refreshed setting the TokenProvider field of AssumeRoleProvider
will allow the credential provider to prompt for new MFA token code when the
role's credentials need to be refreshed.

The StdinTokenProvider function is available to prompt on stdin to retrieve
the MFA token code from the user. You can also implement custom prompts by
satisfing the TokenProvider function signature.

Using StdinTokenProvider with multiple AssumeRoleProviders, or Credentials will
have undesirable results as the StdinTokenProvider will not be synchronized. A
single Credentials with an AssumeRoleProvider can be shared safely.

	// Create the credentials from AssumeRoleProvider to assume the role
	// referenced by the "myRoleARN" ARN. Prompting for MFA token from stdin.
	creds := stscreds.NewCredentials(sess, "myRoleArn", func(p *stscreds.AssumeRoleProvider) {
		p.SerialNumber = aws.String("myTokenSerialNumber")
		p.TokenProvider = stscreds.StdinTokenProvider
	})

	// Create service client value configured for credentials
	// from assumed role.
	svc := s3.New(sess, &aws.Config{Credentials: creds})

*/
package stscreds

import (
	"context"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/awserr"
	"github.com/aws/aws-sdk-go-v2/service/sts"
)

// StdinTokenProvider will prompt on stdout and read from stdin for a string value.
// An error is returned if reading from stdin fails.
//
// Use this function go read MFA tokens from stdin. The function makes no attempt
// to make atomic prompts from stdin across multiple gorouties.
//
// Using StdinTokenProvider with multiple AssumeRoleProviders, or Credentials will
// have undesirable results as the StdinTokenProvider will not be synchronized. A
// single Credentials with an AssumeRoleProvider can be shared safely
//
// Will wait forever until something is provided on the stdin.
func StdinTokenProvider() (string, error) {
	var v string
	fmt.Printf("Assume Role MFA token code: ")
	_, err := fmt.Scanln(&v)

	return v, err
}

// ProviderName provides a name of AssumeRole provider
const ProviderName = "AssumeRoleProvider"

// AssumeRoler represents the minimal subset of the STS client API used by this provider.
type AssumeRoler interface {
	AssumeRoleRequest(input *sts.AssumeRoleInput) sts.AssumeRoleRequest
}

// DefaultDuration is the default amount of time in minutes that the credentials
// will be valid for.
var DefaultDuration = time.Duration(15) * time.Minute

// AssumeRoleProvider retrieves temporary credentials from the STS service, and
// keeps track of their expiration time.
//
// This credential provider will be used by the SDKs default credential change
// when shared configuration is enabled, and the shared config or shared credentials
// file configure assume role. See Session docs for how to do this.
//
// AssumeRoleProvider does not provide any synchronization and it is not safe
// to share this value across multiple Credentials, Sessions, or service clients
// without also sharing the same Credentials instance.
type AssumeRoleProvider struct {
	aws.SafeCredentialsProvider

	// STS client to make assume role request with.
	Client AssumeRoler

	// Role to be assumed.
	RoleARN string

	// Session name, if you wish to reuse the credentials elsewhere.
	RoleSessionName string

	// Expiry duration of the STS credentials. Defaults to 15 minutes if not set.
	Duration time.Duration

	// Optional ExternalID to pass along, defaults to nil if not set.
	ExternalID *string

	// The policy plain text must be 2048 bytes or shorter. However, an internal
	// conversion compresses it into a packed binary format with a separate limit.
	// The PackedPolicySize response element indicates by percentage how close to
	// the upper size limit the policy is, with 100% equaling the maximum allowed
	// size.
	Policy *string

	// The identification number of the MFA device that is associated with the user
	// who is making the AssumeRole call. Specify this value if the trust policy
	// of the role being assumed includes a condition that requires MFA authentication.
	// The value is either the serial number for a hardware device (such as GAHT12345678)
	// or an Amazon Resource Name (ARN) for a virtual device (such as arn:aws:iam::123456789012:mfa/user).
	SerialNumber *string

	// The value provided by the MFA device, if the trust policy of the role being
	// assumed requires MFA (that is, if the policy includes a condition that tests
	// for MFA). If the role being assumed requires MFA and if the TokenCode value
	// is missing or expired, the AssumeRole call returns an "access denied" error.
	//
	// If SerialNumber is set and neither TokenCode nor TokenProvider are also
	// set an error will be returned.
	TokenCode *string

	// Async method of providing MFA token code for assuming an IAM role with MFA.
	// The value returned by the function will be used as the TokenCode in the Retrieve
	// call. See StdinTokenProvider for a provider that prompts and reads from stdin.
	//
	// This token provider will be called when ever the assumed role's
	// credentials need to be refreshed when SerialNumber is also set and
	// TokenCode is not set.
	//
	// If both TokenCode and TokenProvider is set, TokenProvider will be used and
	// TokenCode is ignored.
	TokenProvider func() (string, error)

	// ExpiryWindow will allow the credentials to trigger refreshing prior to
	// the credentials actually expiring. This is beneficial so race conditions
	// with expiring credentials do not cause request to fail unexpectedly
	// due to ExpiredTokenException exceptions.
	//
	// So a ExpiryWindow of 10s would cause calls to IsExpired() to return true
	// 10 seconds before the credentials are actually expired.
	//
	// If ExpiryWindow is 0 or less it will be ignored.
	ExpiryWindow time.Duration
}

// NewAssumeRoleProvider constructs and returns a credentials provider that
// will retrieve credentials by assuming a IAM role using STS.
func NewAssumeRoleProvider(client AssumeRoler, roleARN string) *AssumeRoleProvider {
	p := &AssumeRoleProvider{
		Client:  client,
		RoleARN: roleARN,
	}
	p.RetrieveFn = p.retrieveFn

	return p
}

// Retrieve generates a new set of temporary credentials using STS.
func (p *AssumeRoleProvider) retrieveFn() (aws.Credentials, error) {
	// Apply defaults where parameters are not set.
	if len(p.RoleSessionName) == 0 {
		// Try to work out a role name that will hopefully end up unique.
		p.RoleSessionName = fmt.Sprintf("%d", time.Now().UTC().UnixNano())
	}
	if p.Duration == 0 {
		// Expire as often as AWS permits.
		p.Duration = DefaultDuration
	}
	input := &sts.AssumeRoleInput{
		DurationSeconds: aws.Int64(int64(p.Duration / time.Second)),
		RoleArn:         aws.String(p.RoleARN),
		RoleSessionName: aws.String(p.RoleSessionName),
		ExternalId:      p.ExternalID,
	}
	if p.Policy != nil {
		input.Policy = p.Policy
	}
	if p.SerialNumber != nil {
		if p.TokenCode != nil {
			input.SerialNumber = p.SerialNumber
			input.TokenCode = p.TokenCode
		} else if p.TokenProvider != nil {
			input.SerialNumber = p.SerialNumber
			code, err := p.TokenProvider()
			if err != nil {
				return aws.Credentials{}, err
			}
			input.TokenCode = aws.String(code)
		} else {
			return aws.Credentials{},
				awserr.New("AssumeRoleTokenNotAvailable",
					"assume role with MFA enabled, but neither TokenCode nor TokenProvider are set", nil)
		}
	}

	req := p.Client.AssumeRoleRequest(input)
	resp, err := req.Send(context.Background())
	if err != nil {
		return aws.Credentials{Source: ProviderName}, err
	}

	return aws.Credentials{
		AccessKeyID:     *resp.Credentials.AccessKeyId,
		SecretAccessKey: *resp.Credentials.SecretAccessKey,
		SessionToken:    *resp.Credentials.SessionToken,
		Source:          ProviderName,

		CanExpire: true,
		Expires:   resp.Credentials.Expiration.Add(-p.ExpiryWindow),
	}, nil
}

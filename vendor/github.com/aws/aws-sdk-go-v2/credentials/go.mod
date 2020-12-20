module github.com/aws/aws-sdk-go-v2/credentials

go 1.15

require (
	github.com/aws/aws-sdk-go-v2 v0.30.0
	github.com/aws/aws-sdk-go-v2/ec2imds v0.1.5
	github.com/aws/aws-sdk-go-v2/service/sts v0.30.0
	github.com/awslabs/smithy-go v0.4.0
)

replace (
	github.com/aws/aws-sdk-go-v2 => ../
	github.com/aws/aws-sdk-go-v2/ec2imds => ../ec2imds/
	github.com/aws/aws-sdk-go-v2/service/sts => ../service/sts/
)

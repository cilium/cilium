module github.com/aws/aws-sdk-go-v2/credentials

go 1.15

require (
	github.com/aws/aws-sdk-go-v2 v1.0.0
	github.com/aws/aws-sdk-go-v2/feature/ec2/imds v1.0.0
	github.com/aws/aws-sdk-go-v2/service/sts v1.0.0
	github.com/aws/smithy-go v1.0.0
	github.com/aws/aws-sdk-go-v2/service/internal/presigned-url v1.0.0
)

replace (
	github.com/aws/aws-sdk-go-v2 => ../
	github.com/aws/aws-sdk-go-v2/feature/ec2/imds => ../feature/ec2/imds/
	github.com/aws/aws-sdk-go-v2/service/sts => ../service/sts/
)

replace github.com/aws/aws-sdk-go-v2/service/internal/presigned-url => ../service/internal/presigned-url/

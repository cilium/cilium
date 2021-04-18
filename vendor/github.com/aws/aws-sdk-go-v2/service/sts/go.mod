module github.com/aws/aws-sdk-go-v2/service/sts

go 1.15

require (
	github.com/aws/aws-sdk-go-v2 v1.3.2
	github.com/aws/aws-sdk-go-v2/service/internal/presigned-url v1.0.6
	github.com/aws/smithy-go v1.3.1
)

replace github.com/aws/aws-sdk-go-v2 => ../../

replace github.com/aws/aws-sdk-go-v2/service/internal/presigned-url => ../../service/internal/presigned-url/

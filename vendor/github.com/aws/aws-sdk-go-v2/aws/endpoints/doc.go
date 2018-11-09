// Package endpoints provides the types and functionality for defining regions
// and endpoints, as well as querying those definitions.
//
// The SDK's Regions and Endpoints metadata is code generated into the endpoints
// package, and is accessible via the DefaultResolver function. This function
// returns a endpoint Resolver will search the metadata and build an associated
// endpoint if one is found. The default resolver will search all partitions
// known by the SDK. e.g AWS Standard (aws), AWS China (aws-cn), and
// AWS GovCloud (US) (aws-us-gov).
// .
//
// Enumerating Regions and Endpoint Metadata
//
// Casting the Resolver returned by DefaultResolver to a EnumPartitions interface
// will allow you to get access to the list of underlying Partitions with the
// Partitions method. This is helpful if you want to limit the SDK's endpoint
// resolving to a single partition, or enumerate regions, services, and endpoints
// in the partition.
//
//     resolver := endpoints.NewDefaultResolver()
//     partitions := resolver.Partitions()
//
//     for _, p := range partitions {
//         fmt.Println("Regions for", p.ID())
//         for id, _ := range p.Regions() {
//             fmt.Println("*", id)
//         }
//
//         fmt.Println("Services for", p.ID())
//         for id, _ := range p.Services() {
//             fmt.Println("*", id)
//         }
//     }
//
// Using Custom Endpoints
//
// The endpoints package also gives you the ability to use your own logic how
// endpoints are resolved. This is a great way to define a custom endpoint
// for select services, without passing that logic down through your code.
//
// If a type implements the Resolver interface it can be used to resolve
// endpoints. To use this with the SDK's Session and Config set the value
// of the type to the EndpointsResolver field of aws.Config when initializing
// the service client.
//
// In addition the ResolverFunc is a wrapper for a func matching the signature
// of Resolver.ResolveEndpoint, converting it to a type that satisfies the
// Resolver interface.
//
//
//     defaultResolver := endpoints.NewDefaultResolver()
//     myCustomResolver := func(service, region string) (aws.Endpoint, error) {
//         if service == endpoints.S3ServiceID {
//             return aws.Endpoint{
//                 URL:           "s3.custom.endpoint.com",
//                 SigningRegion: "custom-signing-region",
//             }, nil
//         }
//
//         return defaultResolver.ResolveEndpoint(service, region)
//     }
//
//     cfg, err := external.LoadDefaultAWSConfig()
//     if err != nil {
//         panic(err)
//     }
//     cfg.Region = "us-west-2"
//     cfg.EndpointResolver = aws.EndpointResolverFunc(myCustomResolver)
package endpoints

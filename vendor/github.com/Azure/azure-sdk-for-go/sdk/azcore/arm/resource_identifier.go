// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

package arm

import (
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/arm/internal/resource"
)

// RootResourceID defines the tenant as the root parent of all other ResourceID.
var RootResourceID = resource.RootResourceID

// ResourceID represents a resource ID such as `/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/myRg`.
// Don't create this type directly, use [ParseResourceID] instead. Fields are considered immutable and shouldn't be
// modified after creation.
// Name and ResourceType describe the final resource; Parent preserves its ancestry.
// Checking only ResourceType or whether Parent is non-nil does not establish the expected shape:
// both an ordinary resource-group-scoped resource and an extension resource have a parent.
type ResourceID = resource.ResourceID

// ParseResourceID parses a string to an instance of ResourceID.
// Parsing does not validate resource existence, authorization, or the shape expected by an operation.
// Use [ResourceID.ValidateResourceTypeChain] to check the complete resource-type ancestry before
// passing extracted fields to an operation that assumes a particular resource-ID shape.
// Extracting only SubscriptionID, ResourceGroupName, and Name can discard parent information,
// causing an operation to address a different resource. Authorization for the original ID
// does not establish authorization for that different resource.
func ParseResourceID(id string) (*ResourceID, error) {
	return resource.ParseResourceID(id)
}

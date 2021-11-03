package xds_core_v3


import (
	xds "github.com/cncf/xds/go/xds/core/v3"
)

type ResourceLocatorValidationError = xds.ResourceLocatorValidationError
type ResourceLocator_DirectiveValidationError = xds.ResourceLocator_DirectiveValidationError
type ContextParamsValidationError = xds.ContextParamsValidationError
type Resource = xds.Resource
type CollectionEntry = xds.CollectionEntry
type CollectionEntry_Locator = xds.CollectionEntry_Locator
type CollectionEntry_InlineEntry_ = xds.CollectionEntry_InlineEntry_
type CollectionEntry_InlineEntry = xds.CollectionEntry_InlineEntry
type ResourceLocator_Scheme = xds.ResourceLocator_Scheme
type ResourceLocator = xds.ResourceLocator
type ResourceLocator_ExactContext = xds.ResourceLocator_ExactContext
type ResourceLocator_Directive = xds.ResourceLocator_Directive
type ResourceLocator_Directive_Alt = xds.ResourceLocator_Directive_Alt
type ResourceLocator_Directive_Entry = xds.ResourceLocator_Directive_Entry
type ResourceName = xds.ResourceName
type ResourceNameValidationError = xds.ResourceNameValidationError
type Authority = xds.Authority
type ResourceValidationError = xds.ResourceValidationError
type AuthorityValidationError = xds.AuthorityValidationError
type CollectionEntryValidationError = xds.CollectionEntryValidationError
type CollectionEntry_InlineEntryValidationError = xds.CollectionEntry_InlineEntryValidationError
type ContextParams = xds.ContextParams

const (
	ResourceLocator_XDSTP ResourceLocator_Scheme = xds.ResourceLocator_XDSTP
	ResourceLocator_HTTP  ResourceLocator_Scheme = xds.ResourceLocator_HTTP
	ResourceLocator_FILE  ResourceLocator_Scheme = xds.ResourceLocator_FILE
)

var ResourceLocator_Scheme_name = xds.ResourceLocator_Scheme_name

var ResourceLocator_Scheme_value = xds.ResourceLocator_Scheme_name
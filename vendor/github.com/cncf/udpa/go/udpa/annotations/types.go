package udpa_annotations


import (
	xds "github.com/cncf/xds/go/udpa/annotations"
)

type FieldSecurityAnnotation = xds.FieldSecurityAnnotation
type FieldSecurityAnnotationValidationError = xds.FieldSecurityAnnotationValidationError
type VersioningAnnotationValidationError = xds.VersioningAnnotationValidationError
type MigrateAnnotation = xds.MigrateAnnotation
type FieldMigrateAnnotation = xds.FieldMigrateAnnotation
type FileMigrateAnnotation = xds.FileMigrateAnnotation
type StatusAnnotationValidationError = xds.StatusAnnotationValidationError
type VersioningAnnotation = xds.VersioningAnnotation
type MigrateAnnotationValidationError = xds.MigrateAnnotationValidationError
type FieldMigrateAnnotationValidationError = xds.FieldMigrateAnnotationValidationError
type FileMigrateAnnotationValidationError = xds.FileMigrateAnnotationValidationError
type PackageVersionStatus = xds.PackageVersionStatus
type StatusAnnotation = xds.StatusAnnotation

const (
	PackageVersionStatus_UNKNOWN                      PackageVersionStatus = xds.PackageVersionStatus_UNKNOWN
	PackageVersionStatus_FROZEN                       PackageVersionStatus = xds.PackageVersionStatus_FROZEN
	PackageVersionStatus_ACTIVE                       PackageVersionStatus = xds.PackageVersionStatus_ACTIVE
	PackageVersionStatus_NEXT_MAJOR_VERSION_CANDIDATE PackageVersionStatus = xds.PackageVersionStatus_NEXT_MAJOR_VERSION_CANDIDATE
)
var PackageVersionStatus_name = xds.PackageVersionStatus_name
var PackageVersionStatus_value = xds.PackageVersionStatus_value

var E_Security = xds.E_Security
var E_Sensitive = xds.E_Sensitive
var E_MessageMigrate = xds.E_MessageMigrate
var E_FieldMigrate = xds.E_FieldMigrate
var E_EnumMigrate = xds.E_EnumMigrate
var E_EnumValueMigrate = xds.E_EnumValueMigrate
var E_FileMigrate = xds.E_FileMigrate
var E_Versioning = xds.E_Versioning
var E_FileStatus = xds.E_FileStatus



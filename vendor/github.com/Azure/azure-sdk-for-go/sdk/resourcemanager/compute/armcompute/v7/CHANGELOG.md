# Release History

## 7.1.0 (2025-10-09)
### Features Added

- New value `OrchestrationServiceNamesAutomaticZoneRebalancing` added to enum type `OrchestrationServiceNames`
- New value `ZonePlacementPolicyTypeAuto` added to enum type `ZonePlacementPolicyType`
- New enum type `HighSpeedInterconnectPlacement` with values `HighSpeedInterconnectPlacementNone`, `HighSpeedInterconnectPlacementTrunk`
- New enum type `OrchestrationServiceOperationStatus` with values `OrchestrationServiceOperationStatusCompleted`, `OrchestrationServiceOperationStatusInProgress`
- New enum type `ReservationType` with values `ReservationTypeBlock`, `ReservationTypeTargeted`
- New enum type `ScriptShellTypes` with values `ScriptShellTypesDefault`, `ScriptShellTypesPowershell7`
- New function `*VirtualMachineScaleSetsClient.BeginScaleOut(context.Context, string, string, VMScaleSetScaleOutInput, *VirtualMachineScaleSetsClientBeginScaleOutOptions) (*runtime.Poller[VirtualMachineScaleSetsClientScaleOutResponse], error)`
- New struct `AllInstancesDown`
- New struct `MaxInstancePercentPerZonePolicy`
- New struct `ScheduleProfile`
- New struct `VMScaleSetScaleOutInput`
- New struct `VMScaleSetScaleOutInputProperties`
- New struct `ZoneAllocationPolicy`
- New field `ReservationType` in struct `CapacityReservationGroupProperties`
- New field `ScheduleProfile` in struct `CapacityReservationProperties`
- New field `ScheduledEventsAPIVersion` in struct `EventGridAndResourceGraph`
- New field `LastStatusChangeTime`, `LatestOperationStatus` in struct `OrchestrationServiceSummary`
- New field `AddProxyAgentExtension` in struct `ProxyAgentSettings`
- New field `ZoneAllocationPolicy` in struct `ResiliencyPolicy`
- New field `AllInstancesDown` in struct `ScheduledEventsPolicy`
- New field `Tags` in struct `VirtualMachineNetworkInterfaceConfiguration`
- New field `Tags` in struct `VirtualMachinePublicIPAddressConfiguration`
- New field `GalleryScriptReferenceID`, `ScriptShell` in struct `VirtualMachineRunCommandScriptSource`
- New field `Placement` in struct `VirtualMachineScaleSet`
- New field `Tags` in struct `VirtualMachineScaleSetNetworkConfiguration`
- New field `HighSpeedInterconnectPlacement` in struct `VirtualMachineScaleSetProperties`
- New field `Tags` in struct `VirtualMachineScaleSetPublicIPAddressConfiguration`
- New field `Tags` in struct `VirtualMachineScaleSetUpdateNetworkConfiguration`
- New field `Tags` in struct `VirtualMachineScaleSetUpdatePublicIPAddressConfiguration`
- New field `PatchNameMasksToExclude`, `PatchNameMasksToInclude` in struct `WindowsParameters`


## 7.0.0 (2025-07-23)
### Breaking Changes

- Type of `OperationValue.Display` has been changed from `*OperationValueDisplay` to `*OperationDisplay`
- Type of `OperationValue.Origin` has been changed from `*string` to `*Origin`
- Enum `AvailabilitySetSKUTypes` has been removed
- Enum `Expand` has been removed
- Operation `*VirtualMachineImagesClient.NewListWithPropertiesPager` does not support pagination anymore, use `*VirtualMachineImagesClient.ListWithProperties` instead.
- Struct `DiskImageEncryption` has been removed
- Struct `GalleryArtifactPublishingProfileBase` has been removed
- Struct `GalleryArtifactSafetyProfileBase` has been removed
- Struct `GalleryArtifactSource` has been removed
- Struct `GalleryArtifactVersionSource` has been removed
- Struct `GalleryDiskImage` has been removed
- Struct `GalleryResourceProfilePropertiesBase` has been removed
- Struct `GalleryResourceProfileVersionPropertiesBase` has been removed
- Struct `ImageDisk` has been removed
- Struct `LatestGalleryImageVersion` has been removed
- Struct `LogAnalyticsInputBase` has been removed
- Struct `ManagedArtifact` has been removed
- Struct `OperationValueDisplay` has been removed
- Struct `PirCommunityGalleryResource` has been removed
- Struct `PirResource` has been removed
- Struct `PirSharedGalleryResource` has been removed
- Struct `ProxyOnlyResource` has been removed
- Struct `ProxyResource` has been removed
- Struct `Resource` has been removed
- Struct `ResourceWithOptionalLocation` has been removed
- Struct `SharedGalleryDiskImage` has been removed
- Struct `UpdateResource` has been removed
- Struct `UpdateResourceDefinition` has been removed
- Struct `VirtualMachineImagesWithPropertiesListResult` has been removed

### Features Added

- New enum type `ActionType` with values `ActionTypeInternal`
- New enum type `AvailabilityPolicyDiskDelay` with values `AvailabilityPolicyDiskDelayAutomaticReattach`, `AvailabilityPolicyDiskDelayNone`
- New enum type `CreatedByType` with values `CreatedByTypeApplication`, `CreatedByTypeKey`, `CreatedByTypeManagedIdentity`, `CreatedByTypeUser`
- New enum type `Origin` with values `OriginSystem`, `OriginUser`, `OriginUserSystem`
- New enum type `SnapshotAccessState` with values `SnapshotAccessStateAvailable`, `SnapshotAccessStateAvailableWithInstantAccess`, `SnapshotAccessStateInstantAccess`, `SnapshotAccessStatePending`, `SnapshotAccessStateUnknown`
- New enum type `SupportedSecurityOption` with values `SupportedSecurityOptionTrustedLaunchAndConfidentialVMSupported`, `SupportedSecurityOptionTrustedLaunchSupported`
- New struct `AvailabilityPolicy`
- New struct `OperationDisplay`
- New field `SecurityMetadataAccessSAS` in struct `AccessURI`
- New field `SystemData` in struct `AvailabilitySet`
- New field `SystemData` in struct `CapacityReservation`
- New field `SystemData` in struct `CapacityReservationGroup`
- New field `InstantAccessDurationMinutes`, `SecurityMetadataURI` in struct `CreationData`
- New field `SystemData` in struct `DedicatedHost`
- New field `SystemData` in struct `DedicatedHostGroup`
- New field `NextLink` in struct `DedicatedHostSizeListResult`
- New field `SystemData` in struct `Disk`
- New field `SystemData` in struct `DiskAccess`
- New field `SystemData` in struct `DiskEncryptionSet`
- New field `AvailabilityPolicy` in struct `DiskProperties`
- New field `SystemData` in struct `DiskRestorePoint`
- New field `AvailabilityPolicy` in struct `DiskUpdateProperties`
- New field `SystemData` in struct `Gallery`
- New field `SystemData` in struct `GalleryApplication`
- New field `SystemData` in struct `GalleryApplicationVersion`
- New field `SystemData` in struct `GalleryImage`
- New field `SystemData` in struct `GalleryImageVersion`
- New field `SystemData` in struct `GalleryInVMAccessControlProfile`
- New field `SystemData` in struct `GalleryInVMAccessControlProfileVersion`
- New field `SystemData` in struct `GallerySoftDeletedResource`
- New field `SystemData` in struct `Image`
- New field `NextLink` in struct `OperationListResult`
- New field `ActionType`, `IsDataAction` in struct `OperationValue`
- New field `SystemData` in struct `PrivateEndpointConnection`
- New field `SystemData` in struct `ProximityPlacementGroup`
- New field `SystemData` in struct `RestorePoint`
- New field `SystemData` in struct `RestorePointCollection`
- New field `SystemData` in struct `RollingUpgradeStatusInfo`
- New field `SystemData` in struct `SSHPublicKeyResource`
- New field `SystemData` in struct `Snapshot`
- New field `SnapshotAccessState` in struct `SnapshotProperties`
- New field `SnapshotAccessState` in struct `SnapshotUpdateProperties`
- New field `SupportedSecurityOption` in struct `SupportedCapabilities`
- New field `CreatedBy`, `CreatedByType`, `LastModifiedBy`, `LastModifiedByType` in struct `SystemData`
- New field `SystemData` in struct `VirtualMachine`
- New field `SystemData` in struct `VirtualMachineExtension`
- New field `SystemData` in struct `VirtualMachineExtensionImage`
- New field `SystemData` in struct `VirtualMachineRunCommand`
- New field `SystemData` in struct `VirtualMachineScaleSet`
- New field `SystemData` in struct `VirtualMachineScaleSetVM`
- New field `NextLink` in struct `VirtualMachineSizeListResult`


## 6.4.0 (2025-03-28)
### Features Added

- New value `AllocationStrategyPrioritized` added to enum type `AllocationStrategy`
- New value `InstanceViewTypesResiliencyView` added to enum type `InstanceViewTypes`
- New value `NetworkAPIVersionTwoThousandTwentyTwo1101` added to enum type `NetworkAPIVersion`
- New enum type `Expand` with values `ExpandProperties`
- New enum type `Modes` with values `ModesAudit`, `ModesDisabled`, `ModesEnforce`
- New enum type `RebalanceBehavior` with values `RebalanceBehaviorCreateBeforeDelete`
- New enum type `RebalanceStrategy` with values `RebalanceStrategyRecreate`
- New enum type `ResilientVMDeletionStatus` with values `ResilientVMDeletionStatusDisabled`, `ResilientVMDeletionStatusEnabled`, `ResilientVMDeletionStatusFailed`, `ResilientVMDeletionStatusInProgress`
- New enum type `ZonePlacementPolicyType` with values `ZonePlacementPolicyTypeAny`
- New function `*AvailabilitySetsClient.CancelMigrationToVirtualMachineScaleSet(context.Context, string, string, *AvailabilitySetsClientCancelMigrationToVirtualMachineScaleSetOptions) (AvailabilitySetsClientCancelMigrationToVirtualMachineScaleSetResponse, error)`
- New function `*AvailabilitySetsClient.BeginConvertToVirtualMachineScaleSet(context.Context, string, string, *AvailabilitySetsClientBeginConvertToVirtualMachineScaleSetOptions) (*runtime.Poller[AvailabilitySetsClientConvertToVirtualMachineScaleSetResponse], error)`
- New function `*AvailabilitySetsClient.StartMigrationToVirtualMachineScaleSet(context.Context, string, string, MigrateToVirtualMachineScaleSetInput, *AvailabilitySetsClientStartMigrationToVirtualMachineScaleSetOptions) (AvailabilitySetsClientStartMigrationToVirtualMachineScaleSetResponse, error)`
- New function `*AvailabilitySetsClient.ValidateMigrationToVirtualMachineScaleSet(context.Context, string, string, MigrateToVirtualMachineScaleSetInput, *AvailabilitySetsClientValidateMigrationToVirtualMachineScaleSetOptions) (AvailabilitySetsClientValidateMigrationToVirtualMachineScaleSetResponse, error)`
- New function `*VirtualMachineImagesClient.NewListWithPropertiesPager(string, string, string, string, Expand, *VirtualMachineImagesClientListWithPropertiesOptions) *runtime.Pager[VirtualMachineImagesClientListWithPropertiesResponse]`
- New function `*VirtualMachinesClient.BeginMigrateToVMScaleSet(context.Context, string, string, *VirtualMachinesClientBeginMigrateToVMScaleSetOptions) (*runtime.Poller[VirtualMachinesClientMigrateToVMScaleSetResponse], error)`
- New struct `AutomaticZoneRebalancingPolicy`
- New struct `ConvertToVirtualMachineScaleSetInput`
- New struct `DefaultVirtualMachineScaleSetInfo`
- New struct `HostEndpointSettings`
- New struct `MigrateToVirtualMachineScaleSetInput`
- New struct `MigrateVMToVirtualMachineScaleSetInput`
- New struct `Placement`
- New struct `VirtualMachineImagesWithPropertiesListResult`
- New struct `VirtualMachineScaleSetMigrationInfo`
- New field `VirtualMachineScaleSetMigrationInfo` in struct `AvailabilitySetProperties`
- New field `Imds`, `WireServer` in struct `ProxyAgentSettings`
- New field `AutomaticZoneRebalancingPolicy` in struct `ResiliencyPolicy`
- New field `Rank` in struct `SKUProfileVMSize`
- New field `PrioritizeUnhealthyVMs` in struct `ScaleInPolicy`
- New field `AlignRegionalDisksToVMZone` in struct `StorageProfile`
- New field `Placement` in struct `VirtualMachine`
- New field `ResilientVMDeletionStatus` in struct `VirtualMachineScaleSetVMProperties`


## 6.3.0 (2025-01-24)
### Features Added

- New field `IsBootstrapCertificate` in struct `CloudServiceVaultCertificate`


## 6.2.0 (2024-12-27)
### Features Added

- New value `StorageAccountTypePremiumV2LRS` added to enum type `StorageAccountType`
- New enum type `AccessControlRulesMode` with values `AccessControlRulesModeAudit`, `AccessControlRulesModeDisabled`, `AccessControlRulesModeEnforce`
- New enum type `EndpointAccess` with values `EndpointAccessAllow`, `EndpointAccessDeny`
- New enum type `EndpointTypes` with values `EndpointTypesIMDS`, `EndpointTypesWireServer`
- New enum type `GalleryApplicationScriptRebootBehavior` with values `GalleryApplicationScriptRebootBehaviorNone`, `GalleryApplicationScriptRebootBehaviorRerun`
- New enum type `SoftDeletedArtifactTypes` with values `SoftDeletedArtifactTypesImages`
- New enum type `ValidationStatus` with values `ValidationStatusFailed`, `ValidationStatusSucceeded`, `ValidationStatusUnknown`
- New function `*ClientFactory.NewGalleryInVMAccessControlProfileVersionsClient() *GalleryInVMAccessControlProfileVersionsClient`
- New function `*ClientFactory.NewGalleryInVMAccessControlProfilesClient() *GalleryInVMAccessControlProfilesClient`
- New function `*ClientFactory.NewSoftDeletedResourceClient() *SoftDeletedResourceClient`
- New function `NewGalleryInVMAccessControlProfileVersionsClient(string, azcore.TokenCredential, *arm.ClientOptions) (*GalleryInVMAccessControlProfileVersionsClient, error)`
- New function `*GalleryInVMAccessControlProfileVersionsClient.BeginCreateOrUpdate(context.Context, string, string, string, string, GalleryInVMAccessControlProfileVersion, *GalleryInVMAccessControlProfileVersionsClientBeginCreateOrUpdateOptions) (*runtime.Poller[GalleryInVMAccessControlProfileVersionsClientCreateOrUpdateResponse], error)`
- New function `*GalleryInVMAccessControlProfileVersionsClient.BeginDelete(context.Context, string, string, string, string, *GalleryInVMAccessControlProfileVersionsClientBeginDeleteOptions) (*runtime.Poller[GalleryInVMAccessControlProfileVersionsClientDeleteResponse], error)`
- New function `*GalleryInVMAccessControlProfileVersionsClient.Get(context.Context, string, string, string, string, *GalleryInVMAccessControlProfileVersionsClientGetOptions) (GalleryInVMAccessControlProfileVersionsClientGetResponse, error)`
- New function `*GalleryInVMAccessControlProfileVersionsClient.NewListByGalleryInVMAccessControlProfilePager(string, string, string, *GalleryInVMAccessControlProfileVersionsClientListByGalleryInVMAccessControlProfileOptions) *runtime.Pager[GalleryInVMAccessControlProfileVersionsClientListByGalleryInVMAccessControlProfileResponse]`
- New function `*GalleryInVMAccessControlProfileVersionsClient.BeginUpdate(context.Context, string, string, string, string, GalleryInVMAccessControlProfileVersionUpdate, *GalleryInVMAccessControlProfileVersionsClientBeginUpdateOptions) (*runtime.Poller[GalleryInVMAccessControlProfileVersionsClientUpdateResponse], error)`
- New function `NewGalleryInVMAccessControlProfilesClient(string, azcore.TokenCredential, *arm.ClientOptions) (*GalleryInVMAccessControlProfilesClient, error)`
- New function `*GalleryInVMAccessControlProfilesClient.BeginCreateOrUpdate(context.Context, string, string, string, GalleryInVMAccessControlProfile, *GalleryInVMAccessControlProfilesClientBeginCreateOrUpdateOptions) (*runtime.Poller[GalleryInVMAccessControlProfilesClientCreateOrUpdateResponse], error)`
- New function `*GalleryInVMAccessControlProfilesClient.BeginDelete(context.Context, string, string, string, *GalleryInVMAccessControlProfilesClientBeginDeleteOptions) (*runtime.Poller[GalleryInVMAccessControlProfilesClientDeleteResponse], error)`
- New function `*GalleryInVMAccessControlProfilesClient.Get(context.Context, string, string, string, *GalleryInVMAccessControlProfilesClientGetOptions) (GalleryInVMAccessControlProfilesClientGetResponse, error)`
- New function `*GalleryInVMAccessControlProfilesClient.NewListByGalleryPager(string, string, *GalleryInVMAccessControlProfilesClientListByGalleryOptions) *runtime.Pager[GalleryInVMAccessControlProfilesClientListByGalleryResponse]`
- New function `*GalleryInVMAccessControlProfilesClient.BeginUpdate(context.Context, string, string, string, GalleryInVMAccessControlProfileUpdate, *GalleryInVMAccessControlProfilesClientBeginUpdateOptions) (*runtime.Poller[GalleryInVMAccessControlProfilesClientUpdateResponse], error)`
- New function `NewSoftDeletedResourceClient(string, azcore.TokenCredential, *arm.ClientOptions) (*SoftDeletedResourceClient, error)`
- New function `*SoftDeletedResourceClient.NewListByArtifactNamePager(string, string, string, string, *SoftDeletedResourceClientListByArtifactNameOptions) *runtime.Pager[SoftDeletedResourceClientListByArtifactNameResponse]`
- New struct `AccessControlRules`
- New struct `AccessControlRulesIdentity`
- New struct `AccessControlRulesPrivilege`
- New struct `AccessControlRulesRole`
- New struct `AccessControlRulesRoleAssignment`
- New struct `AdditionalReplicaSet`
- New struct `ExecutedValidation`
- New struct `GalleryIdentity`
- New struct `GalleryInVMAccessControlProfile`
- New struct `GalleryInVMAccessControlProfileList`
- New struct `GalleryInVMAccessControlProfileProperties`
- New struct `GalleryInVMAccessControlProfileUpdate`
- New struct `GalleryInVMAccessControlProfileVersion`
- New struct `GalleryInVMAccessControlProfileVersionList`
- New struct `GalleryInVMAccessControlProfileVersionProperties`
- New struct `GalleryInVMAccessControlProfileVersionUpdate`
- New struct `GalleryResourceProfilePropertiesBase`
- New struct `GalleryResourceProfileVersionPropertiesBase`
- New struct `GallerySoftDeletedResource`
- New struct `GallerySoftDeletedResourceList`
- New struct `GallerySoftDeletedResourceProperties`
- New struct `PlatformAttribute`
- New struct `ValidationsProfile`
- New field `Identity` in struct `Gallery`
- New field `StartsAtVersion` in struct `GalleryImageFeature`
- New field `AllowUpdateImage` in struct `GalleryImageProperties`
- New field `Restore`, `ValidationsProfile` in struct `GalleryImageVersionProperties`
- New field `BlockDeletionBeforeEndOfLife` in struct `GalleryImageVersionSafetyProfile`
- New field `SecurityProfile` in struct `GalleryList`
- New field `Identity` in struct `GalleryUpdate`
- New field `AdditionalReplicaSets` in struct `TargetRegion`
- New field `ScriptBehaviorAfterReboot` in struct `UserArtifactSettings`


## 6.1.0 (2024-08-23)
### Features Added

- New enum type `AllocationStrategy` with values `AllocationStrategyCapacityOptimized`, `AllocationStrategyLowestPrice`
- New enum type `ZonalPlatformFaultDomainAlignMode` with values `ZonalPlatformFaultDomainAlignModeAligned`, `ZonalPlatformFaultDomainAlignModeUnaligned`
- New struct `SKUProfile`
- New struct `SKUProfileVMSize`
- New field `ScheduledEventsPolicy` in struct `AvailabilitySetProperties`
- New field `LogicalSectorSize` in struct `DiskRestorePointProperties`
- New field `SKUProfile`, `ZonalPlatformFaultDomainAlignMode` in struct `VirtualMachineScaleSetProperties`
- New field `Zones` in struct `VirtualMachineScaleSetUpdate`
- New field `SKUProfile`, `ZonalPlatformFaultDomainAlignMode` in struct `VirtualMachineScaleSetUpdateProperties`


## 6.0.0 (2024-07-26)
### Breaking Changes

- Type of `SecurityPostureReference.ExcludeExtensions` has been changed from `[]*VirtualMachineExtension` to `[]*string`

### Features Added

- New struct `SecurityPostureReferenceUpdate`
- New field `IsOverridable` in struct `SecurityPostureReference`
- New field `SecurityPostureReference` in struct `VirtualMachineScaleSetUpdateVMProfile`


## 5.7.0 (2024-04-26)
### Features Added

- New value `DiffDiskPlacementNvmeDisk` added to enum type `DiffDiskPlacement`
- New value `DiskCreateOptionTypesCopy`, `DiskCreateOptionTypesRestore` added to enum type `DiskCreateOptionTypes`
- New enum type `ResourceIDOptionsForGetCapacityReservationGroups` with values `ResourceIDOptionsForGetCapacityReservationGroupsAll`, `ResourceIDOptionsForGetCapacityReservationGroupsCreatedInSubscription`, `ResourceIDOptionsForGetCapacityReservationGroupsSharedWithSubscription`
- New struct `EventGridAndResourceGraph`
- New struct `ScheduledEventsAdditionalPublishingTargets`
- New struct `ScheduledEventsPolicy`
- New struct `UserInitiatedReboot`
- New struct `UserInitiatedRedeploy`
- New field `ResourceIDsOnly` in struct `CapacityReservationGroupsClientListBySubscriptionOptions`
- New field `SourceResource` in struct `DataDisk`
- New field `Caching`, `DeleteOption`, `DiskEncryptionSet`, `WriteAcceleratorEnabled` in struct `DataDisksToAttach`
- New field `ScheduledEventsPolicy` in struct `VirtualMachineProperties`
- New field `ScheduledEventsPolicy` in struct `VirtualMachineScaleSetProperties`
- New field `ForceUpdateOSDiskForEphemeral` in struct `VirtualMachineScaleSetReimageParameters`
- New field `DiffDiskSettings` in struct `VirtualMachineScaleSetUpdateOSDisk`
- New field `ForceUpdateOSDiskForEphemeral` in struct `VirtualMachineScaleSetVMReimageParameters`


## 5.6.0 (2024-03-22)
### Features Added

- New field `VirtualMachineID` in struct `GalleryArtifactVersionFullSource`


## 5.5.0 (2024-01-26)
### Features Added

- New value `DiskSecurityTypesConfidentialVMNonPersistedTPM` added to enum type `DiskSecurityTypes`
- New enum type `ProvisionedBandwidthCopyOption` with values `ProvisionedBandwidthCopyOptionEnhanced`, `ProvisionedBandwidthCopyOptionNone`
- New field `ProvisionedBandwidthCopySpeed` in struct `CreationData`


## 5.4.0 (2023-12-22)
### Features Added

- New value `ConfidentialVMEncryptionTypeNonPersistedTPM` added to enum type `ConfidentialVMEncryptionType`
- New value `ReplicationStatusTypesUefiSettings` added to enum type `ReplicationStatusTypes`
- New value `SecurityEncryptionTypesNonPersistedTPM` added to enum type `SecurityEncryptionTypes`
- New enum type `Mode` with values `ModeAudit`, `ModeEnforce`
- New enum type `SSHEncryptionTypes` with values `SSHEncryptionTypesEd25519`, `SSHEncryptionTypesRSA`
- New enum type `UefiKeyType` with values `UefiKeyTypeSHA256`, `UefiKeyTypeX509`
- New enum type `UefiSignatureTemplateName` with values `UefiSignatureTemplateNameMicrosoftUefiCertificateAuthorityTemplate`, `UefiSignatureTemplateNameMicrosoftWindowsTemplate`, `UefiSignatureTemplateNameNoSignatureTemplate`
- New function `*DedicatedHostsClient.BeginRedeploy(context.Context, string, string, string, *DedicatedHostsClientBeginRedeployOptions) (*runtime.Poller[DedicatedHostsClientRedeployResponse], error)`
- New function `*VirtualMachineScaleSetVMsClient.BeginApproveRollingUpgrade(context.Context, string, string, string, *VirtualMachineScaleSetVMsClientBeginApproveRollingUpgradeOptions) (*runtime.Poller[VirtualMachineScaleSetVMsClientApproveRollingUpgradeResponse], error)`
- New function `*VirtualMachineScaleSetVMsClient.BeginAttachDetachDataDisks(context.Context, string, string, string, AttachDetachDataDisksRequest, *VirtualMachineScaleSetVMsClientBeginAttachDetachDataDisksOptions) (*runtime.Poller[VirtualMachineScaleSetVMsClientAttachDetachDataDisksResponse], error)`
- New function `*VirtualMachineScaleSetsClient.BeginApproveRollingUpgrade(context.Context, string, string, *VirtualMachineScaleSetsClientBeginApproveRollingUpgradeOptions) (*runtime.Poller[VirtualMachineScaleSetsClientApproveRollingUpgradeResponse], error)`
- New function `*VirtualMachinesClient.BeginAttachDetachDataDisks(context.Context, string, string, AttachDetachDataDisksRequest, *VirtualMachinesClientBeginAttachDetachDataDisksOptions) (*runtime.Poller[VirtualMachinesClientAttachDetachDataDisksResponse], error)`
- New struct `AttachDetachDataDisksRequest`
- New struct `CommunityGalleryMetadata`
- New struct `CommunityGalleryProperties`
- New struct `DataDisksToAttach`
- New struct `DataDisksToDetach`
- New struct `EncryptionIdentity`
- New struct `GalleryImageVersionUefiSettings`
- New struct `ImageVersionSecurityProfile`
- New struct `ProxyAgentSettings`
- New struct `ResiliencyPolicy`
- New struct `ResilientVMCreationPolicy`
- New struct `ResilientVMDeletionPolicy`
- New struct `ResourceSharingProfile`
- New struct `SSHGenerateKeyPairInputParameters`
- New struct `SharedGalleryProperties`
- New struct `UefiKey`
- New struct `UefiKeySignatures`
- New field `OSRollingUpgradeDeferral` in struct `AutomaticOSUpgradePolicy`
- New field `SharedSubscriptionIDs` in struct `CapacityReservationGroupInstanceView`
- New field `SharingProfile` in struct `CapacityReservationGroupProperties`
- New field `Properties` in struct `CommunityGallery`
- New field `ArtifactTags`, `Disclaimer` in struct `CommunityGalleryImageProperties`
- New field `ArtifactTags`, `Disclaimer` in struct `CommunityGalleryImageVersionProperties`
- New field `SecurityProfile` in struct `GalleryImageVersionProperties`
- New field `DiskControllerType` in struct `RestorePointSourceVMStorageProfile`
- New field `Parameters` in struct `SSHPublicKeysClientGenerateKeyPairOptions`
- New field `EncryptionIdentity`, `ProxyAgentSettings` in struct `SecurityProfile`
- New field `Properties` in struct `SharedGallery`
- New field `ArtifactTags` in struct `SharedGalleryImageProperties`
- New field `ArtifactTags` in struct `SharedGalleryImageVersionProperties`
- New field `Etag`, `ManagedBy` in struct `VirtualMachine`
- New field `IsVMInStandbyPool` in struct `VirtualMachineInstanceView`
- New field `Etag` in struct `VirtualMachineScaleSet`
- New field `ResiliencyPolicy` in struct `VirtualMachineScaleSetProperties`
- New field `ResiliencyPolicy` in struct `VirtualMachineScaleSetUpdateProperties`
- New field `Etag` in struct `VirtualMachineScaleSetVM`
- New field `TimeCreated` in struct `VirtualMachineScaleSetVMProfile`
- New field `IfMatch`, `IfNoneMatch` in struct `VirtualMachineScaleSetVMsClientBeginUpdateOptions`
- New field `IfMatch`, `IfNoneMatch` in struct `VirtualMachineScaleSetsClientBeginCreateOrUpdateOptions`
- New field `IfMatch`, `IfNoneMatch` in struct `VirtualMachineScaleSetsClientBeginUpdateOptions`
- New field `IfMatch`, `IfNoneMatch` in struct `VirtualMachinesClientBeginCreateOrUpdateOptions`
- New field `IfMatch`, `IfNoneMatch` in struct `VirtualMachinesClientBeginUpdateOptions`


## 5.3.0 (2023-11-24)
### Features Added

- Support for test fakes and OpenTelemetry trace spans.


## 5.3.0-beta.2 (2023-10-30)

### Other Changes

- Updated with latest code generator to fix a few issues in fakes.

## 5.3.0-beta.1 (2023-10-09)
### Features Added

- Support for test fakes and OpenTelemetry trace spans.

## 5.2.0 (2023-09-22)
### Features Added

- New value `DiskCreateOptionCopyFromSanSnapshot` added to enum type `DiskCreateOption`
- New enum type `DomainNameLabelScopeTypes` with values `DomainNameLabelScopeTypesNoReuse`, `DomainNameLabelScopeTypesResourceGroupReuse`, `DomainNameLabelScopeTypesSubscriptionReuse`, `DomainNameLabelScopeTypesTenantReuse`
- New enum type `NetworkInterfaceAuxiliaryMode` with values `NetworkInterfaceAuxiliaryModeAcceleratedConnections`, `NetworkInterfaceAuxiliaryModeFloating`, `NetworkInterfaceAuxiliaryModeNone`
- New enum type `NetworkInterfaceAuxiliarySKU` with values `NetworkInterfaceAuxiliarySKUA1`, `NetworkInterfaceAuxiliarySKUA2`, `NetworkInterfaceAuxiliarySKUA4`, `NetworkInterfaceAuxiliarySKUA8`, `NetworkInterfaceAuxiliarySKUNone`
- New field `ElasticSanResourceID` in struct `CreationData`
- New field `LastOwnershipUpdateTime` in struct `DiskProperties`
- New field `AuxiliaryMode`, `AuxiliarySKU` in struct `VirtualMachineNetworkInterfaceConfigurationProperties`
- New field `DomainNameLabelScope` in struct `VirtualMachinePublicIPAddressDNSSettingsConfiguration`
- New field `AuxiliaryMode`, `AuxiliarySKU` in struct `VirtualMachineScaleSetNetworkConfigurationProperties`
- New field `DomainNameLabelScope` in struct `VirtualMachineScaleSetPublicIPAddressConfigurationDNSSettings`
- New field `AuxiliaryMode`, `AuxiliarySKU` in struct `VirtualMachineScaleSetUpdateNetworkConfigurationProperties`
- New field `TimeCreated` in struct `VirtualMachineScaleSetVMProperties`


## 5.1.0 (2023-07-28)
### Features Added

- New enum type `FileFormat` with values `FileFormatVHD`, `FileFormatVHDX`
- New field `FileFormat` in struct `GrantAccessData`


## 5.0.0 (2023-05-26)
### Breaking Changes

- Type of `CommunityGalleryImageProperties.Identifier` has been changed from `*GalleryImageIdentifier` to `*CommunityGalleryImageIdentifier`
- Type of `GalleryTargetExtendedLocation.StorageAccountType` has been changed from `*StorageAccountType` to `*EdgeZoneStorageAccountType`
- Type of `RestorePointSourceVMDataDisk.DiskRestorePoint` has been changed from `*APIEntityReference` to `*DiskRestorePointAttributes`
- Type of `RestorePointSourceVMOSDisk.DiskRestorePoint` has been changed from `*APIEntityReference` to `*DiskRestorePointAttributes`
- `StorageAccountTypeStandardSSDLRS` from enum `StorageAccountType` has been removed
- Field `ID` of struct `VirtualMachineScaleSetIPConfiguration` has been removed
- Field `ID` of struct `VirtualMachineScaleSetNetworkConfiguration` has been removed
- Field `ID` of struct `VirtualMachineScaleSetUpdateIPConfiguration` has been removed
- Field `ID` of struct `VirtualMachineScaleSetUpdateNetworkConfiguration` has been removed

### Features Added

- New enum type `EdgeZoneStorageAccountType` with values `EdgeZoneStorageAccountTypePremiumLRS`, `EdgeZoneStorageAccountTypeStandardLRS`, `EdgeZoneStorageAccountTypeStandardSSDLRS`, `EdgeZoneStorageAccountTypeStandardZRS`
- New enum type `ExpandTypeForListVMs` with values `ExpandTypeForListVMsInstanceView`
- New enum type `ExpandTypesForListVMs` with values `ExpandTypesForListVMsInstanceView`
- New enum type `RestorePointEncryptionType` with values `RestorePointEncryptionTypeEncryptionAtRestWithCustomerKey`, `RestorePointEncryptionTypeEncryptionAtRestWithPlatformAndCustomerKeys`, `RestorePointEncryptionTypeEncryptionAtRestWithPlatformKey`
- New function `*DedicatedHostsClient.NewListAvailableSizesPager(string, string, string, *DedicatedHostsClientListAvailableSizesOptions) *runtime.Pager[DedicatedHostsClientListAvailableSizesResponse]`
- New function `*VirtualMachineScaleSetsClient.BeginReapply(context.Context, string, string, *VirtualMachineScaleSetsClientBeginReapplyOptions) (*runtime.Poller[VirtualMachineScaleSetsClientReapplyResponse], error)`
- New struct `CommunityGalleryImageIdentifier`
- New struct `DedicatedHostSizeListResult`
- New struct `DiskRestorePointAttributes`
- New struct `RestorePointEncryption`
- New struct `RunCommandManagedIdentity`
- New struct `SecurityPostureReference`
- New field `SKU` in struct `DedicatedHostUpdate`
- New field `BypassPlatformSafetyChecksOnUserSchedule` in struct `LinuxVMGuestPatchAutomaticByPlatformSettings`
- New field `HyperVGeneration` in struct `RestorePointSourceMetadata`
- New field `WriteAcceleratorEnabled` in struct `RestorePointSourceVMDataDisk`
- New field `WriteAcceleratorEnabled` in struct `RestorePointSourceVMOSDisk`
- New field `ProvisionAfterExtensions` in struct `VirtualMachineExtensionProperties`
- New field `ErrorBlobManagedIdentity`, `OutputBlobManagedIdentity`, `TreatFailureAsDeploymentFailure` in struct `VirtualMachineRunCommandProperties`
- New field `ScriptURIManagedIdentity` in struct `VirtualMachineRunCommandScriptSource`
- New field `PriorityMixPolicy`, `SpotRestorePolicy` in struct `VirtualMachineScaleSetUpdateProperties`
- New field `Location` in struct `VirtualMachineScaleSetVMExtension`
- New field `SecurityPostureReference` in struct `VirtualMachineScaleSetVMProfile`
- New field `Hibernate` in struct `VirtualMachineScaleSetsClientBeginDeallocateOptions`
- New field `Expand` in struct `VirtualMachinesClientListAllOptions`
- New field `Expand` in struct `VirtualMachinesClientListOptions`
- New field `BypassPlatformSafetyChecksOnUserSchedule` in struct `WindowsVMGuestPatchAutomaticByPlatformSettings`


## 4.2.1 (2023-04-14)
### Bug Fixes

- Fix serialization bug of empty value of `any` type.


## 4.2.0 (2023-03-27)
### Features Added

- New struct `ClientFactory` which is a client factory used to create any client in this module
- New value `StorageAccountTypeStandardSSDLRS` added to enum type `StorageAccountType`
- New field `ComputerName` in struct `VirtualMachineScaleSetVMInstanceView`
- New field `HyperVGeneration` in struct `VirtualMachineScaleSetVMInstanceView`
- New field `OSName` in struct `VirtualMachineScaleSetVMInstanceView`
- New field `OSVersion` in struct `VirtualMachineScaleSetVMInstanceView`


## 4.1.0 (2023-01-27)
### Features Added

- New type alias `AlternativeType` with values `AlternativeTypeNone`, `AlternativeTypeOffer`, `AlternativeTypePlan`
- New type alias `ImageState` with values `ImageStateActive`, `ImageStateDeprecated`, `ImageStateScheduledForDeprecation`
- New struct `AlternativeOption`
- New struct `ImageDeprecationStatus`
- New struct `OSImageNotificationProfile`
- New struct `OSProfileProvisioningData`
- New struct `ServiceArtifactReference`
- New field `Zones` in struct `CloudService`
- New field `UserData` in struct `RestorePointSourceMetadata`
- New field `MaxSurge` in struct `RollingUpgradePolicy`
- New field `RollbackFailedInstancesOnPolicyBreach` in struct `RollingUpgradePolicy`
- New field `OSImageNotificationProfile` in struct `ScheduledEventsProfile`
- New field `ImageDeprecationStatus` in struct `VirtualMachineImageProperties`
- New field `ExactVersion` in struct `VirtualMachineReimageParameters`
- New field `OSProfile` in struct `VirtualMachineReimageParameters`
- New field `RequireGuestProvisionSignal` in struct `VirtualMachineScaleSetOSProfile`
- New field `ConstrainedMaximumCapacity` in struct `VirtualMachineScaleSetProperties`
- New field `ExactVersion` in struct `VirtualMachineScaleSetReimageParameters`
- New field `OSProfile` in struct `VirtualMachineScaleSetReimageParameters`
- New field `ServiceArtifactReference` in struct `VirtualMachineScaleSetVMProfile`
- New field `ExactVersion` in struct `VirtualMachineScaleSetVMReimageParameters`
- New field `OSProfile` in struct `VirtualMachineScaleSetVMReimageParameters`


## 4.0.0 (2022-10-04)
### Breaking Changes

- Type of `GalleryImageVersionStorageProfile.Source` has been changed from `*GalleryArtifactVersionSource` to `*GalleryArtifactVersionFullSource`
- Type of `SharingProfile.CommunityGalleryInfo` has been changed from `interface{}` to `*CommunityGalleryInfo`
- Type of `VirtualMachineExtensionUpdateProperties.ProtectedSettingsFromKeyVault` has been changed from `interface{}` to `*KeyVaultSecretReference`
- Type of `GalleryOSDiskImage.Source` has been changed from `*GalleryArtifactVersionSource` to `*GalleryDiskImageSource`
- Type of `GalleryDiskImage.Source` has been changed from `*GalleryArtifactVersionSource` to `*GalleryDiskImageSource`
- Type of `GalleryDataDiskImage.Source` has been changed from `*GalleryArtifactVersionSource` to `*GalleryDiskImageSource`
- Type of `VirtualMachineScaleSetExtensionProperties.ProtectedSettingsFromKeyVault` has been changed from `interface{}` to `*KeyVaultSecretReference`
- Type of `VirtualMachineExtensionProperties.ProtectedSettingsFromKeyVault` has been changed from `interface{}` to `*KeyVaultSecretReference`
- Field `URI` of struct `GalleryArtifactVersionSource` has been removed

### Features Added

- New const `DiskControllerTypesSCSI`
- New const `PolicyViolationCategoryImageFlaggedUnsafe`
- New const `GalleryApplicationCustomActionParameterTypeConfigurationDataBlob`
- New const `PolicyViolationCategoryIPTheft`
- New const `PolicyViolationCategoryCopyrightValidation`
- New const `PolicyViolationCategoryOther`
- New const `GalleryApplicationCustomActionParameterTypeString`
- New const `DiskControllerTypesNVMe`
- New const `GalleryApplicationCustomActionParameterTypeLogOutputBlob`
- New type alias `DiskControllerTypes`
- New type alias `PolicyViolationCategory`
- New type alias `GalleryApplicationCustomActionParameterType`
- New function `PossiblePolicyViolationCategoryValues() []PolicyViolationCategory`
- New function `PossibleGalleryApplicationCustomActionParameterTypeValues() []GalleryApplicationCustomActionParameterType`
- New function `PossibleDiskControllerTypesValues() []DiskControllerTypes`
- New struct `GalleryApplicationCustomAction`
- New struct `GalleryApplicationCustomActionParameter`
- New struct `GalleryApplicationVersionSafetyProfile`
- New struct `GalleryArtifactSafetyProfileBase`
- New struct `GalleryArtifactVersionFullSource`
- New struct `GalleryDiskImageSource`
- New struct `GalleryImageVersionSafetyProfile`
- New struct `LatestGalleryImageVersion`
- New struct `PolicyViolation`
- New struct `PriorityMixPolicy`
- New field `DiskControllerType` in struct `VirtualMachineScaleSetUpdateStorageProfile`
- New field `HardwareProfile` in struct `VirtualMachineScaleSetUpdateVMProfile`
- New field `CustomActions` in struct `GalleryApplicationProperties`
- New field `DisableTCPStateTracking` in struct `VirtualMachineScaleSetNetworkConfigurationProperties`
- New field `DiskControllerType` in struct `StorageProfile`
- New field `OptimizedForFrequentAttach` in struct `DiskProperties`
- New field `BurstingEnabledTime` in struct `DiskProperties`
- New field `DiskControllerTypes` in struct `SupportedCapabilities`
- New field `DisableTCPStateTracking` in struct `VirtualMachineNetworkInterfaceConfigurationProperties`
- New field `EnableVMAgentPlatformUpdates` in struct `WindowsConfiguration`
- New field `PerformancePlus` in struct `CreationData`
- New field `IncrementalSnapshotFamilyID` in struct `SnapshotProperties`
- New field `OptimizedForFrequentAttach` in struct `DiskUpdateProperties`
- New field `DisableTCPStateTracking` in struct `VirtualMachineScaleSetUpdateNetworkConfigurationProperties`
- New field `ExcludeFromLatest` in struct `TargetRegion`
- New field `PrivacyStatementURI` in struct `SharedGalleryImageProperties`
- New field `Eula` in struct `SharedGalleryImageProperties`
- New field `SafetyProfile` in struct `GalleryApplicationVersionProperties`
- New field `SafetyProfile` in struct `GalleryImageVersionProperties`
- New field `EnableVMAgentPlatformUpdates` in struct `LinuxConfiguration`
- New field `CurrentCapacity` in struct `CapacityReservationUtilization`
- New field `PriorityMixPolicy` in struct `VirtualMachineScaleSetProperties`
- New field `CustomActions` in struct `GalleryApplicationVersionPublishingProfile`
- New field `PlatformFaultDomainCount` in struct `CapacityReservationProperties`
- New field `DiskControllerType` in struct `VirtualMachineScaleSetStorageProfile`


## 3.0.1 (2022-07-29)
### Other Changes
- Fix wrong module import for live test

## 3.0.0 (2022-06-24)
### Breaking Changes

- Function `*CloudServicesClient.BeginCreateOrUpdate` parameter(s) have been changed from `(context.Context, string, string, *CloudServicesClientBeginCreateOrUpdateOptions)` to `(context.Context, string, string, CloudService, *CloudServicesClientBeginCreateOrUpdateOptions)`
- Function `*CloudServicesClient.BeginUpdate` parameter(s) have been changed from `(context.Context, string, string, *CloudServicesClientBeginUpdateOptions)` to `(context.Context, string, string, CloudServiceUpdate, *CloudServicesClientBeginUpdateOptions)`
- Function `*CloudServicesUpdateDomainClient.BeginWalkUpdateDomain` parameter(s) have been changed from `(context.Context, string, string, int32, *CloudServicesUpdateDomainClientBeginWalkUpdateDomainOptions)` to `(context.Context, string, string, int32, UpdateDomain, *CloudServicesUpdateDomainClientBeginWalkUpdateDomainOptions)`
- Type of `CloudServiceExtensionProperties.Settings` has been changed from `*string` to `interface{}`
- Type of `CloudServiceExtensionProperties.ProtectedSettings` has been changed from `*string` to `interface{}`
- Field `Parameters` of struct `CloudServicesClientBeginUpdateOptions` has been removed
- Field `Parameters` of struct `CloudServicesClientBeginCreateOrUpdateOptions` has been removed
- Field `Parameters` of struct `CloudServicesUpdateDomainClientBeginWalkUpdateDomainOptions` has been removed

### Features Added

- New const `CloudServiceSlotTypeProduction`
- New const `CloudServiceSlotTypeStaging`
- New function `*VirtualMachineImagesClient.ListByEdgeZone(context.Context, string, string, *VirtualMachineImagesClientListByEdgeZoneOptions) (VirtualMachineImagesClientListByEdgeZoneResponse, error)`
- New function `PossibleCloudServiceSlotTypeValues() []CloudServiceSlotType`
- New struct `SystemData`
- New struct `VMImagesInEdgeZoneListResult`
- New struct `VirtualMachineImagesClientListByEdgeZoneOptions`
- New struct `VirtualMachineImagesClientListByEdgeZoneResponse`
- New field `SystemData` in struct `CloudService`
- New field `SlotType` in struct `CloudServiceNetworkProfile`


## 2.0.0 (2022-06-02)
### Breaking Changes

- Type of `GalleryProperties.ProvisioningState` has been changed from `*GalleryPropertiesProvisioningState` to `*GalleryProvisioningState`
- Type of `GalleryImageVersionProperties.ProvisioningState` has been changed from `*GalleryImageVersionPropertiesProvisioningState` to `*GalleryProvisioningState`
- Type of `GalleryImageProperties.ProvisioningState` has been changed from `*GalleryImagePropertiesProvisioningState` to `*GalleryProvisioningState`
- Type of `GalleryApplicationVersionProperties.ProvisioningState` has been changed from `*GalleryApplicationVersionPropertiesProvisioningState` to `*GalleryProvisioningState`
- Type of `VirtualMachineScaleSetIdentity.UserAssignedIdentities` has been changed from `map[string]*VirtualMachineScaleSetIdentityUserAssignedIdentitiesValue` to `map[string]*UserAssignedIdentitiesValue`
- Const `GalleryImagePropertiesProvisioningStateFailed` has been removed
- Const `GalleryImagePropertiesProvisioningStateMigrating` has been removed
- Const `GalleryImageVersionPropertiesProvisioningStateCreating` has been removed
- Const `GalleryImageVersionPropertiesProvisioningStateMigrating` has been removed
- Const `GalleryApplicationVersionPropertiesProvisioningStateFailed` has been removed
- Const `GalleryPropertiesProvisioningStateMigrating` has been removed
- Const `GalleryApplicationVersionPropertiesProvisioningStateDeleting` has been removed
- Const `GalleryPropertiesProvisioningStateDeleting` has been removed
- Const `GalleryApplicationVersionPropertiesProvisioningStateCreating` has been removed
- Const `GalleryImageVersionPropertiesProvisioningStateSucceeded` has been removed
- Const `GalleryImagePropertiesProvisioningStateCreating` has been removed
- Const `GalleryImagePropertiesProvisioningStateUpdating` has been removed
- Const `GalleryImageVersionPropertiesProvisioningStateDeleting` has been removed
- Const `GalleryPropertiesProvisioningStateFailed` has been removed
- Const `SharingProfileGroupTypesCommunity` has been removed
- Const `GalleryApplicationVersionPropertiesProvisioningStateSucceeded` has been removed
- Const `GalleryApplicationVersionPropertiesProvisioningStateMigrating` has been removed
- Const `GalleryPropertiesProvisioningStateUpdating` has been removed
- Const `GalleryImageVersionPropertiesProvisioningStateFailed` has been removed
- Const `GalleryImagePropertiesProvisioningStateDeleting` has been removed
- Const `GalleryImageVersionPropertiesProvisioningStateUpdating` has been removed
- Const `GalleryPropertiesProvisioningStateCreating` has been removed
- Const `GalleryApplicationVersionPropertiesProvisioningStateUpdating` has been removed
- Const `GalleryImagePropertiesProvisioningStateSucceeded` has been removed
- Const `GalleryPropertiesProvisioningStateSucceeded` has been removed
- Function `PossibleGalleryPropertiesProvisioningStateValues` has been removed
- Function `PossibleGalleryImageVersionPropertiesProvisioningStateValues` has been removed
- Function `PossibleGalleryImagePropertiesProvisioningStateValues` has been removed
- Function `PossibleGalleryApplicationVersionPropertiesProvisioningStateValues` has been removed
- Struct `VirtualMachineScaleSetIdentityUserAssignedIdentitiesValue` has been removed

### Features Added

- New const `GallerySharingPermissionTypesCommunity`
- New const `GalleryProvisioningStateUpdating`
- New const `SharedGalleryHostCachingReadOnly`
- New const `SharedGalleryHostCachingNone`
- New const `GalleryProvisioningStateSucceeded`
- New const `GalleryProvisioningStateFailed`
- New const `SharedGalleryHostCachingReadWrite`
- New const `GalleryProvisioningStateCreating`
- New const `DiskEncryptionSetIdentityTypeUserAssigned`
- New const `GalleryProvisioningStateMigrating`
- New const `DiskEncryptionSetIdentityTypeSystemAssignedUserAssigned`
- New const `CopyCompletionErrorReasonCopySourceNotFound`
- New const `GalleryProvisioningStateDeleting`
- New const `DiskStorageAccountTypesPremiumV2LRS`
- New function `PossibleCopyCompletionErrorReasonValues() []CopyCompletionErrorReason`
- New function `PossibleSharedGalleryHostCachingValues() []SharedGalleryHostCaching`
- New function `PossibleGalleryProvisioningStateValues() []GalleryProvisioningState`
- New function `EncryptionSetIdentity.MarshalJSON() ([]byte, error)`
- New function `*CommunityGalleryImagesClient.NewListPager(string, string, *CommunityGalleryImagesClientListOptions) *runtime.Pager[CommunityGalleryImagesClientListResponse]`
- New function `*CommunityGalleryImageVersionsClient.NewListPager(string, string, string, *CommunityGalleryImageVersionsClientListOptions) *runtime.Pager[CommunityGalleryImageVersionsClientListResponse]`
- New struct `CommunityGalleryImageList`
- New struct `CommunityGalleryImageVersionList`
- New struct `CommunityGalleryImageVersionsClientListOptions`
- New struct `CommunityGalleryImageVersionsClientListResponse`
- New struct `CommunityGalleryImagesClientListOptions`
- New struct `CommunityGalleryImagesClientListResponse`
- New struct `CopyCompletionError`
- New struct `SharedGalleryDataDiskImage`
- New struct `SharedGalleryDiskImage`
- New struct `SharedGalleryImageVersionStorageProfile`
- New struct `SharedGalleryOSDiskImage`
- New struct `UserArtifactSettings`
- New field `SharedGalleryImageID` in struct `ImageDiskReference`
- New field `CommunityGalleryImageID` in struct `ImageDiskReference`
- New field `AdvancedSettings` in struct `GalleryApplicationVersionPublishingProfile`
- New field `Settings` in struct `GalleryApplicationVersionPublishingProfile`
- New field `CopyCompletionError` in struct `SnapshotProperties`
- New field `ExcludeFromLatest` in struct `SharedGalleryImageVersionProperties`
- New field `StorageProfile` in struct `SharedGalleryImageVersionProperties`
- New field `ExcludeFromLatest` in struct `CommunityGalleryImageVersionProperties`
- New field `StorageProfile` in struct `CommunityGalleryImageVersionProperties`
- New field `Architecture` in struct `SharedGalleryImageProperties`
- New field `UserAssignedIdentities` in struct `EncryptionSetIdentity`
- New field `Eula` in struct `CommunityGalleryImageProperties`
- New field `PrivacyStatementURI` in struct `CommunityGalleryImageProperties`
- New field `Architecture` in struct `CommunityGalleryImageProperties`
- New field `FederatedClientID` in struct `DiskEncryptionSetUpdateProperties`
- New field `FederatedClientID` in struct `EncryptionSetProperties`
- New field `SecurityProfile` in struct `DiskRestorePointProperties`


## 1.0.0 (2022-05-16)

The package of `github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/compute/armcompute` is using our [next generation design principles](https://azure.github.io/azure-sdk/general_introduction.html) since version 1.0.0, which contains breaking changes.

To migrate the existing applications to the latest version, please refer to [Migration Guide](https://aka.ms/azsdk/go/mgmt/migration).

To learn more, please refer to our documentation [Quick Start](https://aka.ms/azsdk/go/mgmt).

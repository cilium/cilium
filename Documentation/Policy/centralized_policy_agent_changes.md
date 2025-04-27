# Design Document: Centralized Policy Resolution for Cilium Agent

## Overview

This design document outlines the necessary changes to the Cilium agent to support centralized policy resolution. Currently, each Cilium agent (running as a DaemonSet) independently watches policy events, computes the mapping between rules and affected identities, and applies these policies. This redundant computation across all agents causes significant resource overhead and increased load on the Kubernetes API server, especially in large clusters.

The centralized policy resolution approach aims to:
1. Reduce redundant policy computation
2. Decrease load on the Kubernetes API server
3. Improve scalability in large clusters
4. Minimize resource utilization

## Current Architecture

In the existing architecture, each Cilium agent:
1. Watches for policy events via the PolicyWatcher
2. Processes these events through the PolicyImporter
3. Updates the PolicyRepository with new rules
4. Maps rules to identities using SelectorCache
5. Regenerates endpoints as needed

The key bottleneck is that the mapping of rules to identities happens independently in every agent, causing redundant computation.

## Proposed Changes

### New CRD: CiliumResolvedPolicy

We will introduce a new CRD called `CiliumResolvedPolicy` that will contain pre-computed mappings between rules and identities:

```yaml
apiVersion: cilium.io/v1alpha1
kind: CiliumResolvedPolicy
metadata:
  name: resolved-policy-{hash}
spec:
  policyRevision: 123
  rules:
    - selector: ...
      affectedIdentities: [1234, 5678, ...]
      ingress: ...
      egress: ...
      cidrPrefixes: [...]
    - selector: ...
      affectedIdentities: [91011, 121314, ...]
      ingress: ...
      egress: ...
  sourceRef:
    kind: CiliumNetworkPolicy
    name: original-policy
    namespace: default
    resourceVersion: "12345"
status:
  processed: true
  processingTime: "2025-04-27T12:00:00Z"
```

### Changes to PolicyWatcher in pkg/policy/k8s/cell.go

The existing policy watcher in `startK8sPolicyWatcher` function needs to be extended to support watching for CiliumResolvedPolicy resources when centralized mode is enabled:

```go
func startK8sPolicyWatcher(params PolicyWatcherParams) {
    if !params.ClientSet.IsEnabled() {
        return // skip watcher if K8s is not enabled
    }

    // We want to subscribe before the start hook is invoked in order to not miss
    // any events
    ctx, cancel := context.WithCancel(context.Background())

    p := &policyWatcher{
        log:                              params.Logger,
        config:                           params.Config,
        policyImporter:                   params.PolicyImporter,
        k8sResourceSynced:                params.K8sResourceSynced,
        k8sAPIGroups:                     params.K8sAPIGroups,
        svcCache:                         params.ServiceCache,
        ipCache:                          params.IPCache,
        ciliumNetworkPolicies:            params.CiliumNetworkPolicies,
        ciliumClusterwideNetworkPolicies: params.CiliumClusterwideNetworkPolicies,
        ciliumCIDRGroups:                 params.CiliumCIDRGroups,
        ciliumResolvedPolicies:           params.CiliumResolvedPolicies, // New field for resolved policies
        networkPolicies:                  params.NetworkPolicies,

        cnpCache:       make(map[resource.Key]*types.SlimCNP),
        cidrGroupCache: make(map[string]*cilium_v2_alpha1.CiliumCIDRGroup),
        cidrGroupCIDRs: make(map[string]sets.Set[netip.Prefix]),

        toServicesPolicies: make(map[resource.Key]struct{}),
        cnpByServiceID:     make(map[k8s.ServiceID]map[resource.Key]struct{}),
        metricsManager:     params.MetricsManager,
    }

    // Service notifications are not used if CNPs/CCNPs are disabled.
    if params.Config.EnableCiliumNetworkPolicy || params.Config.EnableCiliumClusterwideNetworkPolicy {
        p.svcCacheNotifications = serviceNotificationsQueue(ctx, params.ServiceCache.Notifications())
    }

    params.Lifecycle.Append(cell.Hook{
        OnStart: func(startCtx cell.HookContext) error {
            p.watchResources(ctx)
            return nil
        },
        OnStop: func(cell.HookContext) error {
            if cancel != nil {
                cancel()
            }
            return nil
        },
    })

    // Register watchers based on the centralized policy resolution mode
    if params.Config.CentralizedPolicyResolution {
        // When centralized mode is enabled, we ONLY watch for resolved policies
        // and disable ALL other policy watchers to reduce load on the API server
        p.resolvedPolicySyncPending.Store(1)
        p.registerResourceWithSyncFn(ctx, k8sAPIGroupCiliumResolvedPolicyV1Alpha1, func() bool {
            return p.resolvedPolicySyncPending.Load() == 0
        })
        
        // CIDR Groups are not needed in centralized mode because the resolved policies 
        // already contain the pre-computed CIDR information
    } else {
        // In distributed mode, register all standard policy watchers
        if params.Config.EnableK8sNetworkPolicy {
            p.knpSyncPending.Store(1)
            p.registerResourceWithSyncFn(ctx, k8sAPIGroupNetworkingV1Core, func() bool {
                return p.knpSyncPending.Load() == 0
            })
        }
        
        if params.Config.EnableCiliumNetworkPolicy {
            p.cnpSyncPending.Store(1)
            p.registerResourceWithSyncFn(ctx, k8sAPIGroupCiliumNetworkPolicyV2, func() bool {
                return p.cnpSyncPending.Load() == 0 && p.cidrGroupSynced.Load()
            })
        }

        if params.Config.EnableCiliumClusterwideNetworkPolicy {
            p.ccnpSyncPending.Store(1)
            p.registerResourceWithSyncFn(ctx, k8sAPIGroupCiliumClusterwideNetworkPolicyV2, func() bool {
                return p.ccnpSyncPending.Load() == 0 && p.cidrGroupSynced.Load()
            })
        }
        
        // CIDR Groups are only needed in distributed mode
        if params.Config.EnableCiliumNetworkPolicy || params.Config.EnableCiliumClusterwideNetworkPolicy {
            p.registerResourceWithSyncFn(ctx, k8sAPIGroupCiliumCIDRGroupV2Alpha1, func() bool {
                return p.cidrGroupSynced.Load()
            })
        }
    }
}
```

Also, we need to define a new constant for the CiliumResolvedPolicy API Group:

```go
const (
    k8sAPIGroupNetworkingV1Core                 = "networking.k8s.io/v1::NetworkPolicy"
    k8sAPIGroupCiliumNetworkPolicyV2            = "cilium/v2::CiliumNetworkPolicy"
    k8sAPIGroupCiliumClusterwideNetworkPolicyV2 = "cilium/v2::CiliumClusterwideNetworkPolicy"
    k8sAPIGroupCiliumCIDRGroupV2Alpha1          = "cilium/v2alpha1::CiliumCIDRGroup"
    k8sAPIGroupCiliumResolvedPolicyV1Alpha1     = "cilium/v1alpha1::CiliumResolvedPolicy" // New API group
)
```

### Changes to PolicyWatcherParams struct

We need to update the `PolicyWatcherParams` struct to include the CiliumResolvedPolicies resource:

```go
type PolicyWatcherParams struct {
    cell.In

    Lifecycle cell.Lifecycle

    ClientSet client.Clientset
    Config    *option.DaemonConfig
    Logger    *slog.Logger

    K8sResourceSynced *synced.Resources
    K8sAPIGroups      *synced.APIGroups

    ServiceCache   k8s.ServiceCache
    IPCache        *ipcache.IPCache
    PolicyImporter policycell.PolicyImporter

    CiliumNetworkPolicies            resource.Resource[*cilium_v2.CiliumNetworkPolicy]
    CiliumClusterwideNetworkPolicies resource.Resource[*cilium_v2.CiliumClusterwideNetworkPolicy]
    CiliumCIDRGroups                 resource.Resource[*cilium_v2_alpha1.CiliumCIDRGroup]
    CiliumResolvedPolicies           resource.Resource[*cilium_v1alpha1.CiliumResolvedPolicy] // New resource
    NetworkPolicies                  resource.Resource[*slim_networking_v1.NetworkPolicy]

    MetricsManager CNPMetrics
}
```

### PolicyWatcher Structure Update

The `policyWatcher` struct also needs to be updated to include fields for tracking resolved policies:

```go
type policyWatcher struct {
    // ...existing code...
    
    // For CiliumResolvedPolicy
    resolvedPolicySyncPending atomic.Int32
    ciliumResolvedPolicies    resource.Resource[*cilium_v1alpha1.CiliumResolvedPolicy]
    
    // ...existing code...
}
```

### Changes to PolicyImporter

The PolicyImporter interface needs to be extended to support resolved policies:

```go
// In pkg/policy/cell/policy_importer.go
type PolicyImporter interface {
    UpdatePolicy(*policytypes.PolicyUpdate)
    UpdateResolvedPolicy(*ciliumv1alpha1.CiliumResolvedPolicy) error
}

type policyImporter struct {
    // ...existing code...
    resolvedPolicyQ chan *ciliumv1alpha1.CiliumResolvedPolicy  // New channel for resolved policies
    // ...existing code...
}

func newPolicyImporter(cfg policyImporterParams) PolicyImporter {
    i := &policyImporter{
        // ...existing code...
        resolvedPolicyQ: make(chan *ciliumv1alpha1.CiliumResolvedPolicy, cfg.Config.PolicyQueueSize),
        // ...existing code...
    }

    // Existing code for regular policy updates
    buf := stream.Buffer(
        stream.FromChannel(i.q),
        int(cfg.Config.PolicyQueueSize), 10*time.Millisecond,
        concat)

    cfg.JobGroup.Add(job.Observer("policy-importer", i.processUpdates, buf))
    
    // New buffer and job for resolved policy updates
    resolvedBuf := stream.Buffer(
        stream.FromChannel(i.resolvedPolicyQ),
        int(cfg.Config.PolicyQueueSize), 10*time.Millisecond,
        concatResolved)

    cfg.JobGroup.Add(job.Observer("resolved-policy-importer", i.processResolvedPolicyUpdates, resolvedBuf))

    return i
}

func concatResolved(buf []*ciliumv1alpha1.CiliumResolvedPolicy, in *ciliumv1alpha1.CiliumResolvedPolicy) []*ciliumv1alpha1.CiliumResolvedPolicy {
    buf = append(buf, in)
    return buf
}

func (i *policyImporter) UpdateResolvedPolicy(resolvedPolicy *ciliumv1alpha1.CiliumResolvedPolicy) error {
    // Queue the resolved policy update for processing
    i.resolvedPolicyQ <- resolvedPolicy
    return nil
}

// processResolvedPolicyUpdates is similar to processUpdates but handles resolved policies
// with pre-computed identity mappings
func (i *policyImporter) processResolvedPolicyUpdates(ctx context.Context, updates []*ciliumv1alpha1.CiliumResolvedPolicy) error {
    if len(updates) == 0 {
        return nil
    }

    i.log.Info("Processing resolved policy updates", logfields.Count, len(updates))
    
    // We don't need to handle CIDR prefixes here separately, 
    // expecting them to be pre-computed and published by
    // centralized policy controller.

    
    // Process each resolved policy to update the repository
    idsToRegen := &set.Set[identity.NumericIdentity]{}
    startRevision := i.repo.GetRevision()
    endRevision := startRevision
    
    for _, resolvedPolicy := range updates {
        // For resolved policies, we use ImportResolvedPolicy on the repository
        // which will take the pre-computed identity mappings. Even though affected
        // identities are already computed, we still fetch them from ImportResolvedPolicy
        // which is expected to add the old identities deleted no longer related to the policy.
        affectedIdentities, newRevision, err := i.repo.ImportResolvedPolicy(resolvedPolicy)
        if err != nil {
            i.log.Error("Failed to import resolved policy",
                logfields.Error, err,
                logfields.Resource, resolvedPolicy.Name)
            continue
        }
        
        endRevision = newRevision
        idsToRegen.Merge(*affectedIdentities)
        
                
        // Send monitor notification similar to regular policy updates
        // ....same as in processUpdates...
    }
    
    // Regenerate affected endpoints
    i.log.Info("Resolved policy repository updates complete, triggering endpoint updates",
        logfields.PolicyRevision, endRevision)
    if i.epm != nil {
        i.epm.UpdatePolicy(idsToRegen, startRevision, endRevision)
    }
    
    // Record metrics for policy application
    // ....same as in processUpdates...    
    
    // Clean up stale prefixes, if CIDRS are handled separately
    
    return nil
}
```

### Changes to PolicyRepository

The PolicyRepository interface needs a new method to directly import resolved policies:

```go
// In pkg/policy/repository.go
type Repository Struct {
    // ...existing code...
    ImportResolvedPolicy(resolvedPolicy *ciliumv1alpha1.CiliumResolvedPolicy) (*set.Set[identity.NumericIdentity], uint64, error)
    // ...existing code...
}

// This is similar to ReplaceByResourceID function in the existing repository used for updating normal policies.
func (p *policyRepository) ImportResolvedPolicy(resolvedPolicy *ciliumv1alpha1.CiliumResolvedPolicy) (*set.Set[identity.NumericIdentity], uint64, error) {
    p.Mutex.Lock()
    defer p.Mutex.Unlock()
    
    identities := &set.Set[identity.NumericIdentity]{}
            resourceID := ipcachetypes.NewResourceID(
            ipcachetypes.ResourceKindCiliumNetworkPolicy,
            resolvedPolicy.Spec.SourceRef.Namespace,
            resolvedPolicy.Spec.SourceRef.Name,
        )
if resolvedPolicy == nil || len(resolvedPolicy.Spec.Rules) == 0 {
        // This is a delete operation
        
        // Remove the rulesif resolvedPolicy == nil || len(resolvedPolicy.Spec.Rules) == 0 {
        // This is a delete operation
associated with this resource
if resolvedPolicy == nil || len(resolvedPolicy.Spec.Rules) == 0 {
        // This is a delete operation
        for _, rulesBySource := rangif resolvedPolicy == nil || len(resolvedPolicy.Spec.Rules) == 0 {
        // This is a delete operation
e p.rules {
            if rrulerangif resolvedPolicy == nil || len(resolvedPolicy.Spec.Rules) == 0 {
        // This is a delete operation
e := rulesBySource[resouif rrulerangif resolvedPolicy == nil || len(resolvedPolicy.Spec.Rules) == 0 {
// This is a delete operation
e                                for _, r := range rrules {
                    // Add affected identities to the regeneration set
                    identities.Merge(*r.GetAffectedIdentities())
                }
                delete(rulesBySource, resourceID)
            }
        }
        
        p.revision++
        return identities, p.revision, nil
    }
    
    // This is an add/update operation
    // ReplaceByResourceID creates new policy.rule by calling p.newRule(*api.Rule, ruleKey)
    // newRule will internally create identitySelector object, run the compute to match policy 
    // to matching identities and the list of identities will be added to the identitySelector.
    // new policy.Rule will be added to the rules, rulesByNamespace and rulesByResource maps.
    
    // We can directlry create identitySelector object and add it to the selectorCache
    // and then add the rule to the rules map using p.insert(newRule) 
    
    return identities, p.revision, nil
}
```

## Endpoint Regeneration Flow

### When Policy Changes

1. The PolicyWatcher detects a change to a CiliumResolvedPolicy resource
2. The PolicyImporter processes this change via `UpdateResolvedPolicy`
3. The PolicyImporter buffers events and processes them in batches via `processResolvedPolicyUpdates`
4. Each resolved policy is imported into the PolicyRepository via `ImportResolvedPolicy`
5. Affected identities are collected and merged across all policy updates
6. Metrics are recorded for policy implementation delay
7. The EndpointManager is notified to regenerate affected endpoints

```
┌────────────────┐      ┌────────────────┐      ┌────────────────┐      ┌────────────────┐      ┌────────────────┐
│                │      │                │      │                │      │                │      │                │
│  PolicyWatcher │─────▶│ PolicyImporter │─────▶│processResolved│─────▶│    Policy     │─────▶│   Endpoint    │
│  (watches CRP) │      │(UpdateResolved)│      │PolicyUpdates  │      │  Repository   │      │ Regeneration  │
│                │      │                │      │               │      │   (Import)    │      │               │
└────────────────┘      └────────────────┘      └────────────────┘      └────────────────┘      └────────────────┘
                                                       
```

### When New Endpoint is Created

1. New endpoint is created with a set of identities
2. The endpoint constructor calls `RegeneratePolicy` on the endpoint
3. The endpoint's `regeneratePolicy` method retrieves applicable policies from the PolicyRepository
4. The PolicyRepository returns pre-computed policy decisions based on the endpoint's identities
5. The endpoint is configured with the appropriate policies without recomputing identity mappings

```
┌────────────────┐      ┌────────────────┐      ┌────────────────┐      ┌────────────────┐
│                │      │                │      │                │      │                │
│    Endpoint    │─────▶│ RegeneratePolicy ────▶│  Policy Repo  │─────▶│   Configure   │
│    Creation    │      │                │      │   (Lookup)    │      │    Endpoint   │
│                │      │                │      │               │      │               │
└────────────────┘      └────────────────┘      └────────────────┘      └────────────────┘
                                                       │                       │
                                                       │                       │
                                                       ▼                       ▼
                                               ┌────────────────┐      ┌────────────────┐
                                               │                │      │                │
                                               │  Pre-computed  │      │   Update BPF   │
                                               │Policy Decisions│      │ Policy Maps    │
                                               │                │      │                │
                                               └────────────────┘      └────────────────┘
```

## Performance Considerations

1. Reduced CPU and memory usage across the cluster as identity resolution happens only once
2. Reduced API server load due to fewer policy watches (only one component watches raw policies)

## Implementation steps

1. Implement core changes to PolicyWatcher, PolicyImporter, and PolicyRepository
2. Implement support for handling resolved policies in endpoint regeneration
3. Implement metrics and observability for the new policy resolution path
4. Implement seamless switching between centralized and distributed policy resolution
5. Test and validate the new architecture in a staging environment
6. Optimize policy repository with data structures more light weight and efficient for the centralized mode.

## Note on Centralized Identity Allocation

Beta version changes for centralized identity allocation are already supported. This functionality complements the centralized policy resolution approach and the code interactions will need to be understood in a subsequent phase.
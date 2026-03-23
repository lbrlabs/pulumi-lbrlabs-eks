## Context

The Cluster component already creates the Amazon VPC CNI add-on in [provider/pkg/provider/cluster.go](../../../../provider/pkg/provider/cluster.go), but it does not pass any `ConfigurationValues`. AWS EKS network policy support is enabled through VPC CNI add-on configuration rather than through a separate resource in this provider, so the public package currently has no first-class way to opt into it.

This repository treats [schema.yaml](../../../../schema.yaml) as the public API source of truth and generates SDKs for Go, Node.js, Python, and .NET from that schema. Any new Cluster input must therefore be modeled in schema types first, then implemented in the provider so code generation stays aligned.

## Goals / Non-Goals

**Goals:**
- Add an optional, strongly typed `vpcCniConfig` input to the Cluster component.
- Model network policy-related VPC CNI settings as dedicated schema types rather than a free-form string or map.
- Preserve current behavior for consumers that do not opt into `vpcCniConfig`.
- Render the typed config into `eks.AddonArgs.ConfigurationValues` for the `vpc-cni` add-on.
- Regenerate all SDKs so each language exposes the same typed input surface.

**Non-Goals:**
- Expose every Amazon VPC CNI configuration field in this change.
- Replace the existing IAM role wiring or addon installation flow for `aws-node`.
- Enforce addon version compatibility in provider code beyond documenting AWS requirements.
- Add or manage Kubernetes `NetworkPolicy` or `ClusterNetworkPolicy` resources themselves.

## Decisions

### 1. Add dedicated public schema types for VPC CNI configuration

The schema will gain a top-level `lbrlabs-eks:index:VpcCniConfig` type and a nested `lbrlabs-eks:index:VpcCniNodeAgentConfig` type, and `lbrlabs-eks:index:Cluster` will gain an optional `vpcCniConfig` input property that references them.

This matches how the package already exposes nested typed configuration such as `NginxIngressConfig`. It keeps the public API self-documenting and ensures all generated SDKs expose the same shape.

Alternative considered:
- Use a raw JSON string or `map[string]string` input. Rejected because it weakens validation, produces poor generated SDK ergonomics, and pushes AWS addon schema details onto consumers.

### 2. Scope the first version to the network policy-related VPC CNI fields

The first typed surface will cover the fields required for this request:
- `enableNetworkPolicy`
- `nodeAgent.enablePolicyEventLogs`
- `nodeAgent.enableCloudWatchLogs`
- `nodeAgent.metricsBindAddr`
- `nodeAgent.healthProbeBindAddr`

This keeps the change focused while still giving the provider a dedicated VPC CNI configuration object that can be expanded later.

Alternative considered:
- Model the full VPC CNI addon schema immediately. Rejected because it increases scope substantially and would make it harder to reason about compatibility and defaults in one change.

### 3. Keep the public API typed, convert to AWS addon-compatible values internally

The public schema types will use booleans and integers where that is the natural package API. The provider implementation will convert those values into the `ConfigurationValues` payload expected by the EKS add-on when creating or updating `vpc-cni`.

This preserves strong typing for users while isolating the stringly typed addon configuration format to provider internals.

Alternative considered:
- Mirror the addon payload exactly and expose strings for all values. Rejected because it leaks an implementation detail into the public API and weakens validation.

### 4. Preserve existing behavior when configuration is omitted

If `vpcCniConfig` is not provided, the provider will continue creating the `vpc-cni` addon without explicit configuration values. This avoids surprising existing stacks and keeps the change additive.

When `vpcCniConfig` is provided, the provider will serialize only the explicitly configured fields so the package does not unintentionally override unrelated VPC CNI defaults.

Alternative considered:
- Always send a default configuration object. Rejected because it creates unnecessary drift against current behavior and increases the chance of update-time surprises.

## Risks / Trade-offs

- [AWS addon version support varies by feature] -> Document that network policy support depends on an AWS-supported VPC CNI addon version instead of trying to hard-code version checks in the provider.
- [Typed scope is intentionally partial] -> Limit this change to network policy-related settings and leave broader VPC CNI coverage for follow-up changes.
- [Removing configuration after opt-in may have update semantics] -> Prefer explicit rollback by setting `enableNetworkPolicy` to `false` rather than assuming omission will always clear or preserve addon state in the desired way.
- [Generated SDK churn affects multiple languages] -> Keep `schema.yaml` as the source of truth and regenerate all SDKs in the same change so generated code stays synchronized.

## Migration Plan

This is an additive API change. Existing consumers do not need to migrate unless they want to enable VPC CNI network policy support.

For rollout:
1. Add the new schema types and Cluster input.
2. Implement serialization in the provider.
3. Regenerate SDKs and update examples or docs.

For rollback:
1. Set `vpcCniConfig.enableNetworkPolicy` to `false`.
2. Remove other `nodeAgent` settings if they are no longer needed.
3. Re-deploy the stack after confirming the target cluster and addon version support the desired state.

## Open Questions

No blocking open questions. This design assumes the first release should focus on the network policy-related VPC CNI fields and leave broader CNI tuning for a separate change.

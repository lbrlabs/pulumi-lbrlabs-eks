## Why

The provider currently installs the Amazon VPC CNI add-on, but consumers cannot enable EKS network policy support through the package API. Users must instead patch the add-on outside Pulumi or inject raw configuration, which breaks the goal of shipping an opinionated but complete EKS component.

## What Changes

- Add an optional typed `vpcCniConfig` input to the `lbrlabs-eks:index:Cluster` component.
- Define dedicated schema types for VPC CNI configuration and nested node agent settings instead of exposing raw JSON or untyped maps.
- Support the Amazon EKS network policy configuration fields exposed by the VPC CNI add-on, including `enableNetworkPolicy` and the related `nodeAgent` settings.
- Serialize typed VPC CNI configuration into the `vpc-cni` add-on `ConfigurationValues` in the provider implementation.
- Regenerate the Node.js, Python, Go, and .NET SDKs and update examples or documentation as needed.
- Preserve current behavior for existing consumers that do not set `vpcCniConfig`.

## Capabilities

### New Capabilities
- `vpc-cni-config`: Configure the Amazon VPC CNI add-on through typed Cluster inputs, including optional EKS network policy support.

### Modified Capabilities
- None.

## Impact

This change affects [schema.yaml](/Users/lbriggs/src/github/lbrlabs/pulumi-lbrlabs-eks/schema.yaml), [provider/pkg/provider/cluster.go](/Users/lbriggs/src/github/lbrlabs/pulumi-lbrlabs-eks/provider/pkg/provider/cluster.go), generated SDKs under [sdk/](/Users/lbriggs/src/github/lbrlabs/pulumi-lbrlabs-eks/sdk), and likely examples or README documentation. This is intended to be additive and backwards compatible: existing stacks should see no behavior change unless they opt into the new configuration.

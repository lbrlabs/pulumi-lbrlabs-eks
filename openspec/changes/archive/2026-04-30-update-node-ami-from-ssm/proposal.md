## Why

Attached EKS node groups currently rely on implicit AMI behavior, so running `pulumi up` does not reliably track the latest EKS optimized AL2023 node AMI. This leaves existing node groups on stale AMIs unless consumers manually change inputs such as `releaseVersion`.

## What Changes

- Add package behavior that explicitly selects the EKS-managed AL2023 AMI type for default attached-node groups.
- Resolve the latest EKS optimized AL2023 AMI `release_version` from AWS public SSM metadata and pass it to the EKS managed node group.
- Configure managed node group updates to roll one unavailable node at a time.
- Keep existing public inputs compatible; explicit `amiType` or `releaseVersion` behavior must not be broken.
- Do not add ASG instance-refresh behavior for this change.

## Capabilities

### New Capabilities

- `attached-node-ami-refresh`: Defines default EKS AMI type selection, SSM release version resolution, and rolling managed node group update behavior.

### Modified Capabilities

None.

## Impact

- Provider implementation: updates `provider/pkg/provider/nodegroup.go` to select EKS-managed AL2023 AMI types, resolve the current EKS AMI release version, and configure rolling update settings.
- AWS resources: affected stacks may see EKS managed node group updates during `pulumi up`.
- Public API and SDKs: no schema or SDK changes are expected unless implementation discovers a required API surface.
- Compatibility: existing stacks can observe node replacement or rolling node group updates as newer AMIs are applied, but no user code migration should be required.

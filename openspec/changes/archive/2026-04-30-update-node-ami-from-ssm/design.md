## Context

`AttachedNodeGroup` is implemented in `provider/pkg/provider/nodegroup.go` as an EKS managed node group. Today it passes `amiType` and `releaseVersion` through to `aws.eks.NodeGroup`, but the default path does not set `releaseVersion` from the current EKS optimized AMI metadata. As a result, a normal `pulumi up` can leave existing nodes on an older AMI until a user manually changes node group inputs.

The package already has a separate `AutoscaledNodeGroup` implementation for Karpenter. That path uses `amiSelectorTerms` with `alias: al2023@latest`, so this change is scoped to attached managed node groups.

## Goals / Non-Goals

**Goals:**

- Make default attached node groups use an explicit EKS-managed AL2023 AMI type.
- Select the EKS AL2023 AMI type that matches the configured node architecture.
- Ensure Pulumi detects EKS AMI release version changes and updates the existing managed node group in place.
- Configure the managed node group update strategy to roll one unavailable node at a time.
- Preserve existing explicit `amiType` and `releaseVersion` behavior where possible.

**Non-Goals:**

- Add Auto Scaling Group instance refresh settings directly.
- Change `AutoscaledNodeGroup` or Karpenter AMI selection behavior.
- Add a new public input unless implementation proves one is required.
- Force consumers to opt into custom AMI behavior for default node groups.

## Decisions

- Set `releaseVersion` from the EKS optimized AMI public SSM metadata for the selected Kubernetes version and architecture.
  - Rationale: `releaseVersion` is the managed node group field EKS can update in place for AMI releases, which lets EKS keep responsibility for bootstrap and rolling behavior.
  - Alternative considered: rely only on EKS managed node group defaults. That preserves fewer inputs, but does not give Pulumi a concrete change when AWS publishes a new AMI.

- Use EKS managed AL2023 `amiType` values instead of launch-template `ImageId`.
  - Rationale: EKS workers need the managed node group bootstrap path. Supplying a launch-template AMI ID makes EKS treat the node group as custom AMI flow and requires user data, which this package should not own for this change.
  - Alternative considered: use public SSM parameters through launch template `ImageId`. That tracks an AMI alias directly, but it also requires manual bootstrap user data for managed node groups.

- Derive the EKS managed AMI type from selected architecture.
  - Rationale: x86_64 node groups should use `AL2023_x86_64_STANDARD`; arm64 node groups should use `AL2023_ARM_64_STANDARD`.
  - Alternative considered: always use x86_64. That would break arm instance families such as `t4g`.

- Set `UpdateConfig.MaxUnavailable` to `1`.
  - Rationale: EKS managed node group updates should not make all nodes unavailable at once.
  - Alternative considered: leave EKS/provider defaults. That is less explicit and makes the rollout behavior harder to reason about.

- Keep `amiType` on the managed node group and avoid launch-template `ImageId`.
  - Rationale: this leaves EKS responsible for AMI selection and bootstrap.
  - Alternative considered: omit `amiType` and set launch-template `ImageId`. That requires custom bootstrap user data.

## Risks / Trade-offs

- Existing stacks may see managed node group updates during `pulumi up` after this change -> document the behavior in release notes and keep the change limited to default AMI behavior.
- Public SSM metadata lookup depends on the cluster Kubernetes version and selected architecture -> build the parameter path from the live cluster version and instance family architecture.
- Consumers using explicit `releaseVersion` may expect no automatic AMI movement -> preserve that explicit input path unless default behavior is being used.

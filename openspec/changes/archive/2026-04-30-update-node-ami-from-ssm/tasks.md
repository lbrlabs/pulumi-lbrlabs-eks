## 1. Provider Implementation

- [x] 1.1 Add EKS AMI release version resolution to `provider/pkg/provider/nodegroup.go` for default `AttachedNodeGroup` AMI behavior.
- [x] 1.2 Select the EKS-managed AL2023 AMI type for the configured node architecture.
- [x] 1.3 Select the correct AMI architecture for the configured node instance types, defaulting to x86_64 for the existing `t3.medium` default.
- [x] 1.4 Resolve the latest EKS optimized AL2023 `release_version` from AWS public SSM metadata.
- [x] 1.5 Configure `aws.eks.NodeGroup` updates with `MaxUnavailable: 1`.
- [x] 1.6 Preserve explicit `releaseVersion` and `amiType` behavior by only enabling the default EKS AMI release path when it does not conflict with those inputs.

## 2. Compatibility and Schema

- [x] 2.1 Confirm no new public inputs or outputs are required in `schema.yaml`.
- [x] 2.2 If implementation requires schema changes, update `schema.yaml` and regenerate SDKs with the repository Makefile target.
- [x] 2.3 Confirm `AutoscaledNodeGroup` Karpenter AMI selection remains unchanged.

## 3. Verification

- [x] 3.1 Run the relevant provider build or tests with the repository Makefile target.
- [x] 3.2 Run example validation from `examples/` or the closest existing example test target to ensure `AttachedNodeGroup` programs still compile.
- [ ] 3.3 Inspect Pulumi preview output for an attached node group to verify `releaseVersion` updates in place and `updateConfig.maxUnavailable` is set to 1.

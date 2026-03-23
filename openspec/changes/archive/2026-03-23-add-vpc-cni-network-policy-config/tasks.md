## 1. Schema and provider contract

- [x] 1.1 Add `VpcCniConfig` and `VpcCniNodeAgentConfig` types to `schema.yaml`, and add optional `vpcCniConfig` to the `lbrlabs-eks:index:Cluster` input properties.
- [x] 1.2 Add matching typed Go inputs to `provider/pkg/provider/cluster.go` so Cluster arguments can represent `enableNetworkPolicy` and the nested `nodeAgent` settings without untyped maps.

## 2. VPC CNI addon implementation

- [x] 2.1 Update the `vpc-cni` add-on creation in `provider/pkg/provider/cluster.go` to serialize `vpcCniConfig` into `eks.AddonArgs.ConfigurationValues` using the AWS-supported `enableNetworkPolicy` and `nodeAgent` keys.
- [x] 2.2 Preserve current behavior when `vpcCniConfig` is omitted, and ensure only explicitly configured fields are emitted in the VPC CNI add-on configuration payload.

## 3. Generated SDKs and usage updates

- [x] 3.1 Regenerate the provider schema outputs and multi-language SDKs with the project build flow, using the relevant Makefile targets such as `make provider` and `make build_sdks`.
- [x] 3.2 Update examples or README documentation to show how to opt into `vpcCniConfig` for EKS network policy support and note that AWS addon/version support still applies.

## 4. Verification

- [x] 4.1 Verify the regenerated Go, Node.js, Python, and .NET SDKs expose typed `vpcCniConfig` and nested node agent inputs instead of raw JSON or generic maps.
- [x] 4.2 Run the repository verification flow needed for this change, including `cd examples && go test -v -tags=all -parallel 10 -timeout 2h`, and fix any breakages caused by the new schema surface.

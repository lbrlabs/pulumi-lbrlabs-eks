## ADDED Requirements

### Requirement: Cluster exposes typed VPC CNI configuration
The `lbrlabs-eks:index:Cluster` component SHALL expose an optional `vpcCniConfig` input property in [schema.yaml](/Users/lbriggs/src/github/lbrlabs/pulumi-lbrlabs-eks/schema.yaml). The property MUST reference a dedicated `lbrlabs-eks:index:VpcCniConfig` schema type rather than a free-form JSON string or untyped map.

#### Scenario: Consumer enables network policy through the package API
- **WHEN** a Pulumi program sets `vpcCniConfig.enableNetworkPolicy` on a Cluster
- **THEN** the package accepts the value through a typed Cluster input without requiring raw add-on configuration JSON

#### Scenario: Consumer configures node agent settings
- **WHEN** a Pulumi program sets `vpcCniConfig.nodeAgent` values
- **THEN** the package accepts those values through a dedicated nested schema type instead of a generic object

### Requirement: VPC CNI node agent settings are strongly typed
The `lbrlabs-eks:index:VpcCniConfig` schema type MUST expose a nested `lbrlabs-eks:index:VpcCniNodeAgentConfig` type for network policy-related node agent settings. The nested type SHALL model `enablePolicyEventLogs` and `enableCloudWatchLogs` as booleans and `metricsBindAddr` and `healthProbeBindAddr` as integers in the public package API.

#### Scenario: Consumer sets logging flags
- **WHEN** a Pulumi program sets `vpcCniConfig.nodeAgent.enablePolicyEventLogs` or `vpcCniConfig.nodeAgent.enableCloudWatchLogs`
- **THEN** the generated SDKs expose those fields as typed boolean inputs

#### Scenario: Consumer sets node agent ports
- **WHEN** a Pulumi program sets `vpcCniConfig.nodeAgent.metricsBindAddr` or `vpcCniConfig.nodeAgent.healthProbeBindAddr`
- **THEN** the generated SDKs expose those fields as typed numeric inputs

### Requirement: VPC CNI configuration is optional and backwards compatible
The provider implementation in [provider/pkg/provider/cluster.go](/Users/lbriggs/src/github/lbrlabs/pulumi-lbrlabs-eks/provider/pkg/provider/cluster.go) SHALL preserve current `vpc-cni` add-on behavior when `vpcCniConfig` is omitted. Existing programs that do not set `vpcCniConfig` MUST continue to create or update the Cluster without being required to configure network policy settings.

#### Scenario: Existing stack does not opt in
- **WHEN** a Cluster is created or updated without `vpcCniConfig`
- **THEN** the provider creates the `vpc-cni` add-on without introducing new required inputs or network policy configuration

### Requirement: Provider renders typed VPC CNI config into addon configuration values
When `vpcCniConfig` is provided, the provider SHALL serialize the configured values into the `ConfigurationValues` payload for the `vpc-cni` EKS add-on using the AWS-supported keys `enableNetworkPolicy` and `nodeAgent`. The provider MUST include only fields that the consumer explicitly configured.

#### Scenario: Consumer enables network policy
- **WHEN** a Cluster is configured with `vpcCniConfig.enableNetworkPolicy = true`
- **THEN** the `vpc-cni` add-on receives `ConfigurationValues` that enable network policy using the AWS-supported configuration key

#### Scenario: Consumer configures node agent overrides
- **WHEN** a Cluster is configured with `vpcCniConfig.nodeAgent` overrides
- **THEN** the `vpc-cni` add-on receives a `nodeAgent` configuration block containing the corresponding AWS-supported fields

### Requirement: Generated SDKs expose the same typed VPC CNI surface in every language
After schema regeneration, the generated Go, Node.js, Python, and .NET SDKs SHALL expose `vpcCniConfig` and its nested node agent settings as typed inputs derived from the schema rather than language-specific ad hoc wrappers.

#### Scenario: SDKs are regenerated after the schema change
- **WHEN** the package SDKs are regenerated from the updated schema
- **THEN** each supported language exposes typed `vpcCniConfig` inputs that match the schema-defined field names and nesting

## Purpose

Define the default AMI refresh behavior for attached EKS managed node groups.

## Requirements

### Requirement: Attached node groups use EKS-managed AL2023 AMIs

The `lbrlabs-eks:index:AttachedNodeGroup` component SHALL use EKS-managed AL2023 AMI types when the consumer does not provide an explicit `amiType` or `releaseVersion`.

#### Scenario: Default attached node group uses EKS managed AL2023 AMI

- **WHEN** a Pulumi program creates or updates an `AttachedNodeGroup` without `amiType` or `releaseVersion`
- **THEN** the provider sets an EKS managed AL2023 `amiType` on the node group

#### Scenario: AMI matches node architecture

- **WHEN** the provider selects the default AMI for an attached node group
- **THEN** the selected EKS managed AL2023 `amiType` matches the node architecture required by the configured instance types

### Requirement: Attached node groups track EKS AMI release versions

The `lbrlabs-eks:index:AttachedNodeGroup` component SHALL resolve the latest EKS optimized AL2023 AMI `release_version` from AWS public SSM metadata and pass it to the managed node group when the consumer does not provide an explicit `releaseVersion`.

#### Scenario: Pulumi program is re-run after AWS publishes an AMI release

- **WHEN** AWS publishes a newer EKS-optimized AL2023 AMI and the user runs `pulumi up`
- **THEN** Pulumi detects a managed node group `releaseVersion` update for the attached node group

#### Scenario: Managed node group rolls one unavailable node at a time

- **WHEN** the provider updates the managed node group AMI release version
- **THEN** the node group update configuration limits unavailable nodes to one at a time

### Requirement: Explicit AMI controls remain compatible

The `lbrlabs-eks:index:AttachedNodeGroup` component MUST preserve explicit consumer control through existing AMI-related inputs and MUST NOT introduce a required public input for AMI refresh behavior.

#### Scenario: Consumer pins release version

- **WHEN** a Pulumi program sets `releaseVersion` on an `AttachedNodeGroup`
- **THEN** the provider honors the pinned release behavior instead of forcing automatic AMI updates

#### Scenario: Existing program omits AMI fields

- **WHEN** an existing Pulumi program does not set `amiType` or `releaseVersion`
- **THEN** the program continues to compile without schema changes or new required inputs

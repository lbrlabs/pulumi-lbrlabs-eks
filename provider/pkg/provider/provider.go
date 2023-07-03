package provider

import (
	"github.com/pkg/errors"

	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi/provider"
)

func construct(ctx *pulumi.Context, typ, name string, inputs provider.ConstructInputs,
	options pulumi.ResourceOption) (*provider.ConstructResult, error) {
	// TODO: Add support for additional component resources here.
	switch typ {
	case "lbrlabs-eks:index:Cluster":
		return constructCluster(ctx, name, inputs, options)
	case "lbrlabs-eks:index:AttachedNodeGroup":
		return constructNodeGroup(ctx, name, inputs, options)
	case "lbrlabs-eks:index:IamServiceAccountRole":
		return constructIamServiceAccountRole(ctx, name, inputs, options)
	case "lbrlabs-eks:index:RoleMapping":
		return constructIamRoleMapping(ctx, name, inputs, options)
	default:
		return nil, errors.Errorf("unknown resource type %s", typ)
	}
}

// constructCluster is an implementation of Construct for the example Cluster component.
// It demonstrates converting the raw ConstructInputs to the component's args struct, creating
// the component, and returning its URN and state (outputs).
func constructCluster(ctx *pulumi.Context, name string, inputs provider.ConstructInputs,
	options pulumi.ResourceOption) (*provider.ConstructResult, error) {

	// Copy the raw inputs to StaticPageArgs. `inputs.CopyTo` uses the types and `pulumi:` tags
	// on the struct's fields to convert the raw values to the appropriate Input types.
	args := &ClusterArgs{}
	if err := inputs.CopyTo(args); err != nil {
		return nil, errors.Wrap(err, "setting args")
	}

	// Create the component resource.
	cluster, err := NewCluster(ctx, name, args, options)
	if err != nil {
		return nil, errors.Wrap(err, "creating component")
	}

	// Return the component resource's URN and state. `NewConstructResult` automatically sets the
	// ConstructResult's state based on resource struct fields tagged with `pulumi:` tags with a value
	// that is convertible to `pulumi.Input`.
	return provider.NewConstructResult(cluster)
}

// constructNodeGroup is an implementation of Construct for the example NodeGroup component.
// It demonstrates converting the raw ConstructInputs to the component's args struct, creating
// the component, and returning its URN and state (outputs).
func constructNodeGroup(ctx *pulumi.Context, name string, inputs provider.ConstructInputs,
	options pulumi.ResourceOption) (*provider.ConstructResult, error) {

	// Copy the raw inputs to StaticPageArgs. `inputs.CopyTo` uses the types and `pulumi:` tags
	// on the struct's fields to convert the raw values to the appropriate Input types.
	args := &NodeGroupArgs{}
	if err := inputs.CopyTo(args); err != nil {
		return nil, errors.Wrap(err, "setting args")
	}

	// Create the component resource.
	ng, err := NewNodeGroup(ctx, name, args, options)
	if err != nil {
		return nil, errors.Wrap(err, "creating component")
	}

	// Return the component resource's URN and state. `NewConstructResult` automatically sets the
	// ConstructResult's state based on resource struct fields tagged with `pulumi:` tags with a value
	// that is convertible to `pulumi.Input`.
	return provider.NewConstructResult(ng)
}

// constructIamServiceAccountRole is an implementation of Construct for the example IamServiceAccountRole component.
// It demonstrates converting the raw ConstructInputs to the component's args struct, creating
// the component, and returning its URN and state (outputs).
func constructIamServiceAccountRole(ctx *pulumi.Context, name string, inputs provider.ConstructInputs,
	options pulumi.ResourceOption) (*provider.ConstructResult, error) {

	// Copy the raw inputs to StaticPageArgs. `inputs.CopyTo` uses the types and `pulumi:` tags
	// on the struct's fields to convert the raw values to the appropriate Input types.
	args := &IamServiceAccountRoleArgs{}
	if err := inputs.CopyTo(args); err != nil {
		return nil, errors.Wrap(err, "setting args")
	}

	// Create the component resource.
	irsa, err := NewIamServiceAccountRole(ctx, name, args, options)
	if err != nil {
		return nil, errors.Wrap(err, "creating component")
	}

	// Return the component resource's URN and state. `NewConstructResult` automatically sets the
	// ConstructResult's state based on resource struct fields tagged with `pulumi:` tags with a value
	// that is convertible to `pulumi.Input`.
	return provider.NewConstructResult(irsa)
}

// constructIamRoleMappings is an implementation of Construct for the example IamRoleMappings component.
// It demonstrates converting the raw ConstructInputs to the component's args struct, creating
// the component, and returning its URN and state (outputs).
func constructIamRoleMapping(ctx *pulumi.Context, name string, inputs provider.ConstructInputs,
	options pulumi.ResourceOption) (*provider.ConstructResult, error) {

	// Copy the raw inputs to StaticPageArgs. `inputs.CopyTo` uses the types and `pulumi:` tags
	// on the struct's fields to convert the raw values to the appropriate Input types.
	args := &RoleMappingArgs{}
	if err := inputs.CopyTo(args); err != nil {
		return nil, errors.Wrap(err, "setting args")
	}

	// Create the component resource.
	roleMapping, err := NewRoleMapping(ctx, name, args, options)
	if err != nil {
		return nil, errors.Wrap(err, "creating component")
	}

	// Return the component resource's URN and state. `NewConstructResult` automatically sets the
	// ConstructResult's state based on resource struct fields tagged with `pulumi:` tags with a value
	// that is convertible to `pulumi.Input`.
	return provider.NewConstructResult(roleMapping)
}

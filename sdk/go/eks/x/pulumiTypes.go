// Code generated by Pulumi SDK Generator DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package eks

import (
	"context"
	"reflect"

	"github.com/lbrlabs/pulumi-lbrlabs-eks/sdk/go/eks/internal"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumix"
)

var _ = internal.GetEnvOrDefault

// Represents a single requirement with key, operator, and values.
type Requirement struct {
	// The key of the requirement.
	Key *string `pulumi:"key"`
	// The operator for the requirement (e.g., In, Gt).
	Operator *string `pulumi:"operator"`
	// The list of values for the requirement.
	Values []string `pulumi:"values"`
}

// Represents a single requirement with key, operator, and values.
type RequirementArgs struct {
	// The key of the requirement.
	Key pulumix.Input[*string] `pulumi:"key"`
	// The operator for the requirement (e.g., In, Gt).
	Operator pulumix.Input[*string] `pulumi:"operator"`
	// The list of values for the requirement.
	Values pulumix.Input[[]string] `pulumi:"values"`
}

func (RequirementArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*Requirement)(nil)).Elem()
}

func (i RequirementArgs) ToRequirementOutput() RequirementOutput {
	return i.ToRequirementOutputWithContext(context.Background())
}

func (i RequirementArgs) ToRequirementOutputWithContext(ctx context.Context) RequirementOutput {
	return pulumi.ToOutputWithContext(ctx, i).(RequirementOutput)
}

func (i *RequirementArgs) ToOutput(ctx context.Context) pulumix.Output[*RequirementArgs] {
	return pulumix.Val(i)
}

// Represents a single requirement with key, operator, and values.
type RequirementOutput struct{ *pulumi.OutputState }

func (RequirementOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*Requirement)(nil)).Elem()
}

func (o RequirementOutput) ToRequirementOutput() RequirementOutput {
	return o
}

func (o RequirementOutput) ToRequirementOutputWithContext(ctx context.Context) RequirementOutput {
	return o
}

func (o RequirementOutput) ToOutput(ctx context.Context) pulumix.Output[Requirement] {
	return pulumix.Output[Requirement]{
		OutputState: o.OutputState,
	}
}

// The key of the requirement.
func (o RequirementOutput) Key() pulumix.Output[*string] {
	return pulumix.Apply[Requirement](o, func(v Requirement) *string { return v.Key })
}

// The operator for the requirement (e.g., In, Gt).
func (o RequirementOutput) Operator() pulumix.Output[*string] {
	return pulumix.Apply[Requirement](o, func(v Requirement) *string { return v.Operator })
}

// The list of values for the requirement.
func (o RequirementOutput) Values() pulumix.ArrayOutput[string] {
	value := pulumix.Apply[Requirement](o, func(v Requirement) []string { return v.Values })
	return pulumix.ArrayOutput[string]{OutputState: value.OutputState}
}

// Represents a taint for a karpenter node.
type Taint struct {
	// The effect of the taint.
	Effect []string `pulumi:"effect"`
	// The key of the taint.
	Key *string `pulumi:"key"`
	// The value of the taint.
	Value *string `pulumi:"value"`
}

func init() {
	pulumi.RegisterOutputType(RequirementOutput{})
}

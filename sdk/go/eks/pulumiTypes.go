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

// Configuration for Autoscaled nodes disruption.
type DisruptionConfig struct {
	// The amount of time Karpenter should wait after discovering a consolidation decision. This value can currently only be set when the consolidationPolicy is 'WhenEmpty'. You can choose to disable consolidation entirely by setting the string value 'Never' here.
	ConsolidateAfter *string `pulumi:"consolidateAfter"`
	// Describes which types of Nodes Karpenter should consider for consolidation.
	ConsolidationPolicy *string `pulumi:"consolidationPolicy"`
	// The amount of time a Node can live on the cluster before being removed.
	ExpireAfter *string `pulumi:"expireAfter"`
}

// Defaults sets the appropriate defaults for DisruptionConfig
func (val *DisruptionConfig) Defaults() *DisruptionConfig {
	if val == nil {
		return nil
	}
	tmp := *val
	if tmp.ConsolidateAfter == nil {
		consolidateAfter_ := "30s"
		tmp.ConsolidateAfter = &consolidateAfter_
	}
	if tmp.ConsolidationPolicy == nil {
		consolidationPolicy_ := "WhenUnderutilized"
		tmp.ConsolidationPolicy = &consolidationPolicy_
	}
	if tmp.ExpireAfter == nil {
		expireAfter_ := "720h"
		tmp.ExpireAfter = &expireAfter_
	}
	return &tmp
}

// DisruptionConfigInput is an input type that accepts DisruptionConfigArgs and DisruptionConfigOutput values.
// You can construct a concrete instance of `DisruptionConfigInput` via:
//
//	DisruptionConfigArgs{...}
type DisruptionConfigInput interface {
	pulumi.Input

	ToDisruptionConfigOutput() DisruptionConfigOutput
	ToDisruptionConfigOutputWithContext(context.Context) DisruptionConfigOutput
}

// Configuration for Autoscaled nodes disruption.
type DisruptionConfigArgs struct {
	// The amount of time Karpenter should wait after discovering a consolidation decision. This value can currently only be set when the consolidationPolicy is 'WhenEmpty'. You can choose to disable consolidation entirely by setting the string value 'Never' here.
	ConsolidateAfter pulumi.StringPtrInput `pulumi:"consolidateAfter"`
	// Describes which types of Nodes Karpenter should consider for consolidation.
	ConsolidationPolicy pulumi.StringPtrInput `pulumi:"consolidationPolicy"`
	// The amount of time a Node can live on the cluster before being removed.
	ExpireAfter pulumi.StringPtrInput `pulumi:"expireAfter"`
}

// Defaults sets the appropriate defaults for DisruptionConfigArgs
func (val *DisruptionConfigArgs) Defaults() *DisruptionConfigArgs {
	if val == nil {
		return nil
	}
	tmp := *val
	if tmp.ConsolidateAfter == nil {
		tmp.ConsolidateAfter = pulumi.StringPtr("30s")
	}
	if tmp.ConsolidationPolicy == nil {
		tmp.ConsolidationPolicy = pulumi.StringPtr("WhenUnderutilized")
	}
	if tmp.ExpireAfter == nil {
		tmp.ExpireAfter = pulumi.StringPtr("720h")
	}
	return &tmp
}
func (DisruptionConfigArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*DisruptionConfig)(nil)).Elem()
}

func (i DisruptionConfigArgs) ToDisruptionConfigOutput() DisruptionConfigOutput {
	return i.ToDisruptionConfigOutputWithContext(context.Background())
}

func (i DisruptionConfigArgs) ToDisruptionConfigOutputWithContext(ctx context.Context) DisruptionConfigOutput {
	return pulumi.ToOutputWithContext(ctx, i).(DisruptionConfigOutput)
}

func (i DisruptionConfigArgs) ToOutput(ctx context.Context) pulumix.Output[DisruptionConfig] {
	return pulumix.Output[DisruptionConfig]{
		OutputState: i.ToDisruptionConfigOutputWithContext(ctx).OutputState,
	}
}

func (i DisruptionConfigArgs) ToDisruptionConfigPtrOutput() DisruptionConfigPtrOutput {
	return i.ToDisruptionConfigPtrOutputWithContext(context.Background())
}

func (i DisruptionConfigArgs) ToDisruptionConfigPtrOutputWithContext(ctx context.Context) DisruptionConfigPtrOutput {
	return pulumi.ToOutputWithContext(ctx, i).(DisruptionConfigOutput).ToDisruptionConfigPtrOutputWithContext(ctx)
}

// DisruptionConfigPtrInput is an input type that accepts DisruptionConfigArgs, DisruptionConfigPtr and DisruptionConfigPtrOutput values.
// You can construct a concrete instance of `DisruptionConfigPtrInput` via:
//
//	        DisruptionConfigArgs{...}
//
//	or:
//
//	        nil
type DisruptionConfigPtrInput interface {
	pulumi.Input

	ToDisruptionConfigPtrOutput() DisruptionConfigPtrOutput
	ToDisruptionConfigPtrOutputWithContext(context.Context) DisruptionConfigPtrOutput
}

type disruptionConfigPtrType DisruptionConfigArgs

func DisruptionConfigPtr(v *DisruptionConfigArgs) DisruptionConfigPtrInput {
	return (*disruptionConfigPtrType)(v)
}

func (*disruptionConfigPtrType) ElementType() reflect.Type {
	return reflect.TypeOf((**DisruptionConfig)(nil)).Elem()
}

func (i *disruptionConfigPtrType) ToDisruptionConfigPtrOutput() DisruptionConfigPtrOutput {
	return i.ToDisruptionConfigPtrOutputWithContext(context.Background())
}

func (i *disruptionConfigPtrType) ToDisruptionConfigPtrOutputWithContext(ctx context.Context) DisruptionConfigPtrOutput {
	return pulumi.ToOutputWithContext(ctx, i).(DisruptionConfigPtrOutput)
}

func (i *disruptionConfigPtrType) ToOutput(ctx context.Context) pulumix.Output[*DisruptionConfig] {
	return pulumix.Output[*DisruptionConfig]{
		OutputState: i.ToDisruptionConfigPtrOutputWithContext(ctx).OutputState,
	}
}

// Configuration for Autoscaled nodes disruption.
type DisruptionConfigOutput struct{ *pulumi.OutputState }

func (DisruptionConfigOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*DisruptionConfig)(nil)).Elem()
}

func (o DisruptionConfigOutput) ToDisruptionConfigOutput() DisruptionConfigOutput {
	return o
}

func (o DisruptionConfigOutput) ToDisruptionConfigOutputWithContext(ctx context.Context) DisruptionConfigOutput {
	return o
}

func (o DisruptionConfigOutput) ToDisruptionConfigPtrOutput() DisruptionConfigPtrOutput {
	return o.ToDisruptionConfigPtrOutputWithContext(context.Background())
}

func (o DisruptionConfigOutput) ToDisruptionConfigPtrOutputWithContext(ctx context.Context) DisruptionConfigPtrOutput {
	return o.ApplyTWithContext(ctx, func(_ context.Context, v DisruptionConfig) *DisruptionConfig {
		return &v
	}).(DisruptionConfigPtrOutput)
}

func (o DisruptionConfigOutput) ToOutput(ctx context.Context) pulumix.Output[DisruptionConfig] {
	return pulumix.Output[DisruptionConfig]{
		OutputState: o.OutputState,
	}
}

// The amount of time Karpenter should wait after discovering a consolidation decision. This value can currently only be set when the consolidationPolicy is 'WhenEmpty'. You can choose to disable consolidation entirely by setting the string value 'Never' here.
func (o DisruptionConfigOutput) ConsolidateAfter() pulumi.StringPtrOutput {
	return o.ApplyT(func(v DisruptionConfig) *string { return v.ConsolidateAfter }).(pulumi.StringPtrOutput)
}

// Describes which types of Nodes Karpenter should consider for consolidation.
func (o DisruptionConfigOutput) ConsolidationPolicy() pulumi.StringPtrOutput {
	return o.ApplyT(func(v DisruptionConfig) *string { return v.ConsolidationPolicy }).(pulumi.StringPtrOutput)
}

// The amount of time a Node can live on the cluster before being removed.
func (o DisruptionConfigOutput) ExpireAfter() pulumi.StringPtrOutput {
	return o.ApplyT(func(v DisruptionConfig) *string { return v.ExpireAfter }).(pulumi.StringPtrOutput)
}

type DisruptionConfigPtrOutput struct{ *pulumi.OutputState }

func (DisruptionConfigPtrOutput) ElementType() reflect.Type {
	return reflect.TypeOf((**DisruptionConfig)(nil)).Elem()
}

func (o DisruptionConfigPtrOutput) ToDisruptionConfigPtrOutput() DisruptionConfigPtrOutput {
	return o
}

func (o DisruptionConfigPtrOutput) ToDisruptionConfigPtrOutputWithContext(ctx context.Context) DisruptionConfigPtrOutput {
	return o
}

func (o DisruptionConfigPtrOutput) ToOutput(ctx context.Context) pulumix.Output[*DisruptionConfig] {
	return pulumix.Output[*DisruptionConfig]{
		OutputState: o.OutputState,
	}
}

func (o DisruptionConfigPtrOutput) Elem() DisruptionConfigOutput {
	return o.ApplyT(func(v *DisruptionConfig) DisruptionConfig {
		if v != nil {
			return *v
		}
		var ret DisruptionConfig
		return ret
	}).(DisruptionConfigOutput)
}

// The amount of time Karpenter should wait after discovering a consolidation decision. This value can currently only be set when the consolidationPolicy is 'WhenEmpty'. You can choose to disable consolidation entirely by setting the string value 'Never' here.
func (o DisruptionConfigPtrOutput) ConsolidateAfter() pulumi.StringPtrOutput {
	return o.ApplyT(func(v *DisruptionConfig) *string {
		if v == nil {
			return nil
		}
		return v.ConsolidateAfter
	}).(pulumi.StringPtrOutput)
}

// Describes which types of Nodes Karpenter should consider for consolidation.
func (o DisruptionConfigPtrOutput) ConsolidationPolicy() pulumi.StringPtrOutput {
	return o.ApplyT(func(v *DisruptionConfig) *string {
		if v == nil {
			return nil
		}
		return v.ConsolidationPolicy
	}).(pulumi.StringPtrOutput)
}

// The amount of time a Node can live on the cluster before being removed.
func (o DisruptionConfigPtrOutput) ExpireAfter() pulumi.StringPtrOutput {
	return o.ApplyT(func(v *DisruptionConfig) *string {
		if v == nil {
			return nil
		}
		return v.ExpireAfter
	}).(pulumi.StringPtrOutput)
}

// Configuration for the ingress controller.
type IngressConfig struct {
	// Additional configuration for the ingress controller.
	AdditionalConfig map[string]string `pulumi:"additionalConfig"`
	// The number of replicas of the ingress controller.
	ControllerReplicas *float64 `pulumi:"controllerReplicas"`
	// Enable metrics for the ingress controller.
	EnableMetrics *bool `pulumi:"enableMetrics"`
	// Enable the service monitor for kube-prometheus-stackl.
	EnableServiceMonitor *bool `pulumi:"enableServiceMonitor"`
	// NLB target type for NLB loadbalancers.
	NlbTargetType *string `pulumi:"nlbTargetType"`
	// The namespace to deploy the service monitor to.
	ServiceMonitorNamespace *string `pulumi:"serviceMonitorNamespace"`
}

// Defaults sets the appropriate defaults for IngressConfig
func (val *IngressConfig) Defaults() *IngressConfig {
	if val == nil {
		return nil
	}
	tmp := *val
	if tmp.ControllerReplicas == nil {
		controllerReplicas_ := 1.0
		tmp.ControllerReplicas = &controllerReplicas_
	}
	if tmp.EnableMetrics == nil {
		enableMetrics_ := false
		tmp.EnableMetrics = &enableMetrics_
	}
	if tmp.EnableServiceMonitor == nil {
		enableServiceMonitor_ := false
		tmp.EnableServiceMonitor = &enableServiceMonitor_
	}
	if tmp.NlbTargetType == nil {
		nlbTargetType_ := "ip"
		tmp.NlbTargetType = &nlbTargetType_
	}
	return &tmp
}

// IngressConfigInput is an input type that accepts IngressConfigArgs and IngressConfigOutput values.
// You can construct a concrete instance of `IngressConfigInput` via:
//
//	IngressConfigArgs{...}
type IngressConfigInput interface {
	pulumi.Input

	ToIngressConfigOutput() IngressConfigOutput
	ToIngressConfigOutputWithContext(context.Context) IngressConfigOutput
}

// Configuration for the ingress controller.
type IngressConfigArgs struct {
	// Additional configuration for the ingress controller.
	AdditionalConfig pulumi.StringMapInput `pulumi:"additionalConfig"`
	// The number of replicas of the ingress controller.
	ControllerReplicas pulumi.Float64PtrInput `pulumi:"controllerReplicas"`
	// Enable metrics for the ingress controller.
	EnableMetrics pulumi.BoolPtrInput `pulumi:"enableMetrics"`
	// Enable the service monitor for kube-prometheus-stackl.
	EnableServiceMonitor pulumi.BoolPtrInput `pulumi:"enableServiceMonitor"`
	// NLB target type for NLB loadbalancers.
	NlbTargetType pulumi.StringPtrInput `pulumi:"nlbTargetType"`
	// The namespace to deploy the service monitor to.
	ServiceMonitorNamespace pulumi.StringPtrInput `pulumi:"serviceMonitorNamespace"`
}

// Defaults sets the appropriate defaults for IngressConfigArgs
func (val *IngressConfigArgs) Defaults() *IngressConfigArgs {
	if val == nil {
		return nil
	}
	tmp := *val
	if tmp.ControllerReplicas == nil {
		tmp.ControllerReplicas = pulumi.Float64Ptr(1.0)
	}
	if tmp.EnableMetrics == nil {
		tmp.EnableMetrics = pulumi.BoolPtr(false)
	}
	if tmp.EnableServiceMonitor == nil {
		tmp.EnableServiceMonitor = pulumi.BoolPtr(false)
	}
	if tmp.NlbTargetType == nil {
		tmp.NlbTargetType = pulumi.StringPtr("ip")
	}
	return &tmp
}
func (IngressConfigArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*IngressConfig)(nil)).Elem()
}

func (i IngressConfigArgs) ToIngressConfigOutput() IngressConfigOutput {
	return i.ToIngressConfigOutputWithContext(context.Background())
}

func (i IngressConfigArgs) ToIngressConfigOutputWithContext(ctx context.Context) IngressConfigOutput {
	return pulumi.ToOutputWithContext(ctx, i).(IngressConfigOutput)
}

func (i IngressConfigArgs) ToOutput(ctx context.Context) pulumix.Output[IngressConfig] {
	return pulumix.Output[IngressConfig]{
		OutputState: i.ToIngressConfigOutputWithContext(ctx).OutputState,
	}
}

func (i IngressConfigArgs) ToIngressConfigPtrOutput() IngressConfigPtrOutput {
	return i.ToIngressConfigPtrOutputWithContext(context.Background())
}

func (i IngressConfigArgs) ToIngressConfigPtrOutputWithContext(ctx context.Context) IngressConfigPtrOutput {
	return pulumi.ToOutputWithContext(ctx, i).(IngressConfigOutput).ToIngressConfigPtrOutputWithContext(ctx)
}

// IngressConfigPtrInput is an input type that accepts IngressConfigArgs, IngressConfigPtr and IngressConfigPtrOutput values.
// You can construct a concrete instance of `IngressConfigPtrInput` via:
//
//	        IngressConfigArgs{...}
//
//	or:
//
//	        nil
type IngressConfigPtrInput interface {
	pulumi.Input

	ToIngressConfigPtrOutput() IngressConfigPtrOutput
	ToIngressConfigPtrOutputWithContext(context.Context) IngressConfigPtrOutput
}

type ingressConfigPtrType IngressConfigArgs

func IngressConfigPtr(v *IngressConfigArgs) IngressConfigPtrInput {
	return (*ingressConfigPtrType)(v)
}

func (*ingressConfigPtrType) ElementType() reflect.Type {
	return reflect.TypeOf((**IngressConfig)(nil)).Elem()
}

func (i *ingressConfigPtrType) ToIngressConfigPtrOutput() IngressConfigPtrOutput {
	return i.ToIngressConfigPtrOutputWithContext(context.Background())
}

func (i *ingressConfigPtrType) ToIngressConfigPtrOutputWithContext(ctx context.Context) IngressConfigPtrOutput {
	return pulumi.ToOutputWithContext(ctx, i).(IngressConfigPtrOutput)
}

func (i *ingressConfigPtrType) ToOutput(ctx context.Context) pulumix.Output[*IngressConfig] {
	return pulumix.Output[*IngressConfig]{
		OutputState: i.ToIngressConfigPtrOutputWithContext(ctx).OutputState,
	}
}

// Configuration for the ingress controller.
type IngressConfigOutput struct{ *pulumi.OutputState }

func (IngressConfigOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*IngressConfig)(nil)).Elem()
}

func (o IngressConfigOutput) ToIngressConfigOutput() IngressConfigOutput {
	return o
}

func (o IngressConfigOutput) ToIngressConfigOutputWithContext(ctx context.Context) IngressConfigOutput {
	return o
}

func (o IngressConfigOutput) ToIngressConfigPtrOutput() IngressConfigPtrOutput {
	return o.ToIngressConfigPtrOutputWithContext(context.Background())
}

func (o IngressConfigOutput) ToIngressConfigPtrOutputWithContext(ctx context.Context) IngressConfigPtrOutput {
	return o.ApplyTWithContext(ctx, func(_ context.Context, v IngressConfig) *IngressConfig {
		return &v
	}).(IngressConfigPtrOutput)
}

func (o IngressConfigOutput) ToOutput(ctx context.Context) pulumix.Output[IngressConfig] {
	return pulumix.Output[IngressConfig]{
		OutputState: o.OutputState,
	}
}

// Additional configuration for the ingress controller.
func (o IngressConfigOutput) AdditionalConfig() pulumi.StringMapOutput {
	return o.ApplyT(func(v IngressConfig) map[string]string { return v.AdditionalConfig }).(pulumi.StringMapOutput)
}

// The number of replicas of the ingress controller.
func (o IngressConfigOutput) ControllerReplicas() pulumi.Float64PtrOutput {
	return o.ApplyT(func(v IngressConfig) *float64 { return v.ControllerReplicas }).(pulumi.Float64PtrOutput)
}

// Enable metrics for the ingress controller.
func (o IngressConfigOutput) EnableMetrics() pulumi.BoolPtrOutput {
	return o.ApplyT(func(v IngressConfig) *bool { return v.EnableMetrics }).(pulumi.BoolPtrOutput)
}

// Enable the service monitor for kube-prometheus-stackl.
func (o IngressConfigOutput) EnableServiceMonitor() pulumi.BoolPtrOutput {
	return o.ApplyT(func(v IngressConfig) *bool { return v.EnableServiceMonitor }).(pulumi.BoolPtrOutput)
}

// NLB target type for NLB loadbalancers.
func (o IngressConfigOutput) NlbTargetType() pulumi.StringPtrOutput {
	return o.ApplyT(func(v IngressConfig) *string { return v.NlbTargetType }).(pulumi.StringPtrOutput)
}

// The namespace to deploy the service monitor to.
func (o IngressConfigOutput) ServiceMonitorNamespace() pulumi.StringPtrOutput {
	return o.ApplyT(func(v IngressConfig) *string { return v.ServiceMonitorNamespace }).(pulumi.StringPtrOutput)
}

type IngressConfigPtrOutput struct{ *pulumi.OutputState }

func (IngressConfigPtrOutput) ElementType() reflect.Type {
	return reflect.TypeOf((**IngressConfig)(nil)).Elem()
}

func (o IngressConfigPtrOutput) ToIngressConfigPtrOutput() IngressConfigPtrOutput {
	return o
}

func (o IngressConfigPtrOutput) ToIngressConfigPtrOutputWithContext(ctx context.Context) IngressConfigPtrOutput {
	return o
}

func (o IngressConfigPtrOutput) ToOutput(ctx context.Context) pulumix.Output[*IngressConfig] {
	return pulumix.Output[*IngressConfig]{
		OutputState: o.OutputState,
	}
}

func (o IngressConfigPtrOutput) Elem() IngressConfigOutput {
	return o.ApplyT(func(v *IngressConfig) IngressConfig {
		if v != nil {
			return *v
		}
		var ret IngressConfig
		return ret
	}).(IngressConfigOutput)
}

// Additional configuration for the ingress controller.
func (o IngressConfigPtrOutput) AdditionalConfig() pulumi.StringMapOutput {
	return o.ApplyT(func(v *IngressConfig) map[string]string {
		if v == nil {
			return nil
		}
		return v.AdditionalConfig
	}).(pulumi.StringMapOutput)
}

// The number of replicas of the ingress controller.
func (o IngressConfigPtrOutput) ControllerReplicas() pulumi.Float64PtrOutput {
	return o.ApplyT(func(v *IngressConfig) *float64 {
		if v == nil {
			return nil
		}
		return v.ControllerReplicas
	}).(pulumi.Float64PtrOutput)
}

// Enable metrics for the ingress controller.
func (o IngressConfigPtrOutput) EnableMetrics() pulumi.BoolPtrOutput {
	return o.ApplyT(func(v *IngressConfig) *bool {
		if v == nil {
			return nil
		}
		return v.EnableMetrics
	}).(pulumi.BoolPtrOutput)
}

// Enable the service monitor for kube-prometheus-stackl.
func (o IngressConfigPtrOutput) EnableServiceMonitor() pulumi.BoolPtrOutput {
	return o.ApplyT(func(v *IngressConfig) *bool {
		if v == nil {
			return nil
		}
		return v.EnableServiceMonitor
	}).(pulumi.BoolPtrOutput)
}

// NLB target type for NLB loadbalancers.
func (o IngressConfigPtrOutput) NlbTargetType() pulumi.StringPtrOutput {
	return o.ApplyT(func(v *IngressConfig) *string {
		if v == nil {
			return nil
		}
		return v.NlbTargetType
	}).(pulumi.StringPtrOutput)
}

// The namespace to deploy the service monitor to.
func (o IngressConfigPtrOutput) ServiceMonitorNamespace() pulumi.StringPtrOutput {
	return o.ApplyT(func(v *IngressConfig) *string {
		if v == nil {
			return nil
		}
		return v.ServiceMonitorNamespace
	}).(pulumi.StringPtrOutput)
}

// Represents a single requirement with key, operator, and values.
type Requirement struct {
	// The key of the requirement.
	Key *string `pulumi:"key"`
	// The operator for the requirement (e.g., In, Gt).
	Operator *string `pulumi:"operator"`
	// The list of values for the requirement.
	Values []string `pulumi:"values"`
}

// RequirementInput is an input type that accepts RequirementArgs and RequirementOutput values.
// You can construct a concrete instance of `RequirementInput` via:
//
//	RequirementArgs{...}
type RequirementInput interface {
	pulumi.Input

	ToRequirementOutput() RequirementOutput
	ToRequirementOutputWithContext(context.Context) RequirementOutput
}

// Represents a single requirement with key, operator, and values.
type RequirementArgs struct {
	// The key of the requirement.
	Key pulumi.StringPtrInput `pulumi:"key"`
	// The operator for the requirement (e.g., In, Gt).
	Operator pulumi.StringPtrInput `pulumi:"operator"`
	// The list of values for the requirement.
	Values pulumi.StringArrayInput `pulumi:"values"`
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

func (i RequirementArgs) ToOutput(ctx context.Context) pulumix.Output[Requirement] {
	return pulumix.Output[Requirement]{
		OutputState: i.ToRequirementOutputWithContext(ctx).OutputState,
	}
}

// RequirementArrayInput is an input type that accepts RequirementArray and RequirementArrayOutput values.
// You can construct a concrete instance of `RequirementArrayInput` via:
//
//	RequirementArray{ RequirementArgs{...} }
type RequirementArrayInput interface {
	pulumi.Input

	ToRequirementArrayOutput() RequirementArrayOutput
	ToRequirementArrayOutputWithContext(context.Context) RequirementArrayOutput
}

type RequirementArray []RequirementInput

func (RequirementArray) ElementType() reflect.Type {
	return reflect.TypeOf((*[]Requirement)(nil)).Elem()
}

func (i RequirementArray) ToRequirementArrayOutput() RequirementArrayOutput {
	return i.ToRequirementArrayOutputWithContext(context.Background())
}

func (i RequirementArray) ToRequirementArrayOutputWithContext(ctx context.Context) RequirementArrayOutput {
	return pulumi.ToOutputWithContext(ctx, i).(RequirementArrayOutput)
}

func (i RequirementArray) ToOutput(ctx context.Context) pulumix.Output[[]Requirement] {
	return pulumix.Output[[]Requirement]{
		OutputState: i.ToRequirementArrayOutputWithContext(ctx).OutputState,
	}
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
func (o RequirementOutput) Key() pulumi.StringPtrOutput {
	return o.ApplyT(func(v Requirement) *string { return v.Key }).(pulumi.StringPtrOutput)
}

// The operator for the requirement (e.g., In, Gt).
func (o RequirementOutput) Operator() pulumi.StringPtrOutput {
	return o.ApplyT(func(v Requirement) *string { return v.Operator }).(pulumi.StringPtrOutput)
}

// The list of values for the requirement.
func (o RequirementOutput) Values() pulumi.StringArrayOutput {
	return o.ApplyT(func(v Requirement) []string { return v.Values }).(pulumi.StringArrayOutput)
}

type RequirementArrayOutput struct{ *pulumi.OutputState }

func (RequirementArrayOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*[]Requirement)(nil)).Elem()
}

func (o RequirementArrayOutput) ToRequirementArrayOutput() RequirementArrayOutput {
	return o
}

func (o RequirementArrayOutput) ToRequirementArrayOutputWithContext(ctx context.Context) RequirementArrayOutput {
	return o
}

func (o RequirementArrayOutput) ToOutput(ctx context.Context) pulumix.Output[[]Requirement] {
	return pulumix.Output[[]Requirement]{
		OutputState: o.OutputState,
	}
}

func (o RequirementArrayOutput) Index(i pulumi.IntInput) RequirementOutput {
	return pulumi.All(o, i).ApplyT(func(vs []interface{}) Requirement {
		return vs[0].([]Requirement)[vs[1].(int)]
	}).(RequirementOutput)
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
	pulumi.RegisterInputType(reflect.TypeOf((*DisruptionConfigInput)(nil)).Elem(), DisruptionConfigArgs{})
	pulumi.RegisterInputType(reflect.TypeOf((*DisruptionConfigPtrInput)(nil)).Elem(), DisruptionConfigArgs{})
	pulumi.RegisterInputType(reflect.TypeOf((*IngressConfigInput)(nil)).Elem(), IngressConfigArgs{})
	pulumi.RegisterInputType(reflect.TypeOf((*IngressConfigPtrInput)(nil)).Elem(), IngressConfigArgs{})
	pulumi.RegisterInputType(reflect.TypeOf((*RequirementInput)(nil)).Elem(), RequirementArgs{})
	pulumi.RegisterInputType(reflect.TypeOf((*RequirementArrayInput)(nil)).Elem(), RequirementArray{})
	pulumi.RegisterOutputType(DisruptionConfigOutput{})
	pulumi.RegisterOutputType(DisruptionConfigPtrOutput{})
	pulumi.RegisterOutputType(IngressConfigOutput{})
	pulumi.RegisterOutputType(IngressConfigPtrOutput{})
	pulumi.RegisterOutputType(RequirementOutput{})
	pulumi.RegisterOutputType(RequirementArrayOutput{})
}

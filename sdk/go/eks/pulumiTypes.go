// Code generated by Pulumi SDK Generator DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package eks

import (
	"context"
	"reflect"

	"github.com/lbrlabs/pulumi-lbrlabs-eks/sdk/go/eks/internal"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

var _ = internal.GetEnvOrDefault

// Configuration for Autoscaled Node budgets.
type BudgetConfig struct {
	// The duration during which disruptuon can happen.
	Duration *string `pulumi:"duration"`
	// The maximum number of nodes that can be scaled down at any time.
	Nodes *string `pulumi:"nodes"`
	// A cron schedule for when disruption can happen.
	Schedule *string `pulumi:"schedule"`
}

// BudgetConfigInput is an input type that accepts BudgetConfigArgs and BudgetConfigOutput values.
// You can construct a concrete instance of `BudgetConfigInput` via:
//
//	BudgetConfigArgs{...}
type BudgetConfigInput interface {
	pulumi.Input

	ToBudgetConfigOutput() BudgetConfigOutput
	ToBudgetConfigOutputWithContext(context.Context) BudgetConfigOutput
}

// Configuration for Autoscaled Node budgets.
type BudgetConfigArgs struct {
	// The duration during which disruptuon can happen.
	Duration pulumi.StringPtrInput `pulumi:"duration"`
	// The maximum number of nodes that can be scaled down at any time.
	Nodes pulumi.StringPtrInput `pulumi:"nodes"`
	// A cron schedule for when disruption can happen.
	Schedule pulumi.StringPtrInput `pulumi:"schedule"`
}

func (BudgetConfigArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*BudgetConfig)(nil)).Elem()
}

func (i BudgetConfigArgs) ToBudgetConfigOutput() BudgetConfigOutput {
	return i.ToBudgetConfigOutputWithContext(context.Background())
}

func (i BudgetConfigArgs) ToBudgetConfigOutputWithContext(ctx context.Context) BudgetConfigOutput {
	return pulumi.ToOutputWithContext(ctx, i).(BudgetConfigOutput)
}

// BudgetConfigArrayInput is an input type that accepts BudgetConfigArray and BudgetConfigArrayOutput values.
// You can construct a concrete instance of `BudgetConfigArrayInput` via:
//
//	BudgetConfigArray{ BudgetConfigArgs{...} }
type BudgetConfigArrayInput interface {
	pulumi.Input

	ToBudgetConfigArrayOutput() BudgetConfigArrayOutput
	ToBudgetConfigArrayOutputWithContext(context.Context) BudgetConfigArrayOutput
}

type BudgetConfigArray []BudgetConfigInput

func (BudgetConfigArray) ElementType() reflect.Type {
	return reflect.TypeOf((*[]BudgetConfig)(nil)).Elem()
}

func (i BudgetConfigArray) ToBudgetConfigArrayOutput() BudgetConfigArrayOutput {
	return i.ToBudgetConfigArrayOutputWithContext(context.Background())
}

func (i BudgetConfigArray) ToBudgetConfigArrayOutputWithContext(ctx context.Context) BudgetConfigArrayOutput {
	return pulumi.ToOutputWithContext(ctx, i).(BudgetConfigArrayOutput)
}

// Configuration for Autoscaled Node budgets.
type BudgetConfigOutput struct{ *pulumi.OutputState }

func (BudgetConfigOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*BudgetConfig)(nil)).Elem()
}

func (o BudgetConfigOutput) ToBudgetConfigOutput() BudgetConfigOutput {
	return o
}

func (o BudgetConfigOutput) ToBudgetConfigOutputWithContext(ctx context.Context) BudgetConfigOutput {
	return o
}

// The duration during which disruptuon can happen.
func (o BudgetConfigOutput) Duration() pulumi.StringPtrOutput {
	return o.ApplyT(func(v BudgetConfig) *string { return v.Duration }).(pulumi.StringPtrOutput)
}

// The maximum number of nodes that can be scaled down at any time.
func (o BudgetConfigOutput) Nodes() pulumi.StringPtrOutput {
	return o.ApplyT(func(v BudgetConfig) *string { return v.Nodes }).(pulumi.StringPtrOutput)
}

// A cron schedule for when disruption can happen.
func (o BudgetConfigOutput) Schedule() pulumi.StringPtrOutput {
	return o.ApplyT(func(v BudgetConfig) *string { return v.Schedule }).(pulumi.StringPtrOutput)
}

type BudgetConfigArrayOutput struct{ *pulumi.OutputState }

func (BudgetConfigArrayOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*[]BudgetConfig)(nil)).Elem()
}

func (o BudgetConfigArrayOutput) ToBudgetConfigArrayOutput() BudgetConfigArrayOutput {
	return o
}

func (o BudgetConfigArrayOutput) ToBudgetConfigArrayOutputWithContext(ctx context.Context) BudgetConfigArrayOutput {
	return o
}

func (o BudgetConfigArrayOutput) Index(i pulumi.IntInput) BudgetConfigOutput {
	return pulumi.All(o, i).ApplyT(func(vs []interface{}) BudgetConfig {
		return vs[0].([]BudgetConfig)[vs[1].(int)]
	}).(BudgetConfigOutput)
}

// Configuration for Autoscaled nodes disruption.
type DisruptionConfig struct {
	// Budgets control the speed Karpenter can scale down nodes.
	Budgets []BudgetConfig `pulumi:"budgets"`
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
	if tmp.ConsolidationPolicy == nil {
		consolidationPolicy_ := "WhenEmpty"
		tmp.ConsolidationPolicy = &consolidationPolicy_
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
	// Budgets control the speed Karpenter can scale down nodes.
	Budgets BudgetConfigArrayInput `pulumi:"budgets"`
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
	if tmp.ConsolidationPolicy == nil {
		tmp.ConsolidationPolicy = pulumi.StringPtr("WhenEmpty")
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

// Budgets control the speed Karpenter can scale down nodes.
func (o DisruptionConfigOutput) Budgets() BudgetConfigArrayOutput {
	return o.ApplyT(func(v DisruptionConfig) []BudgetConfig { return v.Budgets }).(BudgetConfigArrayOutput)
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

func (o DisruptionConfigPtrOutput) Elem() DisruptionConfigOutput {
	return o.ApplyT(func(v *DisruptionConfig) DisruptionConfig {
		if v != nil {
			return *v
		}
		var ret DisruptionConfig
		return ret
	}).(DisruptionConfigOutput)
}

// Budgets control the speed Karpenter can scale down nodes.
func (o DisruptionConfigPtrOutput) Budgets() BudgetConfigArrayOutput {
	return o.ApplyT(func(v *DisruptionConfig) []BudgetConfig {
		if v == nil {
			return nil
		}
		return v.Budgets
	}).(BudgetConfigArrayOutput)
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
	pulumi.RegisterInputType(reflect.TypeOf((*BudgetConfigInput)(nil)).Elem(), BudgetConfigArgs{})
	pulumi.RegisterInputType(reflect.TypeOf((*BudgetConfigArrayInput)(nil)).Elem(), BudgetConfigArray{})
	pulumi.RegisterInputType(reflect.TypeOf((*DisruptionConfigInput)(nil)).Elem(), DisruptionConfigArgs{})
	pulumi.RegisterInputType(reflect.TypeOf((*DisruptionConfigPtrInput)(nil)).Elem(), DisruptionConfigArgs{})
	pulumi.RegisterInputType(reflect.TypeOf((*IngressConfigInput)(nil)).Elem(), IngressConfigArgs{})
	pulumi.RegisterInputType(reflect.TypeOf((*IngressConfigPtrInput)(nil)).Elem(), IngressConfigArgs{})
	pulumi.RegisterInputType(reflect.TypeOf((*RequirementInput)(nil)).Elem(), RequirementArgs{})
	pulumi.RegisterInputType(reflect.TypeOf((*RequirementArrayInput)(nil)).Elem(), RequirementArray{})
	pulumi.RegisterOutputType(BudgetConfigOutput{})
	pulumi.RegisterOutputType(BudgetConfigArrayOutput{})
	pulumi.RegisterOutputType(DisruptionConfigOutput{})
	pulumi.RegisterOutputType(DisruptionConfigPtrOutput{})
	pulumi.RegisterOutputType(IngressConfigOutput{})
	pulumi.RegisterOutputType(IngressConfigPtrOutput{})
	pulumi.RegisterOutputType(RequirementOutput{})
	pulumi.RegisterOutputType(RequirementArrayOutput{})
}

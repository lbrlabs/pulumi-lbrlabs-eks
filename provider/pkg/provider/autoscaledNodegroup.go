package provider

import (
	"fmt"
	"github.com/pulumi/pulumi-kubernetes/sdk/v4/go/kubernetes/apiextensions"
	metav1 "github.com/pulumi/pulumi-kubernetes/sdk/v4/go/kubernetes/meta/v1"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

type BudgetConfig struct {
	Nodes    pulumi.StringInput `pulumi:"nodes"`
	Schedule pulumi.StringInput `pulumi:"schedule"`
	Duration pulumi.StringInput `pulumi:"duration"`
}

type DisruptionConfig struct {
	ConsolidationPolicy pulumi.StringInput `pulumi:"consolidationPolicy"`
	ConsolidateAfter    pulumi.StringInput `pulumi:"consolidateAfter"`
	ExpireAfter         pulumi.StringInput `pulumi:"expireAfter"`
	Budgets             []BudgetConfig     `pulumi:"budgets"`
}

type AutoscaledNodeGroupArgs struct {
	Annotations      *pulumi.StringMapInput  `pulumi:"annotations"`
	AMIFamily        *pulumi.StringInput     `pulumi:"amiFamily"`
	AmiID            *pulumi.StringInput     `pulumi:"amiId"`
	DiskSize         pulumi.StringInput      `pulumi:"diskSize"`
	Taints           pulumi.ArrayInput       `pulumi:"taints"`
	NodeRole         pulumi.StringInput      `pulumi:"nodeRole"`
	SubnetIds        pulumi.StringArrayInput `pulumi:"subnetIds"`
	SecurityGroupIds pulumi.StringArrayInput `pulumi:"securityGroupIds"`
	Requirements     pulumi.ArrayInput       `pulumi:"requirements"`
	Labels           *pulumi.StringMapInput  `pulumi:"labels"`
	Disruption       *DisruptionConfig       `pulumi:"disruption"`
}

type AutoscaledNodeGroup struct {
	pulumi.ResourceState
}

// NewNodeGroup creates a new EKS Node group component resource.
func NewAutoscaledNodeGroup(ctx *pulumi.Context,
	name string, args *AutoscaledNodeGroupArgs, opts ...pulumi.ResourceOption) (*NodeGroup, error) {
	if args == nil {
		args = &AutoscaledNodeGroupArgs{}
	}

	component := &NodeGroup{}
	err := ctx.RegisterComponentResource("lbrlabs-eks:index:AutoscaledNodeGroup", name, component, opts...)
	if err != nil {
		return nil, err
	}

	var amiFamily pulumi.StringInput

	if args.AMIFamily == nil {
		amiFamily = pulumi.String("AL2")
	} else {
		amiFamily = *args.AMIFamily
	}

	var annotations pulumi.StringMapInput
	if args.Annotations == nil {
		annotations = pulumi.StringMap{}
	} else {
		annotations = *args.Annotations
	}

	var labels pulumi.StringMapInput
	if args.Labels == nil {
		labels = pulumi.StringMap{
			"node.lbrlabs.com/name": pulumi.String(name),
		}
	} else {
		labels = *args.Labels
	}

	var disruption DisruptionConfig

	if args.Disruption == nil {
		disruption = DisruptionConfig{}
	} else {
		disruption = *args.Disruption
	}

	subnetSelectorTermsProcessed := args.SubnetIds.ToStringArrayOutput().ApplyT(func(input interface{}) ([]interface{}, error) {
		subnetIds, ok := input.([]string)
		if !ok {
			return nil, fmt.Errorf("invalid type for subnetIds, expected []string")
		}

		var subnetSelectorTerms []interface{}
		for _, id := range subnetIds {
			subnetSelectorTerm := map[string]interface{}{
				"id": id,
			}
			subnetSelectorTerms = append(subnetSelectorTerms, subnetSelectorTerm)
		}
		return subnetSelectorTerms, nil
	}).(pulumi.ArrayOutput)

	securityGroupSelectorTermsProcessed := args.SecurityGroupIds.ToStringArrayOutput().ApplyT(func(input interface{}) ([]interface{}, error) {
		securityGroupIds, ok := input.([]string)
		if !ok {
			return nil, fmt.Errorf("invalid type for securityGroupIds, expected []string")
		}

		var securityGroupSelectorTerms []interface{}
		for _, id := range securityGroupIds {
			securityGroupSelectorTerm := map[string]interface{}{
				"id": id,
			}
			securityGroupSelectorTerms = append(securityGroupSelectorTerms, securityGroupSelectorTerm)
		}
		return securityGroupSelectorTerms, nil
	}).(pulumi.ArrayOutput)

	spec := map[string]interface{}{
		"amiFamily":                  amiFamily,
		"role":                       args.NodeRole,
		"subnetSelectorTerms":        subnetSelectorTermsProcessed,
		"securityGroupSelectorTerms": securityGroupSelectorTermsProcessed,
		"blockDeviceMappings": []map[string]interface{}{
			{
				"deviceName": "/dev/xvda",
				"ebs": map[string]interface{}{
					"encrypted":  pulumi.Bool(true),
					"volumeSize": args.DiskSize,
					"volumeType": pulumi.String("gp3"),
				},
			},
		},
	}

	if args.AmiID != nil {
		spec["amiSelectorTerms"] = []map[string]interface{}{
			{
				"id": *args.AmiID,
			},
		}
	}

	nodeClass, err := apiextensions.NewCustomResource(ctx, fmt.Sprintf("%s-nodeclass", name), &apiextensions.CustomResourceArgs{
		ApiVersion: pulumi.String("karpenter.k8s.aws/v1beta1"),
		Kind:       pulumi.String("EC2NodeClass"),
		Metadata: metav1.ObjectMetaArgs{
			Annotations: annotations,
		},
		OtherFields: map[string]interface{}{
			"spec": spec,
		},
	}, pulumi.Parent(component))
	if err != nil {
		return nil, fmt.Errorf("error creating autoscaled node class: %w", err)
	}

	var budgetsInput []interface{}
	for _, budget := range disruption.Budgets {
		budgetsInput = append(budgetsInput, map[string]interface{}{
			"nodes":    budget.Nodes,
			"schedule": budget.Schedule,
			"duration": budget.Duration,
		})
	}

	_, err = apiextensions.NewCustomResource(ctx, fmt.Sprintf("%s-nodepool", name), &apiextensions.CustomResourceArgs{
		ApiVersion: pulumi.String("karpenter.sh/v1beta1"),
		Kind:       pulumi.String("NodePool"),
		Metadata: metav1.ObjectMetaArgs{
			Annotations: annotations,
		},
		OtherFields: map[string]interface{}{
			"spec": map[string]interface{}{
				"disruption": map[string]interface{}{
					"consolidationPolicy": disruption.ConsolidationPolicy,
					"consolidateAfter":    disruption.ConsolidateAfter,
					"expireAfter":         disruption.ExpireAfter,
					"budgets":             budgetsInput,
				},
				"template": map[string]interface{}{
					"metadata": map[string]interface{}{
						"labels": labels,
					},
					"spec": map[string]interface{}{
						"requirements": args.Requirements,
						"nodeClassRef": map[string]interface{}{
							"name": nodeClass.Metadata.Name(),
						},
						"taints": args.Taints,
					},
				},
			},
		},
	}, pulumi.Parent(nodeClass))
	if err != nil {
		return nil, fmt.Errorf("error creating autoscaled node pool: %w", err)
	}

	if err := ctx.RegisterResourceOutputs(component, pulumi.Map{}); err != nil {
		return nil, err
	}

	return component, nil

}

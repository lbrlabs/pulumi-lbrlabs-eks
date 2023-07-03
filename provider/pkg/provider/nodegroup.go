package provider

import (
	"encoding/json"
	"fmt"
	"github.com/pulumi/pulumi-aws/sdk/v5/go/aws/eks"
	"github.com/pulumi/pulumi-aws/sdk/v5/go/aws/iam"
	//"github.com/pulumi/pulumi-kubernetes/sdk/v3/go/kubernetes"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

type NodeGroupArgs struct {
	ClusterName        pulumi.StringInput             `pulumi:"clusterName"`
	SubnetIds          pulumi.StringArrayInput        `pulumi:"subnetIds"`
	InstanceTypes      *pulumi.StringArrayInput       `pulumi:"instanceTypes"`
	NodeMaxCount       *pulumi.IntInput               `pulumi:"nodeMaxCount"`
	NodeMinCount       *pulumi.IntInput               `pulumi:"nodeMinCount"`
	NodeDesiredCount   *pulumi.IntInput               `pulumi:"nodeDesiredCount"`
	Taints             eks.NodeGroupTaintArray        `pulumi:"taints"`
	Labels             pulumi.StringMapInput          `pulumi:"labels"`
	ScalingConfig      eks.NodeGroupScalingConfigArgs `pulumi:"scalingConfig"`
}

type NodeGroup struct {
	pulumi.ResourceState

	NodeGroup *eks.NodeGroup `pulumi:"attachedNodeGroup"`
	Role      *iam.Role      `pulumi:"nodeRole"`
}

// NewNodeGroup creates a new EKS Node group component resource.
func NewNodeGroup(ctx *pulumi.Context,
	name string, args *NodeGroupArgs, opts ...pulumi.ResourceOption) (*NodeGroup, error) {
	if args == nil {
		args = &NodeGroupArgs{}
	}

	component := &NodeGroup{}
	err := ctx.RegisterComponentResource("lbrlabs-eks:index:AttachedNodeGroup", name, component, opts...)
	if err != nil {
		return nil, err
	}

	nodePolicyJSON, err := json.Marshal(map[string]interface{}{
		"Statement": []map[string]interface{}{
			{
				"Action": "sts:AssumeRole",
				"Effect": "Allow",
				"Principal": map[string]interface{}{
					"Service": "ec2.amazonaws.com",
				},
			},
		},
		"Version": "2012-10-17",
	})
	if err != nil {
		return nil, fmt.Errorf("error marshalling node policy: %w", err)
	}

	nodeRole, err := iam.NewRole(ctx, fmt.Sprintf("%s-node-role", name), &iam.RoleArgs{
		AssumeRolePolicy: pulumi.String(nodePolicyJSON),
	}, pulumi.Parent(component))
	if err != nil {
		return nil, fmt.Errorf("error creating node role: %w", err)
	}

	_, err = iam.NewRolePolicyAttachment(ctx, fmt.Sprintf("%s-node-worker-policy", name), &iam.RolePolicyAttachmentArgs{
		PolicyArn: pulumi.String("arn:aws:iam::aws:policy/AmazonEKSWorkerNodePolicy"),
		Role:      nodeRole.Name,
	}, pulumi.Parent(nodeRole))
	if err != nil {
		return nil, fmt.Errorf("error attaching node worker policy: %w", err)
	}

	_, err = iam.NewRolePolicyAttachment(ctx, fmt.Sprintf("%s-node-ecr-policy", name), &iam.RolePolicyAttachmentArgs{
		PolicyArn: pulumi.String("arn:aws:iam::aws:policy/AmazonEC2ContainerRegistryReadOnly"),
		Role:      nodeRole.Name,
	}, pulumi.Parent(nodeRole))
	if err != nil {
		return nil, fmt.Errorf("error attaching system node ecr policy: %w", err)
	}

	var instanceTypes pulumi.StringArrayInput

	if args.InstanceTypes == nil {
		instanceTypes = pulumi.StringArray{
			pulumi.String("t3.medium"),
		}
	} else {
		instanceTypes = *args.InstanceTypes
	}

	nodeGroup, err := eks.NewNodeGroup(ctx, fmt.Sprintf("%s-nodes", name), &eks.NodeGroupArgs{
		ClusterName:   args.ClusterName,
		SubnetIds:     args.SubnetIds,
		NodeRoleArn:   nodeRole.Arn,
		Taints:        args.Taints,
		InstanceTypes: instanceTypes,
		Labels:        args.Labels,
		ScalingConfig: args.ScalingConfig,
	}, pulumi.Parent(component), pulumi.IgnoreChanges([]string{"scalingConfig"}))
	if err != nil {
		return nil, fmt.Errorf("error creating system nodegroup provider: %w", err)
	}

	component.NodeGroup = nodeGroup
	component.Role = nodeRole

	if err := ctx.RegisterResourceOutputs(component, pulumi.Map{
		"nodeGroup": nodeGroup,
		"nodeRole":  nodeRole,
	}); err != nil {
		return nil, err
	}

	return component, nil

}

package provider

import (
	"encoding/json"
	"fmt"
	"github.com/pulumi/pulumi-aws/sdk/v6/go/aws/eks"
	"github.com/pulumi/pulumi-aws/sdk/v6/go/aws/iam"
	//"github.com/pulumi/pulumi-kubernetes/sdk/v4/go/kubernetes"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

type NodeGroupArgs struct {
	ClusterName      pulumi.StringInput              `pulumi:"clusterName"`
	SubnetIds        pulumi.StringArrayInput         `pulumi:"subnetIds"`
	CapacityType     *pulumi.StringInput             `pulumi:"capacityType"`
	InstanceTypes    *pulumi.StringArrayInput        `pulumi:"instanceTypes"`
	NodeMaxCount     *pulumi.IntInput                `pulumi:"nodeMaxCount"`
	DiskSize         *pulumi.IntInput                `pulumi:"diskSize"`
	NodeMinCount     *pulumi.IntInput                `pulumi:"nodeMinCount"`
	NodeDesiredCount *pulumi.IntInput                `pulumi:"nodeDesiredCount"`
	Taints           eks.NodeGroupTaintArrayInput    `pulumi:"taints"`
	Labels           pulumi.StringMapInput           `pulumi:"labels"`
	ScalingConfig    eks.NodeGroupScalingConfigInput `pulumi:"scalingConfig"`
	Tags             *pulumi.StringMapInput          `pulumi:"tags"`
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

	var tags pulumi.StringMapInput

	if args.Tags != nil {
		tags = *args.Tags
	} else {
		if err := ctx.Log.Debug("No tags provided, defaulting to empty map", &pulumi.LogArgs{Resource: component}); err != nil {
			return nil, err
		}
		tags = pulumi.StringMap{}
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
		Tags:             tags,
	}, pulumi.Parent(component))
	if err != nil {
		return nil, fmt.Errorf("error creating node role: %w", err)
	}

	workerNodePolicyAttachment, err := iam.NewRolePolicyAttachment(ctx, fmt.Sprintf("%s-node-worker-policy", name), &iam.RolePolicyAttachmentArgs{
		PolicyArn: pulumi.String("arn:aws:iam::aws:policy/AmazonEKSWorkerNodePolicy"),
		Role:      nodeRole.Name,
	}, pulumi.Parent(nodeRole))
	if err != nil {
		return nil, fmt.Errorf("error attaching node worker policy: %w", err)
	}

	ecrPolicyAttachment, err := iam.NewRolePolicyAttachment(ctx, fmt.Sprintf("%s-node-ecr-policy", name), &iam.RolePolicyAttachmentArgs{
		PolicyArn: pulumi.String("arn:aws:iam::aws:policy/AmazonEC2ContainerRegistryReadOnly"),
		Role:      nodeRole.Name,
	}, pulumi.Parent(nodeRole))
	if err != nil {
		return nil, fmt.Errorf("error attaching system node ecr policy: %w", err)
	}

	_, err = iam.NewRolePolicyAttachment(ctx, fmt.Sprintf("%s-node-ssm-policy", name), &iam.RolePolicyAttachmentArgs{
		PolicyArn: pulumi.String("arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"),
		Role:      nodeRole.Name,
	}, pulumi.Parent(nodeRole))
	if err != nil {
		return nil, fmt.Errorf("error attaching system node ecr policy: %w", err)
	}

	_, err = NewRoleMapping(ctx, fmt.Sprintf("%s-aws-auth-role-mapping", name), &RoleMappingArgs{
		RoleArn:  nodeRole.Arn,
		Username: pulumi.String("system:node:{{EC2PrivateDNSName}}"),
		Groups: pulumi.StringArray{
			pulumi.String("system:bootstrappers"),
			pulumi.String("system:nodes"),
		},
	}, pulumi.Parent(nodeRole))
	if err != nil {
		return nil, fmt.Errorf("error creating aws-auth role mapping: %w", err)
	}

	var instanceTypes pulumi.StringArrayInput

	if args.InstanceTypes == nil {
		if err := ctx.Log.Debug("No instance types provided, defaulting to t3.medium", &pulumi.LogArgs{Resource: component}); err != nil {
			return nil, err
		}
		instanceTypes = pulumi.StringArray{
			pulumi.String("t3.medium"),
		}
	} else {
		instanceTypes = *args.InstanceTypes
	}

	var capacityType pulumi.StringInput

	if args.CapacityType == nil {
		if err := ctx.Log.Debug("No capacity type provider, default to ON_DEMAND", &pulumi.LogArgs{Resource: component}); err != nil {
			return nil, err
		}
		capacityType = pulumi.String("ON_DEMAND")
	} else {
		capacityType = *args.CapacityType
	}

	var diskSize pulumi.IntInput

	if args.DiskSize == nil {
		if err := ctx.Log.Debug("No disk size provided, default to 20gb", &pulumi.LogArgs{Resource: component}); err != nil {
			return nil, err
		}
		diskSize = pulumi.Int(20)
	} else {
		diskSize = *args.DiskSize
	}

	nodeGroup, err := eks.NewNodeGroup(ctx, fmt.Sprintf("%s-nodes", name), &eks.NodeGroupArgs{
		ClusterName:   args.ClusterName,
		SubnetIds:     args.SubnetIds,
		CapacityType:  capacityType,
		NodeRoleArn:   nodeRole.Arn,
		DiskSize:      diskSize,
		Taints:        args.Taints,
		InstanceTypes: instanceTypes,
		Labels:        args.Labels,
		ScalingConfig: args.ScalingConfig,
		Tags:          tags,
	},
		pulumi.Parent(component),
		pulumi.IgnoreChanges([]string{"scalingConfig"}),
		pulumi.DependsOn([]pulumi.Resource{nodeRole, ecrPolicyAttachment, workerNodePolicyAttachment}),
	)
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

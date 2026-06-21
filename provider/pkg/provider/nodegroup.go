package provider

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/pulumi/pulumi-aws/sdk/v6/go/aws"
	"github.com/pulumi/pulumi-aws/sdk/v6/go/aws/eks"
	"github.com/pulumi/pulumi-aws/sdk/v6/go/aws/iam"
	"github.com/pulumi/pulumi-aws/sdk/v6/go/aws/ssm"

	//"github.com/pulumi/pulumi-kubernetes/sdk/v4/go/kubernetes"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

type NodeGroupArgs struct {
	ClusterName      pulumi.StringInput              `pulumi:"clusterName"`
	ClusterVersion   pulumi.StringPtrInput           `pulumi:"-"`
	SubnetIds        pulumi.StringArrayInput         `pulumi:"subnetIds"`
	CapacityType     *pulumi.StringInput             `pulumi:"capacityType"`
	InstanceTypes    *pulumi.StringArrayInput        `pulumi:"instanceTypes"`
	NodeMaxCount     *pulumi.IntInput                `pulumi:"nodeMaxCount"`
	DiskSize         *pulumi.IntInput                `pulumi:"diskSize"`
	NodeMinCount     *pulumi.IntInput                `pulumi:"nodeMinCount"`
	NodeDesiredCount *pulumi.IntInput                `pulumi:"nodeDesiredCount"`
	Taints           eks.NodeGroupTaintArrayInput    `pulumi:"taints"`
	Labels           pulumi.StringMapInput           `pulumi:"labels"`
	AMIType          pulumi.StringPtrInput           `pulumi:"amiType"`
	ReleaseVersion   pulumi.StringPtrInput           `pulumi:"releaseVersion"`
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

	current, err := aws.GetPartition(ctx, nil, pulumi.Parent(component))
	if err != nil {
		return nil, fmt.Errorf("error getting partition: %w", err)
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
					"Service": fmt.Sprintf("ec2.%s", current.DnsSuffix),
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
		PolicyArn: pulumi.Sprintf("arn:%s:iam::aws:policy/AmazonEKSWorkerNodePolicy", current.Partition),
		Role:      nodeRole.Name,
	}, pulumi.Parent(nodeRole))
	if err != nil {
		return nil, fmt.Errorf("error attaching node worker policy: %w", err)
	}

	ecrPolicyAttachment, err := iam.NewRolePolicyAttachment(ctx, fmt.Sprintf("%s-node-ecr-policy", name), &iam.RolePolicyAttachmentArgs{
		PolicyArn: pulumi.Sprintf("arn:%s:iam::aws:policy/AmazonEC2ContainerRegistryReadOnly", current.Partition),
		Role:      nodeRole.Name,
	}, pulumi.Parent(nodeRole))
	if err != nil {
		return nil, fmt.Errorf("error attaching node ecr policy: %w", err)
	}

	_, err = iam.NewRolePolicyAttachment(ctx, fmt.Sprintf("%s-node-ssm-policy", name), &iam.RolePolicyAttachmentArgs{
		PolicyArn: pulumi.Sprintf("arn:%s:iam::aws:policy/AmazonSSMManagedInstanceCore", current.Partition),
		Role:      nodeRole.Name,
	}, pulumi.Parent(nodeRole))
	if err != nil {
		return nil, fmt.Errorf("error attaching node ecr policy: %w", err)
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
	ignoreChanges := []string{"scalingConfig"}

	if args.DiskSize == nil {
		if err := ctx.Log.Debug("No disk size provided, default to 40gb", &pulumi.LogArgs{Resource: component}); err != nil {
			return nil, err
		}
		diskSize = pulumi.Int(40)
		ignoreChanges = append(ignoreChanges, "diskSize")
	} else {
		diskSize = *args.DiskSize
	}

	amiType := args.AMIType
	releaseVersion := args.ReleaseVersion

	if args.AMIType == nil && args.ReleaseVersion == nil {
		amiTypeOutput := instanceTypes.ToStringArrayOutput().ApplyT(
			func(instanceTypes []string) (string, error) {
				return nodeGroupAMIType(instanceTypes)
			},
		).(pulumi.StringOutput)
		amiType = amiTypeOutput.ToStringPtrOutput()
	}

	if args.ReleaseVersion == nil {
		clusterVersion := args.ClusterVersion
		if clusterVersion == nil {
			cluster := eks.LookupClusterOutput(ctx, eks.LookupClusterOutputArgs{
				Name: args.ClusterName,
			}, pulumi.Parent(component))
			clusterVersion = cluster.Version().ToStringPtrOutput()
		}

		amiPath := instanceTypes.ToStringArrayOutput().ApplyT(
			func(instanceTypes []string) (string, error) {
				return nodeGroupAMIPath(instanceTypes)
			},
		).(pulumi.StringOutput)

		amiMetadata := ssm.LookupParameterOutput(ctx, ssm.LookupParameterOutputArgs{
			Name: pulumi.Sprintf(
				"/aws/service/eks/optimized-ami/%s/%s/recommended",
				clusterVersion,
				amiPath,
			),
		}, pulumi.Parent(component))

		releaseVersion = amiMetadata.InsecureValue().ApplyT(
			func(value string) (string, error) {
				var metadata struct {
					ReleaseVersion string `json:"release_version"`
				}
				if err := json.Unmarshal([]byte(value), &metadata); err != nil {
					return "", fmt.Errorf("error parsing EKS AMI metadata: %w", err)
				}
				if metadata.ReleaseVersion == "" {
					return "", fmt.Errorf("EKS AMI metadata did not include release_version")
				}
				return metadata.ReleaseVersion, nil
			},
		).(pulumi.StringOutput).ToStringPtrOutput()
	}

	nodeGroup, err := eks.NewNodeGroup(ctx, fmt.Sprintf("%s-nodes", name), &eks.NodeGroupArgs{
		ClusterName:    args.ClusterName,
		SubnetIds:      args.SubnetIds,
		CapacityType:   capacityType,
		NodeRoleArn:    nodeRole.Arn,
		AmiType:        amiType,
		DiskSize:       diskSize,
		ReleaseVersion: releaseVersion,
		Taints:         args.Taints,
		InstanceTypes:  instanceTypes,
		Labels:         args.Labels,
		ScalingConfig:  args.ScalingConfig,
		Tags:           tags,
		UpdateConfig: eks.NodeGroupUpdateConfigArgs{
			MaxUnavailable: pulumi.Int(1),
		},
	},
		pulumi.Parent(component),
		pulumi.IgnoreChanges(ignoreChanges),
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

func nodeGroupAMIArchitecture(instanceTypes []string) (string, error) {
	if len(instanceTypes) == 0 {
		return "x86_64", nil
	}

	var architecture string
	for _, instanceType := range instanceTypes {
		currentArchitecture := "x86_64"
		if isArmInstanceType(instanceType) {
			currentArchitecture = "arm64"
		}

		if architecture == "" {
			architecture = currentArchitecture
			continue
		}

		if architecture != currentArchitecture {
			return "", fmt.Errorf("attached node group instance types must not mix CPU architectures")
		}
	}

	return architecture, nil
}

func nodeGroupAMIType(instanceTypes []string) (string, error) {
	architecture, err := nodeGroupAMIArchitecture(instanceTypes)
	if err != nil {
		return "", err
	}

	switch architecture {
	case "arm64":
		return "AL2023_ARM_64_STANDARD", nil
	case "x86_64":
		return "AL2023_x86_64_STANDARD", nil
	default:
		return "", fmt.Errorf("unsupported attached node group architecture: %s", architecture)
	}
}

func nodeGroupAMIPath(instanceTypes []string) (string, error) {
	architecture, err := nodeGroupAMIArchitecture(instanceTypes)
	if err != nil {
		return "", err
	}

	switch architecture {
	case "arm64":
		return "amazon-linux-2023/arm64/standard", nil
	case "x86_64":
		return "amazon-linux-2023/x86_64/standard", nil
	default:
		return "", fmt.Errorf("unsupported attached node group architecture: %s", architecture)
	}
}

func isArmInstanceType(instanceType string) bool {
	family := strings.Split(instanceType, ".")[0]
	armPrefixes := []string{
		"a1",
		"c6g", "c7g", "c8g",
		"im4gn", "is4gen",
		"m6g", "m7g", "m8g",
		"r6g", "r7g", "r8g",
		"t4g",
		"x2gd",
	}

	for _, prefix := range armPrefixes {
		if strings.HasPrefix(family, prefix) {
			return true
		}
	}

	return false
}

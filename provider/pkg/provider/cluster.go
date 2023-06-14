package provider

import (
	"encoding/json"
	"fmt"

	"github.com/lbrlabs/pulumi-lbrlabs-eks/pkg/provider/kubeconfig"
	"github.com/pulumi/pulumi-aws/sdk/v5/go/aws/eks"
	"github.com/pulumi/pulumi-aws/sdk/v5/go/aws/iam"
	"github.com/pulumi/pulumi-aws/sdk/v5/go/aws/kms"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// The set of arguments for creating a Cluster component resource.
type ClusterArgs struct {
	VpcId               pulumi.StringInput      `pulumi:"vpcId"`
	ClusterSubnetIds    pulumi.StringArrayInput `pulumi:"clusterSubnetIds"`
	SystemNodeSubnetIds pulumi.StringArrayInput `pulumi:"systemNodeSubnetIds"`
}

// The Cluster component resource.
type Cluster struct {
	pulumi.ResourceState

	ControlPlane *eks.Cluster               `pulumi:"controlPlane"`
	SystemNodes  *eks.NodeGroup             `pulumi:"systemNodes"`
	OidcProvider *iam.OpenIdConnectProvider `pulumi:"oidcProvider"`
	KubeConfig   pulumi.StringOutput        `pulumi:"kubeconfig"`
}

// NewCluster creates a new EKS Cluster component resource.
func NewCluster(ctx *pulumi.Context,
	name string, args *ClusterArgs, opts ...pulumi.ResourceOption) (*Cluster, error) {
	if args == nil {
		args = &ClusterArgs{}
	}

	component := &Cluster{}
	err := ctx.RegisterComponentResource("lbrlabs-eks:index:Cluster", name, component, opts...)
	if err != nil {
		return nil, err
	}

	// FIXME: make this strongly typed instead of using interfaces
	clusterRoleJSON, err := json.Marshal(map[string]interface{}{
		"Version": "2012-10-17",
		"Statement": []interface{}{
			map[string]interface{}{
				"Action": "sts:AssumeRole",
				"Principal": map[string]interface{}{
					"Service": []interface{}{
						"eks.amazonaws.com",
					},
				},
				"Effect": "Allow",
			},
		},
	})
	if err != nil {
		return nil, fmt.Errorf("error marshalling cluster role json: %w", err)
	}

	role, err := iam.NewRole(ctx, fmt.Sprintf("%s-cluster-role", name), &iam.RoleArgs{
		AssumeRolePolicy: pulumi.String(clusterRoleJSON),
	}, pulumi.Parent(component))
	if err != nil {
		return nil, fmt.Errorf("error creating cluster role: %w", err)
	}

	_, err = iam.NewRolePolicyAttachment(ctx, fmt.Sprintf("%s-cluster-policy", name), &iam.RolePolicyAttachmentArgs{
		Role:      role.Name,
		PolicyArn: pulumi.String("arn:aws:iam::aws:policy/AmazonEKSClusterPolicy"),
	}, pulumi.Parent(role))
	if err != nil {
		return nil, fmt.Errorf("error attaching cluster policy: %w", err)
	}

	// clusterSecurityGroup, err := ec2.NewSecurityGroup(ctx, fmt.Sprintf("%s-cluster-sg", name), &ec2.SecurityGroupArgs{
	// 	VpcId: args.VpcId,
	// 	RevokeRulesOnDelete: pulumi.Bool(true),
	// }, pulumi.Parent(component))
	// if err != nil {
	// 	return nil, fmt.Errorf("error creating cluster security group: %w", err)
	// }

	// FIXME: ensure we have a key policy for this key that's sane
	kmsKey, err := kms.NewKey(ctx, fmt.Sprintf("%s-cluster-kms-key", name), &kms.KeyArgs{
		EnableKeyRotation: pulumi.Bool(true),
		Description:       pulumi.String("KMS key for EKS cluster secrets"),
	}, pulumi.Parent(component))
	if err != nil {
		return nil, fmt.Errorf("error creating cluster kms key: %w", err)
	}

	controlPlane, err := eks.NewCluster(ctx, name, &eks.ClusterArgs{
		RoleArn: role.Arn,
		VpcConfig: &eks.ClusterVpcConfigArgs{
			//VpcId:     args.VpcId.ToStringPtrOutput(),
			SubnetIds: args.ClusterSubnetIds,
			//ClusterSecurityGroupId: clusterSecurityGroup.ID(),
		},
		EncryptionConfig: &eks.ClusterEncryptionConfigArgs{
			Resources: pulumi.StringArray{
				pulumi.String("secrets"),
			},
			Provider: &eks.ClusterEncryptionConfigProviderArgs{
				KeyArn: kmsKey.Arn,
			},
		},
		EnabledClusterLogTypes: pulumi.StringArray{
			pulumi.String("api"),
			pulumi.String("audit"),
			pulumi.String("authenticator"),
			pulumi.String("controllerManager"),
			pulumi.String("scheduler"),
		},
	}, pulumi.Parent(component))
	if err != nil {
		return nil, fmt.Errorf("error creating cluster control plane: %w", err)
	}

	oidcProvider, err := iam.NewOpenIdConnectProvider(ctx, fmt.Sprintf("%s-oidc-provider", name), &iam.OpenIdConnectProviderArgs{
		ClientIdLists: pulumi.StringArray{
			pulumi.String("sts.amazonaws.com"),
		},
		Url: controlPlane.Identities.Index(pulumi.Int(0)).Oidcs().Index(pulumi.Int(0)).Issuer().Elem(),
		ThumbprintLists: pulumi.StringArray{
			pulumi.String("990f4193972f2becf12ddeda5237f9c952f20d9e"),
		},
	}, pulumi.Parent(controlPlane))
	if err != nil {
		return nil, fmt.Errorf("error creating OIDC provider: %w", err)
	}

	systemNodePolicyJSON, err := json.Marshal(map[string]interface{}{
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
		return nil, fmt.Errorf("error marshalling system node policy: %w", err)
	}

	systemNodeRole, err := iam.NewRole(ctx, fmt.Sprintf("%s-system-node-role", name), &iam.RoleArgs{
		AssumeRolePolicy: pulumi.String(systemNodePolicyJSON),
	}, pulumi.Parent(controlPlane))
	if err != nil {
		return nil, fmt.Errorf("error creating system node role: %w", err)
	}

	_, err = iam.NewRolePolicyAttachment(ctx, fmt.Sprintf("%s-system-node-worker-policy", name), &iam.RolePolicyAttachmentArgs{
		PolicyArn: pulumi.String("arn:aws:iam::aws:policy/AmazonEKSWorkerNodePolicy"),
		Role:      systemNodeRole.Name,
	}, pulumi.Parent(systemNodeRole))
	if err != nil {
		return nil, fmt.Errorf("error attaching system node worker policy: %w", err)
	}
	_, err = iam.NewRolePolicyAttachment(ctx, fmt.Sprintf("%s-system-node-cni-policy", name), &iam.RolePolicyAttachmentArgs{
		PolicyArn: pulumi.String("arn:aws:iam::aws:policy/AmazonEKS_CNI_Policy"),
		Role:      systemNodeRole.Name,
	}, pulumi.Parent(systemNodeRole))
	if err != nil {
		return nil, fmt.Errorf("error attaching system node cni policy: %w", err)
	}
	_, err = iam.NewRolePolicyAttachment(ctx, fmt.Sprintf("%s-system-node-ecr-policy", name), &iam.RolePolicyAttachmentArgs{
		PolicyArn: pulumi.String("arn:aws:iam::aws:policy/AmazonEC2ContainerRegistryReadOnly"),
		Role:      systemNodeRole.Name,
	}, pulumi.Parent(systemNodeRole))
	if err != nil {
		return nil, fmt.Errorf("error attaching system node ecr policy: %w", err)
	}

	systemNodes, err := eks.NewNodeGroup(ctx, fmt.Sprintf("%s-system-nodes", name), &eks.NodeGroupArgs{
		ClusterName: controlPlane.Name,
		SubnetIds:   args.SystemNodeSubnetIds,
		NodeRoleArn: systemNodeRole.Arn,
		Taints: eks.NodeGroupTaintArray{
			eks.NodeGroupTaintArgs{
				Effect: pulumi.String("NO_SCHEDULE"),
				Key:    pulumi.String("node-role.kubernetes.io/system"),
				Value:  pulumi.String("true"),
			},
		},
		ScalingConfig: &eks.NodeGroupScalingConfigArgs{
			MinSize: pulumi.Int(1),
			MaxSize: pulumi.Int(10),
			DesiredSize: pulumi.Int(1),
		},
	}, pulumi.Parent(controlPlane), pulumi.IgnoreChanges([]string{"scalingConfig"}))
	if err != nil {
		return nil, fmt.Errorf("error creating system nodegroup provider: %w", err)
	}

	coreDnsConfig, err := json.Marshal(map[string]interface{}{
		"tolerations": []map[string]interface{}{
			{
				"key":      "node-role.kubernetes.io/system",
				"operator": "Equal",
				"value":    "true",
				"effect":   "NoSchedule",
			},
		},
	})
	if err != nil {
		return nil, fmt.Errorf("error marshalling coredns config: %w", err)
	}

	coreDns, err := eks.NewAddon(ctx, fmt.Sprintf("%s-coredns", name), &eks.AddonArgs{
		AddonName: pulumi.String("coredns"),
		ClusterName: controlPlane.Name,
		ResolveConflicts: pulumi.String("OVERWRITE"),
		ConfigurationValues: pulumi.String(coreDnsConfig),
	}, pulumi.Parent(controlPlane))
	if err != nil {
		return nil, fmt.Errorf("error installing coredns: %w", err)
	}

	vpcCni, err := eks.NewAddon(ctx, fmt.Sprintf("%s-vpc-cni", name), &eks.AddonArgs{
		AddonName: pulumi.String("vpc-cni"),
		ClusterName: controlPlane.Name,
		ResolveConflicts: pulumi.String("OVERWRITE"),
	}, pulumi.Parent(controlPlane))
	if err != nil {
		return nil, fmt.Errorf("error installing vpc cnu: %w", err)
	}


	_ = coreDns
	_ = vpcCni

	kc, err := kubeconfig.Generate(name, controlPlane.Endpoint, controlPlane.CertificateAuthorities.Index(pulumi.Int(0)).Data().Elem(), controlPlane.Name)
	if err != nil {
		return nil, fmt.Errorf("error generating kubeconfig: %w", err)
	}

	component.ControlPlane = controlPlane
	component.OidcProvider = oidcProvider
	component.SystemNodes = systemNodes
	component.KubeConfig = kc

	if err := ctx.RegisterResourceOutputs(component, pulumi.Map{
		"controlPlane": controlPlane,
		"oidcProvider": oidcProvider,
		"systemNodes":  systemNodes,
		"kubeconfig": kc,
	}); err != nil {
		return nil, err
	}

	return component, nil
}

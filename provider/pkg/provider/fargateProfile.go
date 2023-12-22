package provider

import (
	"encoding/json"
	"fmt"
	"github.com/pulumi/pulumi-aws/sdk/v6/go/aws/eks"
	"github.com/pulumi/pulumi-aws/sdk/v6/go/aws/iam"
	//"github.com/pulumi/pulumi-kubernetes/sdk/v4/go/kubernetes"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

type AttachedFargateProfileArgs struct {
	SubnetIds   pulumi.StringArrayInput              `pulumi:"subnetIds"`
	ClusterName pulumi.StringInput                   `pulumi:"clusterName"`
	Selectors   eks.FargateProfileSelectorArrayInput `pulumi:"selectors"`
	Tags        *pulumi.StringMapInput               `pulumi:"tags"`
}

type AttachedFargateProfile struct {
	pulumi.ResourceState

	FargateProfile *eks.FargateProfile `pulumi:"profile"`
	Role           *iam.Role           `pulumi:"role"`
}

// NewFargateProfile creates a new fargate profile component resource.
func NewFargateProfile(ctx *pulumi.Context,
	name string, args *AttachedFargateProfileArgs, opts ...pulumi.ResourceOption) (*AttachedFargateProfile, error) {
	if args == nil {
		args = &AttachedFargateProfileArgs{}
	}

	component := &AttachedFargateProfile{}
	err := ctx.RegisterComponentResource("lbrlabs-eks:index:AttachedFargateProfile", name, component, opts...)
	if err != nil {
		return nil, err
	}

	var tags pulumi.StringMapInput

	if args.Tags != nil {
		tags = *args.Tags
	} else {
		tags = pulumi.StringMap{}
	}

	fargateAssumeRolePolicyJSON, err := json.Marshal(map[string]interface{}{
		"Statement": []map[string]interface{}{
			{
				"Action": "sts:AssumeRole",
				"Effect": "Allow",
				"Principal": map[string]interface{}{
					"Service": "eks-fargate-pods.amazonaws.com",
				},
			},
		},
		"Version": "2012-10-17",
	})
	if err != nil {
		return nil, fmt.Errorf("error marshalling fargate profile policy: %w", err)
	}

	profileRole, err := iam.NewRole(ctx, fmt.Sprintf("%s-fargateprofile-role", name), &iam.RoleArgs{
		AssumeRolePolicy: pulumi.String(fargateAssumeRolePolicyJSON),
		Tags:             tags,
	}, pulumi.Parent(component))
	if err != nil {
		return nil, fmt.Errorf("error creating fargate profile role: %w", err)
	}

	_, err = iam.NewRolePolicyAttachment(ctx, fmt.Sprintf("%s-fargateprofile-execution-policy", name), &iam.RolePolicyAttachmentArgs{
		PolicyArn: pulumi.String("arn:aws:iam::aws:policy/AmazonEKSFargatePodExecutionRolePolicy"),
		Role:      profileRole.Name,
	}, pulumi.Parent(profileRole))
	if err != nil {
		return nil, fmt.Errorf("error attaching fargate profile policy: %w", err)
	}

	_, err = iam.NewRolePolicyAttachment(ctx, fmt.Sprintf("%s-fargateprofile-ecr-policy", name), &iam.RolePolicyAttachmentArgs{
		PolicyArn: pulumi.String("arn:aws:iam::aws:policy/AmazonEC2ContainerRegistryReadOnly"),
		Role:      profileRole.Name,
	}, pulumi.Parent(profileRole))
	if err != nil {
		return nil, fmt.Errorf("error attaching fargate profile ecr policy: %w", err)
	}

	_, err = NewRoleMapping(ctx, fmt.Sprintf("%s-fargateprofile-rolemapping", name), &RoleMappingArgs{
		RoleArn:  profileRole.Arn,
		Username: pulumi.String("system:node:{{SessionName}}"),
		Groups:   pulumi.StringArray{pulumi.String("system:bootstrappers"), pulumi.String("system:nodes"), pulumi.String("system:node-proxier")},
	}, pulumi.Parent(component))
	if err != nil {
		return nil, fmt.Errorf("error creating fargate profile rolemapping: %w", err)
	}

	fargateProfile, err := eks.NewFargateProfile(ctx, fmt.Sprintf("%s-fargateprofile", name), &eks.FargateProfileArgs{
		ClusterName:         args.ClusterName,
		PodExecutionRoleArn: profileRole.Arn,
		SubnetIds:           args.SubnetIds,
		Selectors:           args.Selectors,
		Tags:                tags,
	}, pulumi.Parent(component))
	if err != nil {
		return nil, fmt.Errorf("error creating fargate profile: %w", err)
	}

	component.FargateProfile = fargateProfile
	component.Role = profileRole

	if err := ctx.RegisterResourceOutputs(component, pulumi.Map{
		"fargateProfile": fargateProfile,
		"role":           profileRole,
	}); err != nil {
		return nil, err
	}

	return component, nil

}

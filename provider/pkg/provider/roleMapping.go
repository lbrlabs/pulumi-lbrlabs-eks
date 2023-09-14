package provider

import (
	"fmt"

	apiextensions "github.com/pulumi/pulumi-kubernetes/sdk/v4/go/kubernetes/apiextensions"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

type RoleMappingArgs struct {
	RoleArn  pulumi.StringInput      `pulumi:"roleArn"`
	Username pulumi.StringInput      `pulumi:"username"`
	Groups   pulumi.StringArrayInput `pulumi:"groups"`
}

type RoleMapping struct {
	pulumi.ResourceState

	RoleMapping *apiextensions.CustomResource `pulumi:"roleMapping"`
}

func NewRoleMapping(ctx *pulumi.Context, name string, args *RoleMappingArgs, opts ...pulumi.ResourceOption) (*RoleMapping, error) {

	if args == nil {
		args = &RoleMappingArgs{}
	}

	component := &RoleMapping{}
	err := ctx.RegisterComponentResource("lbrlabs-eks:index:IamRoleMapping", name, component, opts...)
	if err != nil {
		return nil, err
	}

	roleMapping, err := apiextensions.NewCustomResource(ctx, name, &apiextensions.CustomResourceArgs{
		ApiVersion: pulumi.String("iamauthenticator.k8s.aws/v1alpha1"),
		Kind:       pulumi.String("IAMIdentityMapping"),
		OtherFields: map[string]interface{}{
			"spec": map[string]interface{}{
				"arn":      args.RoleArn,
				"username": args.Username,
				"groups":   args.Groups,
			},
		},
	}, pulumi.Parent(component))
	if err != nil {
		return nil, fmt.Errorf("error creating rolemapping custom resource: %v", err)
	}

	component.RoleMapping = roleMapping

	if err := ctx.RegisterResourceOutputs(component, pulumi.Map{}); err != nil {
		return nil, err
	}

	return component, nil

}

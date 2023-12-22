package provider

import (
	"fmt"

	"github.com/pulumi/pulumi-aws/sdk/v6/go/aws/iam"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

type IamServiceAccountRoleArgs struct {
	OidcProviderArn    pulumi.StringInput     `pulumi:"oidcProviderArn"`
	OidcProviderURL    pulumi.StringInput     `pulumi:"oidcProviderUrl"`
	NamespaceName      pulumi.StringInput     `pulumi:"namespaceName"`
	ServiceAccountName pulumi.StringInput     `pulumi:"serviceAccountName"`
	Tags               *pulumi.StringMapInput `pulumi:"tags"`
}

type IamServiceAccountRole struct {
	pulumi.ResourceState

	Role *iam.Role `pulumi:"role"`
}

func NewIamServiceAccountRole(ctx *pulumi.Context, name string, args *IamServiceAccountRoleArgs, opts ...pulumi.ResourceOption) (*IamServiceAccountRole, error) {

	if args == nil {
		args = &IamServiceAccountRoleArgs{}
	}

	var tags pulumi.StringMapInput

	if args.Tags != nil {
		tags = *args.Tags
	} else {
		tags = pulumi.StringMap{}
	}

	component := &IamServiceAccountRole{}
	err := ctx.RegisterComponentResource("lbrlabs-eks:index:IamServiceAccountRole", name, component, opts...)
	if err != nil {
		return nil, err
	}

	trustDocument := iam.GetPolicyDocumentOutput(ctx, iam.GetPolicyDocumentOutputArgs{
		Statements: iam.GetPolicyDocumentStatementArray{
			iam.GetPolicyDocumentStatementArgs{
				Sid: pulumi.String("AllowAssumeRoleWithWebIdentity"),
				Actions: pulumi.StringArray{
					pulumi.String("sts:AssumeRoleWithWebIdentity"),
				},
				Effect: pulumi.String("Allow"),
				Conditions: iam.GetPolicyDocumentStatementConditionArray{
					iam.GetPolicyDocumentStatementConditionArgs{
						Test:     pulumi.String("StringEquals"),
						Variable: pulumi.Sprintf("%s:aud", args.OidcProviderURL),
						Values: pulumi.StringArray{
							pulumi.String("sts.amazonaws.com"),
						},
					},
					iam.GetPolicyDocumentStatementConditionArgs{
						Test:     pulumi.String("StringEquals"),
						Variable: pulumi.Sprintf("%s:sub", args.OidcProviderURL),
						Values: pulumi.StringArray{
							pulumi.Sprintf("system:serviceaccount:%s:%s", args.NamespaceName, args.ServiceAccountName),
						},
					},
				},
				Principals: iam.GetPolicyDocumentStatementPrincipalArray{
					iam.GetPolicyDocumentStatementPrincipalArgs{
						Type: pulumi.String("Federated"),
						Identifiers: pulumi.StringArray{
							args.OidcProviderArn,
						},
					},
				},
			},
		},
	})

	role, err := iam.NewRole(ctx, name, &iam.RoleArgs{
		AssumeRolePolicy: trustDocument.Json(),
		Tags:             tags,
	}, pulumi.Parent(component))

	if err != nil {
		return nil, fmt.Errorf("error creating trust IAM role: %w", err)
	}

	component.Role = role

	if err := ctx.RegisterResourceOutputs(component, pulumi.Map{
		"role": role,
	}); err != nil {
		return nil, err
	}

	return component, nil

}

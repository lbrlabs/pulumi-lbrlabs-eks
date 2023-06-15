package irsa

import (
	"fmt"

	"github.com/pulumi/pulumi-aws/sdk/v5/go/aws/iam"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

type IamServiceAccountRoleArgs struct {
	OidcProviderArn    pulumi.StringInput
	OidcProviderUrl    pulumi.StringInput
	Namespace          pulumi.StringInput
	ServiceAccountName pulumi.StringInput
}

type IamServiceAccountRole struct {
	pulumi.ResourceState

	Role *iam.Role
}

func NewIamServiceAccountRole(ctx *pulumi.Context, name string, args *IamServiceAccountRoleArgs, opts ...pulumi.ResourceOption) (*IamServiceAccountRole, error) {

	if args == nil {
		args = &IamServiceAccountRoleArgs{}
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
						Variable: pulumi.Sprintf("%s:aud", args.OidcProviderUrl),
						Values: pulumi.StringArray{
							pulumi.String("sts.amazonaws.com"),
						},
					},
					iam.GetPolicyDocumentStatementConditionArgs{
						Test:     pulumi.String("StringEquals"),
						Variable: pulumi.Sprintf("%s:sub", args.OidcProviderUrl),
						Values: pulumi.StringArray{
							pulumi.Sprintf("system:serviceaccount:%s:%s", args.Namespace, args.ServiceAccountName),
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
	}, pulumi.Parent(component))

	if err != nil {
		return nil, fmt.Errorf("error creating trust IAM role: %w", err)
	}

	component.Role = role

	return component, nil

}

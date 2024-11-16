// Code generated by Pulumi SDK Generator DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package eks

import (
	"context"
	"reflect"

	"errors"
	"github.com/lbrlabs/pulumi-lbrlabs-eks/sdk/go/eks/internal"
	"github.com/pulumi/pulumi-aws/sdk/v6/go/aws/iam"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

type IamServiceAccountRole struct {
	pulumi.ResourceState

	Role iam.RoleOutput `pulumi:"role"`
}

// NewIamServiceAccountRole registers a new resource with the given unique name, arguments, and options.
func NewIamServiceAccountRole(ctx *pulumi.Context,
	name string, args *IamServiceAccountRoleArgs, opts ...pulumi.ResourceOption) (*IamServiceAccountRole, error) {
	if args == nil {
		return nil, errors.New("missing one or more required arguments")
	}

	if args.NamespaceName == nil {
		return nil, errors.New("invalid value for required argument 'NamespaceName'")
	}
	if args.OidcProviderArn == nil {
		return nil, errors.New("invalid value for required argument 'OidcProviderArn'")
	}
	if args.OidcProviderUrl == nil {
		return nil, errors.New("invalid value for required argument 'OidcProviderUrl'")
	}
	if args.ServiceAccountName == nil {
		return nil, errors.New("invalid value for required argument 'ServiceAccountName'")
	}
	opts = internal.PkgResourceDefaultOpts(opts)
	var resource IamServiceAccountRole
	err := ctx.RegisterRemoteComponentResource("lbrlabs-eks:index:IamServiceAccountRole", name, args, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

type iamServiceAccountRoleArgs struct {
	// The namespace to create the service account in.
	NamespaceName string `pulumi:"namespaceName"`
	// The arn of the OIDC provider attached to your EKS cluster.
	OidcProviderArn string `pulumi:"oidcProviderArn"`
	// The URL of the OIDC provider attached to your EKS cluster.
	OidcProviderUrl string `pulumi:"oidcProviderUrl"`
	// The name of the service account to bind to the role
	ServiceAccountName string `pulumi:"serviceAccountName"`
	// Key-value map of tags to apply to the service account.
	Tags map[string]string `pulumi:"tags"`
}

// The set of arguments for constructing a IamServiceAccountRole resource.
type IamServiceAccountRoleArgs struct {
	// The namespace to create the service account in.
	NamespaceName pulumi.StringInput
	// The arn of the OIDC provider attached to your EKS cluster.
	OidcProviderArn pulumi.StringInput
	// The URL of the OIDC provider attached to your EKS cluster.
	OidcProviderUrl pulumi.StringInput
	// The name of the service account to bind to the role
	ServiceAccountName pulumi.StringInput
	// Key-value map of tags to apply to the service account.
	Tags pulumi.StringMapInput
}

func (IamServiceAccountRoleArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*iamServiceAccountRoleArgs)(nil)).Elem()
}

type IamServiceAccountRoleInput interface {
	pulumi.Input

	ToIamServiceAccountRoleOutput() IamServiceAccountRoleOutput
	ToIamServiceAccountRoleOutputWithContext(ctx context.Context) IamServiceAccountRoleOutput
}

func (*IamServiceAccountRole) ElementType() reflect.Type {
	return reflect.TypeOf((**IamServiceAccountRole)(nil)).Elem()
}

func (i *IamServiceAccountRole) ToIamServiceAccountRoleOutput() IamServiceAccountRoleOutput {
	return i.ToIamServiceAccountRoleOutputWithContext(context.Background())
}

func (i *IamServiceAccountRole) ToIamServiceAccountRoleOutputWithContext(ctx context.Context) IamServiceAccountRoleOutput {
	return pulumi.ToOutputWithContext(ctx, i).(IamServiceAccountRoleOutput)
}

// IamServiceAccountRoleArrayInput is an input type that accepts IamServiceAccountRoleArray and IamServiceAccountRoleArrayOutput values.
// You can construct a concrete instance of `IamServiceAccountRoleArrayInput` via:
//
//	IamServiceAccountRoleArray{ IamServiceAccountRoleArgs{...} }
type IamServiceAccountRoleArrayInput interface {
	pulumi.Input

	ToIamServiceAccountRoleArrayOutput() IamServiceAccountRoleArrayOutput
	ToIamServiceAccountRoleArrayOutputWithContext(context.Context) IamServiceAccountRoleArrayOutput
}

type IamServiceAccountRoleArray []IamServiceAccountRoleInput

func (IamServiceAccountRoleArray) ElementType() reflect.Type {
	return reflect.TypeOf((*[]*IamServiceAccountRole)(nil)).Elem()
}

func (i IamServiceAccountRoleArray) ToIamServiceAccountRoleArrayOutput() IamServiceAccountRoleArrayOutput {
	return i.ToIamServiceAccountRoleArrayOutputWithContext(context.Background())
}

func (i IamServiceAccountRoleArray) ToIamServiceAccountRoleArrayOutputWithContext(ctx context.Context) IamServiceAccountRoleArrayOutput {
	return pulumi.ToOutputWithContext(ctx, i).(IamServiceAccountRoleArrayOutput)
}

// IamServiceAccountRoleMapInput is an input type that accepts IamServiceAccountRoleMap and IamServiceAccountRoleMapOutput values.
// You can construct a concrete instance of `IamServiceAccountRoleMapInput` via:
//
//	IamServiceAccountRoleMap{ "key": IamServiceAccountRoleArgs{...} }
type IamServiceAccountRoleMapInput interface {
	pulumi.Input

	ToIamServiceAccountRoleMapOutput() IamServiceAccountRoleMapOutput
	ToIamServiceAccountRoleMapOutputWithContext(context.Context) IamServiceAccountRoleMapOutput
}

type IamServiceAccountRoleMap map[string]IamServiceAccountRoleInput

func (IamServiceAccountRoleMap) ElementType() reflect.Type {
	return reflect.TypeOf((*map[string]*IamServiceAccountRole)(nil)).Elem()
}

func (i IamServiceAccountRoleMap) ToIamServiceAccountRoleMapOutput() IamServiceAccountRoleMapOutput {
	return i.ToIamServiceAccountRoleMapOutputWithContext(context.Background())
}

func (i IamServiceAccountRoleMap) ToIamServiceAccountRoleMapOutputWithContext(ctx context.Context) IamServiceAccountRoleMapOutput {
	return pulumi.ToOutputWithContext(ctx, i).(IamServiceAccountRoleMapOutput)
}

type IamServiceAccountRoleOutput struct{ *pulumi.OutputState }

func (IamServiceAccountRoleOutput) ElementType() reflect.Type {
	return reflect.TypeOf((**IamServiceAccountRole)(nil)).Elem()
}

func (o IamServiceAccountRoleOutput) ToIamServiceAccountRoleOutput() IamServiceAccountRoleOutput {
	return o
}

func (o IamServiceAccountRoleOutput) ToIamServiceAccountRoleOutputWithContext(ctx context.Context) IamServiceAccountRoleOutput {
	return o
}

func (o IamServiceAccountRoleOutput) Role() iam.RoleOutput {
	return o.ApplyT(func(v *IamServiceAccountRole) iam.RoleOutput { return v.Role }).(iam.RoleOutput)
}

type IamServiceAccountRoleArrayOutput struct{ *pulumi.OutputState }

func (IamServiceAccountRoleArrayOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*[]*IamServiceAccountRole)(nil)).Elem()
}

func (o IamServiceAccountRoleArrayOutput) ToIamServiceAccountRoleArrayOutput() IamServiceAccountRoleArrayOutput {
	return o
}

func (o IamServiceAccountRoleArrayOutput) ToIamServiceAccountRoleArrayOutputWithContext(ctx context.Context) IamServiceAccountRoleArrayOutput {
	return o
}

func (o IamServiceAccountRoleArrayOutput) Index(i pulumi.IntInput) IamServiceAccountRoleOutput {
	return pulumi.All(o, i).ApplyT(func(vs []interface{}) *IamServiceAccountRole {
		return vs[0].([]*IamServiceAccountRole)[vs[1].(int)]
	}).(IamServiceAccountRoleOutput)
}

type IamServiceAccountRoleMapOutput struct{ *pulumi.OutputState }

func (IamServiceAccountRoleMapOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*map[string]*IamServiceAccountRole)(nil)).Elem()
}

func (o IamServiceAccountRoleMapOutput) ToIamServiceAccountRoleMapOutput() IamServiceAccountRoleMapOutput {
	return o
}

func (o IamServiceAccountRoleMapOutput) ToIamServiceAccountRoleMapOutputWithContext(ctx context.Context) IamServiceAccountRoleMapOutput {
	return o
}

func (o IamServiceAccountRoleMapOutput) MapIndex(k pulumi.StringInput) IamServiceAccountRoleOutput {
	return pulumi.All(o, k).ApplyT(func(vs []interface{}) *IamServiceAccountRole {
		return vs[0].(map[string]*IamServiceAccountRole)[vs[1].(string)]
	}).(IamServiceAccountRoleOutput)
}

func init() {
	pulumi.RegisterInputType(reflect.TypeOf((*IamServiceAccountRoleInput)(nil)).Elem(), &IamServiceAccountRole{})
	pulumi.RegisterInputType(reflect.TypeOf((*IamServiceAccountRoleArrayInput)(nil)).Elem(), IamServiceAccountRoleArray{})
	pulumi.RegisterInputType(reflect.TypeOf((*IamServiceAccountRoleMapInput)(nil)).Elem(), IamServiceAccountRoleMap{})
	pulumi.RegisterOutputType(IamServiceAccountRoleOutput{})
	pulumi.RegisterOutputType(IamServiceAccountRoleArrayOutput{})
	pulumi.RegisterOutputType(IamServiceAccountRoleMapOutput{})
}

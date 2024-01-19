// Code generated by Pulumi SDK Generator DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package eks

import (
	"context"
	"reflect"

	"errors"
	"github.com/lbrlabs/pulumi-lbrlabs-eks/sdk/go/eks/internal"
	"github.com/pulumi/pulumi-aws/sdk/v6/go/aws/eks"
	"github.com/pulumi/pulumi-aws/sdk/v6/go/aws/iam"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumix"
)

type Cluster struct {
	pulumi.ResourceState

	// The cluster name
	ClusterName pulumix.Output[string] `pulumi:"clusterName"`
	// The Cluster control plane
	ControlPlane pulumix.GPtrOutput[eks.Cluster, eks.ClusterOutput] `pulumi:"controlPlane"`
	// The role created for karpenter nodes.
	KarpenterNodeRole pulumix.GPtrOutput[iam.Role, iam.RoleOutput] `pulumi:"karpenterNodeRole"`
	// The kubeconfig for this cluster.
	Kubeconfig pulumix.Output[string] `pulumi:"kubeconfig"`
	// The OIDC provider for this cluster.
	OidcProvider pulumix.GPtrOutput[iam.OpenIdConnectProvider, iam.OpenIdConnectProviderOutput] `pulumi:"oidcProvider"`
	// The system node group.
	SystemNodes pulumix.GPtrOutput[eks.NodeGroup, eks.NodeGroupOutput] `pulumi:"systemNodes"`
}

// NewCluster registers a new resource with the given unique name, arguments, and options.
func NewCluster(ctx *pulumi.Context,
	name string, args *ClusterArgs, opts ...pulumi.ResourceOption) (*Cluster, error) {
	if args == nil {
		return nil, errors.New("missing one or more required arguments")
	}

	if args.ClusterSubnetIds == nil {
		return nil, errors.New("invalid value for required argument 'ClusterSubnetIds'")
	}
	if args.SystemNodeSubnetIds == nil {
		return nil, errors.New("invalid value for required argument 'SystemNodeSubnetIds'")
	}
	if args.EnableCertManager == nil {
		enableCertManager_ := true
		args.EnableCertManager = &enableCertManager_
	}
	if args.EnableCloudWatchAgent == nil {
		enableCloudWatchAgent_ := false
		args.EnableCloudWatchAgent = &enableCloudWatchAgent_
	}
	if args.EnableExternalDns == nil {
		enableExternalDns_ := true
		args.EnableExternalDns = &enableExternalDns_
	}
	if args.EnableKarpenter == nil {
		enableKarpenter_ := true
		args.EnableKarpenter = &enableKarpenter_
	}
	if args.EnableOtel == nil {
		enableOtel_ := false
		args.EnableOtel = &enableOtel_
	}
	if args.LbType == nil {
		args.LbType = pulumix.Ptr("nlb")
	}
	opts = internal.PkgResourceDefaultOpts(opts)
	var resource Cluster
	err := ctx.RegisterRemoteComponentResource("lbrlabs-eks:index:Cluster", name, args, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

type clusterArgs struct {
	// The ARN of the certificate to use for the ingress controller.
	CertificateArn   *string  `pulumi:"certificateArn"`
	ClusterSubnetIds []string `pulumi:"clusterSubnetIds"`
	// Whether to enable cert-manager with route 53 integration.
	EnableCertManager *bool `pulumi:"enableCertManager"`
	// Whether to enable cloudwatch container insights for EKS.
	EnableCloudWatchAgent *bool `pulumi:"enableCloudWatchAgent"`
	// Whether to enable external dns with route 53 integration.
	EnableExternalDns *bool `pulumi:"enableExternalDns"`
	// Whether to enable karpenter.
	EnableKarpenter *bool `pulumi:"enableKarpenter"`
	// Whether to enable the OTEL Distro for EKS.
	EnableOtel *bool `pulumi:"enableOtel"`
	// The type of loadbalancer to provision.
	LbType *string `pulumi:"lbType"`
	// The email address to use to issue certificates from Lets Encrypt.
	LetsEncryptEmail *string `pulumi:"letsEncryptEmail"`
	// The initial number of nodes in the system autoscaling group.
	SystemNodeDesiredCount  *float64 `pulumi:"systemNodeDesiredCount"`
	SystemNodeInstanceTypes []string `pulumi:"systemNodeInstanceTypes"`
	// The maximum number of nodes in the system autoscaling group.
	SystemNodeMaxCount *float64 `pulumi:"systemNodeMaxCount"`
	// The minimum number of nodes in the system autoscaling group.
	SystemNodeMinCount  *float64 `pulumi:"systemNodeMinCount"`
	SystemNodeSubnetIds []string `pulumi:"systemNodeSubnetIds"`
	// Key-value map of tags to apply to the cluster.
	Tags map[string]string `pulumi:"tags"`
}

// The set of arguments for constructing a Cluster resource.
type ClusterArgs struct {
	// The ARN of the certificate to use for the ingress controller.
	CertificateArn   pulumix.Input[*string]
	ClusterSubnetIds pulumix.Input[[]string]
	// Whether to enable cert-manager with route 53 integration.
	EnableCertManager *bool
	// Whether to enable cloudwatch container insights for EKS.
	EnableCloudWatchAgent *bool
	// Whether to enable external dns with route 53 integration.
	EnableExternalDns *bool
	// Whether to enable karpenter.
	EnableKarpenter *bool
	// Whether to enable the OTEL Distro for EKS.
	EnableOtel *bool
	// The type of loadbalancer to provision.
	LbType pulumix.Input[*string]
	// The email address to use to issue certificates from Lets Encrypt.
	LetsEncryptEmail *string
	// The initial number of nodes in the system autoscaling group.
	SystemNodeDesiredCount  pulumix.Input[*float64]
	SystemNodeInstanceTypes pulumix.Input[[]string]
	// The maximum number of nodes in the system autoscaling group.
	SystemNodeMaxCount pulumix.Input[*float64]
	// The minimum number of nodes in the system autoscaling group.
	SystemNodeMinCount  pulumix.Input[*float64]
	SystemNodeSubnetIds pulumix.Input[[]string]
	// Key-value map of tags to apply to the cluster.
	Tags pulumix.Input[map[string]string]
}

func (ClusterArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*clusterArgs)(nil)).Elem()
}

type ClusterOutput struct{ *pulumi.OutputState }

func (ClusterOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*Cluster)(nil)).Elem()
}

func (o ClusterOutput) ToClusterOutput() ClusterOutput {
	return o
}

func (o ClusterOutput) ToClusterOutputWithContext(ctx context.Context) ClusterOutput {
	return o
}

func (o ClusterOutput) ToOutput(ctx context.Context) pulumix.Output[Cluster] {
	return pulumix.Output[Cluster]{
		OutputState: o.OutputState,
	}
}

// The cluster name
func (o ClusterOutput) ClusterName() pulumix.Output[string] {
	value := pulumix.Apply[Cluster](o, func(v Cluster) pulumix.Output[string] { return v.ClusterName })
	return pulumix.Flatten[string, pulumix.Output[string]](value)
}

// The Cluster control plane
func (o ClusterOutput) ControlPlane() pulumix.GPtrOutput[eks.Cluster, eks.ClusterOutput] {
	value := pulumix.Apply[Cluster](o, func(v Cluster) pulumix.GPtrOutput[eks.Cluster, eks.ClusterOutput] { return v.ControlPlane })
	unwrapped := pulumix.Flatten[*eks.Cluster, pulumix.GPtrOutput[eks.Cluster, eks.ClusterOutput]](value)
	return pulumix.GPtrOutput[eks.Cluster, eks.ClusterOutput]{OutputState: unwrapped.OutputState}
}

// The role created for karpenter nodes.
func (o ClusterOutput) KarpenterNodeRole() pulumix.GPtrOutput[iam.Role, iam.RoleOutput] {
	value := pulumix.Apply[Cluster](o, func(v Cluster) pulumix.GPtrOutput[iam.Role, iam.RoleOutput] { return v.KarpenterNodeRole })
	unwrapped := pulumix.Flatten[*iam.Role, pulumix.GPtrOutput[iam.Role, iam.RoleOutput]](value)
	return pulumix.GPtrOutput[iam.Role, iam.RoleOutput]{OutputState: unwrapped.OutputState}
}

// The kubeconfig for this cluster.
func (o ClusterOutput) Kubeconfig() pulumix.Output[string] {
	value := pulumix.Apply[Cluster](o, func(v Cluster) pulumix.Output[string] { return v.Kubeconfig })
	return pulumix.Flatten[string, pulumix.Output[string]](value)
}

// The OIDC provider for this cluster.
func (o ClusterOutput) OidcProvider() pulumix.GPtrOutput[iam.OpenIdConnectProvider, iam.OpenIdConnectProviderOutput] {
	value := pulumix.Apply[Cluster](o, func(v Cluster) pulumix.GPtrOutput[iam.OpenIdConnectProvider, iam.OpenIdConnectProviderOutput] {
		return v.OidcProvider
	})
	unwrapped := pulumix.Flatten[*iam.OpenIdConnectProvider, pulumix.GPtrOutput[iam.OpenIdConnectProvider, iam.OpenIdConnectProviderOutput]](value)
	return pulumix.GPtrOutput[iam.OpenIdConnectProvider, iam.OpenIdConnectProviderOutput]{OutputState: unwrapped.OutputState}
}

// The system node group.
func (o ClusterOutput) SystemNodes() pulumix.GPtrOutput[eks.NodeGroup, eks.NodeGroupOutput] {
	value := pulumix.Apply[Cluster](o, func(v Cluster) pulumix.GPtrOutput[eks.NodeGroup, eks.NodeGroupOutput] { return v.SystemNodes })
	unwrapped := pulumix.Flatten[*eks.NodeGroup, pulumix.GPtrOutput[eks.NodeGroup, eks.NodeGroupOutput]](value)
	return pulumix.GPtrOutput[eks.NodeGroup, eks.NodeGroupOutput]{OutputState: unwrapped.OutputState}
}

func init() {
	pulumi.RegisterOutputType(ClusterOutput{})
}

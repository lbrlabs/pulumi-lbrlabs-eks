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
)

type Cluster struct {
	pulumi.ResourceState

	// The cluster name
	ClusterName pulumi.StringOutput `pulumi:"clusterName"`
	// The Cluster control plane
	ControlPlane eks.ClusterOutput `pulumi:"controlPlane"`
	// The role created for karpenter nodes.
	KarpenterNodeRole iam.RoleOutput `pulumi:"karpenterNodeRole"`
	// The kubeconfig for this cluster.
	Kubeconfig pulumi.StringOutput `pulumi:"kubeconfig"`
	// The OIDC provider for this cluster.
	OidcProvider iam.OpenIdConnectProviderOutput `pulumi:"oidcProvider"`
	// The system node group.
	SystemNodes eks.NodeGroupOutput `pulumi:"systemNodes"`
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
	if args.ClusterEndpointPrivateAccess == nil {
		args.ClusterEndpointPrivateAccess = pulumi.BoolPtr(false)
	}
	if args.ClusterEndpointPublicAccess == nil {
		args.ClusterEndpointPublicAccess = pulumi.BoolPtr(true)
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
	if args.EnableExternalIngress == nil {
		enableExternalIngress_ := true
		args.EnableExternalIngress = &enableExternalIngress_
	}
	if args.EnableInternalIngress == nil {
		enableInternalIngress_ := true
		args.EnableInternalIngress = &enableInternalIngress_
	}
	if args.EnableKarpenter == nil {
		enableKarpenter_ := true
		args.EnableKarpenter = &enableKarpenter_
	}
	if args.EnableOtel == nil {
		enableOtel_ := false
		args.EnableOtel = &enableOtel_
	}
	if args.IngressConfig != nil {
		args.IngressConfig = args.IngressConfig.ToIngressConfigPtrOutput().ApplyT(func(v *IngressConfig) *IngressConfig { return v.Defaults() }).(IngressConfigPtrOutput)
	}
	if args.LbType == nil {
		args.LbType = pulumi.StringPtr("nlb")
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
	// The version of the cert-manager helm chart to deploy.
	CertManagerVersion *string `pulumi:"certManagerVersion"`
	// The ARN of the certificate to use for the ingress controller.
	CertificateArn *string `pulumi:"certificateArn"`
	// Indicates whether or not the Amazon EKS private API server endpoint is enabled.
	ClusterEndpointPrivateAccess *bool `pulumi:"clusterEndpointPrivateAccess"`
	// Indicates whether or not the Amazon EKS public API server endpoint is enabled.
	ClusterEndpointPublicAccess *bool    `pulumi:"clusterEndpointPublicAccess"`
	ClusterSubnetIds            []string `pulumi:"clusterSubnetIds"`
	// The version of the EKS cluster to create.
	ClusterVersion *string `pulumi:"clusterVersion"`
	// The version of the eks-iam-auth-controller helm chart to deploy.
	EksIamAuthControllerVersion *string `pulumi:"eksIamAuthControllerVersion"`
	// Whether to enable cert-manager with route 53 integration.
	EnableCertManager *bool `pulumi:"enableCertManager"`
	// Whether to enable cloudwatch container insights for EKS.
	EnableCloudWatchAgent *bool `pulumi:"enableCloudWatchAgent"`
	// Whether to enable external dns with route 53 integration.
	EnableExternalDns *bool `pulumi:"enableExternalDns"`
	// Whether to create an ingress controller for external traffic.
	EnableExternalIngress *bool `pulumi:"enableExternalIngress"`
	// Whether to create an ingress controller for internal traffic.
	EnableInternalIngress *bool `pulumi:"enableInternalIngress"`
	// Whether to enable karpenter.
	EnableKarpenter *bool `pulumi:"enableKarpenter"`
	// Whether to enable the OTEL Distro for EKS.
	EnableOtel             *bool    `pulumi:"enableOtel"`
	EnabledClusterLogTypes []string `pulumi:"enabledClusterLogTypes"`
	// The version of the external-dns helm chart to deploy.
	ExternalDNSVersion *string `pulumi:"externalDNSVersion"`
	// Configuration for the ingress controller.
	IngressConfig *IngressConfig `pulumi:"ingressConfig"`
	// The type of loadbalancer to provision.
	LbType *string `pulumi:"lbType"`
	// The email address to use to issue certificates from Lets Encrypt.
	LetsEncryptEmail *string `pulumi:"letsEncryptEmail"`
	// The version of the nginx ingress controller helm chart to deploy.
	NginxIngressVersion *string `pulumi:"nginxIngressVersion"`
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
	// The version of the cert-manager helm chart to deploy.
	CertManagerVersion pulumi.StringPtrInput
	// The ARN of the certificate to use for the ingress controller.
	CertificateArn pulumi.StringPtrInput
	// Indicates whether or not the Amazon EKS private API server endpoint is enabled.
	ClusterEndpointPrivateAccess pulumi.BoolPtrInput
	// Indicates whether or not the Amazon EKS public API server endpoint is enabled.
	ClusterEndpointPublicAccess pulumi.BoolPtrInput
	ClusterSubnetIds            pulumi.StringArrayInput
	// The version of the EKS cluster to create.
	ClusterVersion pulumi.StringPtrInput
	// The version of the eks-iam-auth-controller helm chart to deploy.
	EksIamAuthControllerVersion pulumi.StringPtrInput
	// Whether to enable cert-manager with route 53 integration.
	EnableCertManager *bool
	// Whether to enable cloudwatch container insights for EKS.
	EnableCloudWatchAgent *bool
	// Whether to enable external dns with route 53 integration.
	EnableExternalDns *bool
	// Whether to create an ingress controller for external traffic.
	EnableExternalIngress *bool
	// Whether to create an ingress controller for internal traffic.
	EnableInternalIngress *bool
	// Whether to enable karpenter.
	EnableKarpenter *bool
	// Whether to enable the OTEL Distro for EKS.
	EnableOtel             *bool
	EnabledClusterLogTypes pulumi.StringArrayInput
	// The version of the external-dns helm chart to deploy.
	ExternalDNSVersion pulumi.StringPtrInput
	// Configuration for the ingress controller.
	IngressConfig IngressConfigPtrInput
	// The type of loadbalancer to provision.
	LbType pulumi.StringPtrInput
	// The email address to use to issue certificates from Lets Encrypt.
	LetsEncryptEmail *string
	// The version of the nginx ingress controller helm chart to deploy.
	NginxIngressVersion pulumi.StringPtrInput
	// The initial number of nodes in the system autoscaling group.
	SystemNodeDesiredCount  pulumi.Float64PtrInput
	SystemNodeInstanceTypes pulumi.StringArrayInput
	// The maximum number of nodes in the system autoscaling group.
	SystemNodeMaxCount pulumi.Float64PtrInput
	// The minimum number of nodes in the system autoscaling group.
	SystemNodeMinCount  pulumi.Float64PtrInput
	SystemNodeSubnetIds pulumi.StringArrayInput
	// Key-value map of tags to apply to the cluster.
	Tags pulumi.StringMapInput
}

func (ClusterArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*clusterArgs)(nil)).Elem()
}

type ClusterInput interface {
	pulumi.Input

	ToClusterOutput() ClusterOutput
	ToClusterOutputWithContext(ctx context.Context) ClusterOutput
}

func (*Cluster) ElementType() reflect.Type {
	return reflect.TypeOf((**Cluster)(nil)).Elem()
}

func (i *Cluster) ToClusterOutput() ClusterOutput {
	return i.ToClusterOutputWithContext(context.Background())
}

func (i *Cluster) ToClusterOutputWithContext(ctx context.Context) ClusterOutput {
	return pulumi.ToOutputWithContext(ctx, i).(ClusterOutput)
}

type ClusterOutput struct{ *pulumi.OutputState }

func (ClusterOutput) ElementType() reflect.Type {
	return reflect.TypeOf((**Cluster)(nil)).Elem()
}

func (o ClusterOutput) ToClusterOutput() ClusterOutput {
	return o
}

func (o ClusterOutput) ToClusterOutputWithContext(ctx context.Context) ClusterOutput {
	return o
}

// The cluster name
func (o ClusterOutput) ClusterName() pulumi.StringOutput {
	return o.ApplyT(func(v *Cluster) pulumi.StringOutput { return v.ClusterName }).(pulumi.StringOutput)
}

// The Cluster control plane
func (o ClusterOutput) ControlPlane() eks.ClusterOutput {
	return o.ApplyT(func(v *Cluster) eks.ClusterOutput { return v.ControlPlane }).(eks.ClusterOutput)
}

// The role created for karpenter nodes.
func (o ClusterOutput) KarpenterNodeRole() iam.RoleOutput {
	return o.ApplyT(func(v *Cluster) iam.RoleOutput { return v.KarpenterNodeRole }).(iam.RoleOutput)
}

// The kubeconfig for this cluster.
func (o ClusterOutput) Kubeconfig() pulumi.StringOutput {
	return o.ApplyT(func(v *Cluster) pulumi.StringOutput { return v.Kubeconfig }).(pulumi.StringOutput)
}

// The OIDC provider for this cluster.
func (o ClusterOutput) OidcProvider() iam.OpenIdConnectProviderOutput {
	return o.ApplyT(func(v *Cluster) iam.OpenIdConnectProviderOutput { return v.OidcProvider }).(iam.OpenIdConnectProviderOutput)
}

// The system node group.
func (o ClusterOutput) SystemNodes() eks.NodeGroupOutput {
	return o.ApplyT(func(v *Cluster) eks.NodeGroupOutput { return v.SystemNodes }).(eks.NodeGroupOutput)
}

func init() {
	pulumi.RegisterInputType(reflect.TypeOf((*ClusterInput)(nil)).Elem(), &Cluster{})
	pulumi.RegisterOutputType(ClusterOutput{})
}

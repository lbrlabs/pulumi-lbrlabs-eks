// *** WARNING: this file was generated by Pulumi SDK Generator. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;
using Pulumi;

namespace Lbrlabs.PulumiPackage.Eks
{
    [EksResourceType("lbrlabs-eks:index:Cluster")]
    public partial class Cluster : global::Pulumi.ComponentResource
    {
        /// <summary>
        /// The cluster name
        /// </summary>
        [Output("clusterName")]
        public Output<string> ClusterName { get; private set; } = null!;

        /// <summary>
        /// The Cluster control plane
        /// </summary>
        [Output("controlPlane")]
        public Output<Pulumi.Aws.Eks.Cluster> ControlPlane { get; private set; } = null!;

        /// <summary>
        /// The role created for karpenter nodes.
        /// </summary>
        [Output("karpenterNodeRole")]
        public Output<Pulumi.Aws.Iam.Role?> KarpenterNodeRole { get; private set; } = null!;

        /// <summary>
        /// Name of the SQS queue that Karpenter uses for interruption events.
        /// </summary>
        [Output("karpenterQueueName")]
        public Output<string?> KarpenterQueueName { get; private set; } = null!;

        /// <summary>
        /// The kubeconfig for this cluster.
        /// </summary>
        [Output("kubeconfig")]
        public Output<string> Kubeconfig { get; private set; } = null!;

        /// <summary>
        /// The OIDC provider for this cluster.
        /// </summary>
        [Output("oidcProvider")]
        public Output<Pulumi.Aws.Iam.OpenIdConnectProvider> OidcProvider { get; private set; } = null!;

        /// <summary>
        /// The system node group.
        /// </summary>
        [Output("systemNodes")]
        public Output<Pulumi.Aws.Eks.NodeGroup> SystemNodes { get; private set; } = null!;


        /// <summary>
        /// Create a Cluster resource with the given unique name, arguments, and options.
        /// </summary>
        ///
        /// <param name="name">The unique name of the resource</param>
        /// <param name="args">The arguments used to populate this resource's properties</param>
        /// <param name="options">A bag of options that control this resource's behavior</param>
        public Cluster(string name, ClusterArgs args, ComponentResourceOptions? options = null)
            : base("lbrlabs-eks:index:Cluster", name, args ?? new ClusterArgs(), MakeResourceOptions(options, ""), remote: true)
        {
        }

        private static ComponentResourceOptions MakeResourceOptions(ComponentResourceOptions? options, Input<string>? id)
        {
            var defaultOptions = new ComponentResourceOptions
            {
                Version = Utilities.Version,
                PluginDownloadURL = "github://api.github.com/lbrlabs",
            };
            var merged = ComponentResourceOptions.Merge(defaultOptions, options);
            // Override the ID if one was specified for consistency with other language SDKs.
            merged.Id = id ?? merged.Id;
            return merged;
        }
    }

    public sealed class ClusterArgs : global::Pulumi.ResourceArgs
    {
        /// <summary>
        /// The ARN of the AWS principal that should get admin access.
        /// </summary>
        [Input("adminAccessPrincipal")]
        public Input<string>? AdminAccessPrincipal { get; set; }

        /// <summary>
        /// The version of the cert-manager helm chart to deploy.
        /// </summary>
        [Input("certManagerVersion")]
        public Input<string>? CertManagerVersion { get; set; }

        /// <summary>
        /// The ARN of the certificate to use for the ingress controller.
        /// </summary>
        [Input("certificateArn")]
        public Input<string>? CertificateArn { get; set; }

        /// <summary>
        /// Indicates whether or not the Amazon EKS private API server endpoint is enabled.
        /// </summary>
        [Input("clusterEndpointPrivateAccess")]
        public Input<bool>? ClusterEndpointPrivateAccess { get; set; }

        /// <summary>
        /// Indicates whether or not the Amazon EKS public API server endpoint is enabled.
        /// </summary>
        [Input("clusterEndpointPublicAccess")]
        public Input<bool>? ClusterEndpointPublicAccess { get; set; }

        [Input("clusterSubnetIds", required: true)]
        private InputList<string>? _clusterSubnetIds;
        public InputList<string> ClusterSubnetIds
        {
            get => _clusterSubnetIds ?? (_clusterSubnetIds = new InputList<string>());
            set => _clusterSubnetIds = value;
        }

        /// <summary>
        /// The version of the EKS cluster to create.
        /// </summary>
        [Input("clusterVersion")]
        public Input<string>? ClusterVersion { get; set; }

        /// <summary>
        /// The version of the eks-iam-auth-controller helm chart to deploy.
        /// </summary>
        [Input("eksIamAuthControllerVersion")]
        public Input<string>? EksIamAuthControllerVersion { get; set; }

        /// <summary>
        /// Whether to enable cert-manager with route 53 integration.
        /// </summary>
        [Input("enableCertManager")]
        public bool? EnableCertManager { get; set; }

        /// <summary>
        /// Whether to enable cloudwatch container insights for EKS.
        /// </summary>
        [Input("enableCloudWatchAgent")]
        public bool? EnableCloudWatchAgent { get; set; }

        /// <summary>
        /// Whether to enable external dns with route 53 integration.
        /// </summary>
        [Input("enableExternalDns")]
        public bool? EnableExternalDns { get; set; }

        /// <summary>
        /// Whether to create an ingress controller for external traffic.
        /// </summary>
        [Input("enableExternalIngress")]
        public bool? EnableExternalIngress { get; set; }

        /// <summary>
        /// Whether to create an ingress controller for internal traffic.
        /// </summary>
        [Input("enableInternalIngress")]
        public bool? EnableInternalIngress { get; set; }

        /// <summary>
        /// Whether to enable karpenter.
        /// </summary>
        [Input("enableKarpenter")]
        public bool? EnableKarpenter { get; set; }

        /// <summary>
        /// Whether to enable the OTEL Distro for EKS.
        /// </summary>
        [Input("enableOtel")]
        public bool? EnableOtel { get; set; }

        [Input("enabledClusterLogTypes")]
        private InputList<string>? _enabledClusterLogTypes;
        public InputList<string> EnabledClusterLogTypes
        {
            get => _enabledClusterLogTypes ?? (_enabledClusterLogTypes = new InputList<string>());
            set => _enabledClusterLogTypes = value;
        }

        /// <summary>
        /// The version of the external-dns helm chart to deploy.
        /// </summary>
        [Input("externalDNSVersion")]
        public Input<string>? ExternalDNSVersion { get; set; }

        /// <summary>
        /// Configuration for the ingress controller.
        /// </summary>
        [Input("ingressConfig")]
        public Input<Inputs.IngressConfigArgs>? IngressConfig { get; set; }

        /// <summary>
        /// The version of karpenter to deploy.
        /// </summary>
        [Input("karpenterVersion")]
        public Input<string>? KarpenterVersion { get; set; }

        /// <summary>
        /// The type of loadbalancer to provision.
        /// </summary>
        [Input("lbType")]
        public Input<string>? LbType { get; set; }

        /// <summary>
        /// The email address to use to issue certificates from Lets Encrypt.
        /// </summary>
        [Input("letsEncryptEmail")]
        public string? LetsEncryptEmail { get; set; }

        /// <summary>
        /// The container registry to pull images from.
        /// </summary>
        [Input("nginxIngressRegistry")]
        public Input<string>? NginxIngressRegistry { get; set; }

        /// <summary>
        /// The tag to use for the nginx ingress controller images.
        /// </summary>
        [Input("nginxIngressTag")]
        public Input<string>? NginxIngressTag { get; set; }

        /// <summary>
        /// The version of the nginx ingress controller helm chart to deploy.
        /// </summary>
        [Input("nginxIngressVersion")]
        public Input<string>? NginxIngressVersion { get; set; }

        /// <summary>
        /// The initial number of nodes in the system autoscaling group.
        /// </summary>
        [Input("systemNodeDesiredCount")]
        public Input<double>? SystemNodeDesiredCount { get; set; }

        [Input("systemNodeInstanceTypes")]
        private InputList<string>? _systemNodeInstanceTypes;
        public InputList<string> SystemNodeInstanceTypes
        {
            get => _systemNodeInstanceTypes ?? (_systemNodeInstanceTypes = new InputList<string>());
            set => _systemNodeInstanceTypes = value;
        }

        /// <summary>
        /// The maximum number of nodes in the system autoscaling group.
        /// </summary>
        [Input("systemNodeMaxCount")]
        public Input<double>? SystemNodeMaxCount { get; set; }

        /// <summary>
        /// The minimum number of nodes in the system autoscaling group.
        /// </summary>
        [Input("systemNodeMinCount")]
        public Input<double>? SystemNodeMinCount { get; set; }

        [Input("systemNodeSubnetIds", required: true)]
        private InputList<string>? _systemNodeSubnetIds;
        public InputList<string> SystemNodeSubnetIds
        {
            get => _systemNodeSubnetIds ?? (_systemNodeSubnetIds = new InputList<string>());
            set => _systemNodeSubnetIds = value;
        }

        [Input("tags")]
        private InputMap<string>? _tags;

        /// <summary>
        /// Key-value map of tags to apply to the cluster.
        /// </summary>
        public InputMap<string> Tags
        {
            get => _tags ?? (_tags = new InputMap<string>());
            set => _tags = value;
        }

        public ClusterArgs()
        {
            ClusterEndpointPrivateAccess = false;
            ClusterEndpointPublicAccess = true;
            EnableCertManager = true;
            EnableCloudWatchAgent = false;
            EnableExternalDns = true;
            EnableExternalIngress = true;
            EnableInternalIngress = true;
            EnableKarpenter = true;
            EnableOtel = false;
            KarpenterVersion = "0.36.2";
            LbType = "nlb";
            NginxIngressRegistry = "registry.k8s.io";
            NginxIngressTag = "v1.12.0";
        }
        public static new ClusterArgs Empty => new ClusterArgs();
    }
}

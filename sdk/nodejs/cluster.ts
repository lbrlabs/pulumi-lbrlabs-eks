// *** WARNING: this file was generated by Pulumi SDK Generator. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as utilities from "./utilities";

import * as pulumiAws from "@pulumi/aws";

export class Cluster extends pulumi.ComponentResource {
    /** @internal */
    public static readonly __pulumiType = 'lbrlabs-eks:index:Cluster';

    /**
     * Returns true if the given object is an instance of Cluster.  This is designed to work even
     * when multiple copies of the Pulumi SDK have been loaded into the same process.
     */
    public static isInstance(obj: any): obj is Cluster {
        if (obj === undefined || obj === null) {
            return false;
        }
        return obj['__pulumiType'] === Cluster.__pulumiType;
    }

    /**
     * The cluster name
     */
    public /*out*/ readonly clusterName!: pulumi.Output<string>;
    /**
     * The Cluster control plane
     */
    public /*out*/ readonly controlPlane!: pulumi.Output<pulumiAws.eks.Cluster>;
    /**
     * The role created for karpenter nodes.
     */
    public /*out*/ readonly karpenterNodeRole!: pulumi.Output<pulumiAws.iam.Role | undefined>;
    /**
     * The kubeconfig for this cluster.
     */
    public /*out*/ readonly kubeconfig!: pulumi.Output<string>;
    /**
     * The OIDC provider for this cluster.
     */
    public /*out*/ readonly oidcProvider!: pulumi.Output<pulumiAws.iam.OpenIdConnectProvider>;
    /**
     * The system node group.
     */
    public /*out*/ readonly systemNodes!: pulumi.Output<pulumiAws.eks.NodeGroup>;

    /**
     * Create a Cluster resource with the given unique name, arguments, and options.
     *
     * @param name The _unique_ name of the resource.
     * @param args The arguments to use to populate this resource's properties.
     * @param opts A bag of options that control this resource's behavior.
     */
    constructor(name: string, args: ClusterArgs, opts?: pulumi.ComponentResourceOptions) {
        let resourceInputs: pulumi.Inputs = {};
        opts = opts || {};
        if (!opts.id) {
            if ((!args || args.clusterSubnetIds === undefined) && !opts.urn) {
                throw new Error("Missing required property 'clusterSubnetIds'");
            }
            if ((!args || args.systemNodeSubnetIds === undefined) && !opts.urn) {
                throw new Error("Missing required property 'systemNodeSubnetIds'");
            }
            resourceInputs["certificateArn"] = args ? args.certificateArn : undefined;
            resourceInputs["clusterSubnetIds"] = args ? args.clusterSubnetIds : undefined;
            resourceInputs["enableCertManager"] = (args ? args.enableCertManager : undefined) ?? true;
            resourceInputs["enableCloudWatchAgent"] = (args ? args.enableCloudWatchAgent : undefined) ?? false;
            resourceInputs["enableExternalDns"] = (args ? args.enableExternalDns : undefined) ?? true;
            resourceInputs["enableKarpenter"] = (args ? args.enableKarpenter : undefined) ?? true;
            resourceInputs["enableOtel"] = (args ? args.enableOtel : undefined) ?? false;
            resourceInputs["lbType"] = (args ? args.lbType : undefined) ?? "nlb";
            resourceInputs["letsEncryptEmail"] = args ? args.letsEncryptEmail : undefined;
            resourceInputs["systemNodeDesiredCount"] = args ? args.systemNodeDesiredCount : undefined;
            resourceInputs["systemNodeInstanceTypes"] = args ? args.systemNodeInstanceTypes : undefined;
            resourceInputs["systemNodeMaxCount"] = args ? args.systemNodeMaxCount : undefined;
            resourceInputs["systemNodeMinCount"] = args ? args.systemNodeMinCount : undefined;
            resourceInputs["systemNodeSubnetIds"] = args ? args.systemNodeSubnetIds : undefined;
            resourceInputs["tags"] = args ? args.tags : undefined;
            resourceInputs["clusterName"] = undefined /*out*/;
            resourceInputs["controlPlane"] = undefined /*out*/;
            resourceInputs["karpenterNodeRole"] = undefined /*out*/;
            resourceInputs["kubeconfig"] = undefined /*out*/;
            resourceInputs["oidcProvider"] = undefined /*out*/;
            resourceInputs["systemNodes"] = undefined /*out*/;
        } else {
            resourceInputs["clusterName"] = undefined /*out*/;
            resourceInputs["controlPlane"] = undefined /*out*/;
            resourceInputs["karpenterNodeRole"] = undefined /*out*/;
            resourceInputs["kubeconfig"] = undefined /*out*/;
            resourceInputs["oidcProvider"] = undefined /*out*/;
            resourceInputs["systemNodes"] = undefined /*out*/;
        }
        opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts);
        super(Cluster.__pulumiType, name, resourceInputs, opts, true /*remote*/);
    }
}

/**
 * The set of arguments for constructing a Cluster resource.
 */
export interface ClusterArgs {
    /**
     * The ARN of the certificate to use for the ingress controller.
     */
    certificateArn?: pulumi.Input<string>;
    clusterSubnetIds: pulumi.Input<pulumi.Input<string>[]>;
    /**
     * Whether to enable cert-manager with route 53 integration.
     */
    enableCertManager?: boolean;
    /**
     * Whether to enable cloudwatch container insights for EKS.
     */
    enableCloudWatchAgent?: boolean;
    /**
     * Whether to enable external dns with route 53 integration.
     */
    enableExternalDns?: boolean;
    /**
     * Whether to enable karpenter.
     */
    enableKarpenter?: boolean;
    /**
     * Whether to enable the OTEL Distro for EKS.
     */
    enableOtel?: boolean;
    /**
     * The type of loadbalancer to provision.
     */
    lbType?: pulumi.Input<string>;
    /**
     * The email address to use to issue certificates from Lets Encrypt.
     */
    letsEncryptEmail?: pulumi.Input<string>;
    /**
     * The initial number of nodes in the system autoscaling group.
     */
    systemNodeDesiredCount?: pulumi.Input<number>;
    systemNodeInstanceTypes?: pulumi.Input<pulumi.Input<string>[]>;
    /**
     * The maximum number of nodes in the system autoscaling group.
     */
    systemNodeMaxCount?: pulumi.Input<number>;
    /**
     * The minimum number of nodes in the system autoscaling group.
     */
    systemNodeMinCount?: pulumi.Input<number>;
    systemNodeSubnetIds: pulumi.Input<pulumi.Input<string>[]>;
    /**
     * Key-value map of tags to apply to the cluster.
     */
    tags?: pulumi.Input<{[key: string]: pulumi.Input<string>}>;
}

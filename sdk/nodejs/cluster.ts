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

    public /*out*/ readonly controlPlane!: pulumi.Output<pulumiAws.eks.Cluster>;
    /**
     * The kubeconfig for this cluster.
     */
    public /*out*/ readonly kubeconfig!: pulumi.Output<string>;
    public /*out*/ readonly oidcProvider!: pulumi.Output<pulumiAws.iam.OpenIdConnectProvider>;
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
            if ((!args || args.letsEncryptEmail === undefined) && !opts.urn) {
                throw new Error("Missing required property 'letsEncryptEmail'");
            }
            if ((!args || args.systemNodeSubnetIds === undefined) && !opts.urn) {
                throw new Error("Missing required property 'systemNodeSubnetIds'");
            }
            resourceInputs["clusterSubnetIds"] = args ? args.clusterSubnetIds : undefined;
            resourceInputs["letsEncryptEmail"] = args ? args.letsEncryptEmail : undefined;
            resourceInputs["systemNodeDesiredCount"] = args ? args.systemNodeDesiredCount : undefined;
            resourceInputs["systemNodeInstanceTypes"] = args ? args.systemNodeInstanceTypes : undefined;
            resourceInputs["systemNodeMaxCount"] = args ? args.systemNodeMaxCount : undefined;
            resourceInputs["systemNodeMinCount"] = args ? args.systemNodeMinCount : undefined;
            resourceInputs["systemNodeSubnetIds"] = args ? args.systemNodeSubnetIds : undefined;
            resourceInputs["controlPlane"] = undefined /*out*/;
            resourceInputs["kubeconfig"] = undefined /*out*/;
            resourceInputs["oidcProvider"] = undefined /*out*/;
            resourceInputs["systemNodes"] = undefined /*out*/;
        } else {
            resourceInputs["controlPlane"] = undefined /*out*/;
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
    clusterSubnetIds: pulumi.Input<pulumi.Input<string>[]>;
    /**
     * The email address to use to issue certificates from Lets Encrypt.
     */
    letsEncryptEmail: pulumi.Input<string>;
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
}

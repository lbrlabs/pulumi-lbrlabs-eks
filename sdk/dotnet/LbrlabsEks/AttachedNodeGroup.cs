// *** WARNING: this file was generated by Pulumi SDK Generator. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;
using Pulumi;

namespace Lbrlabs.PulumiPackage.LbrlabsEks
{
    [LbrlabsEksResourceType("lbrlabs-eks:index:AttachedNodeGroup")]
    public partial class AttachedNodeGroup : global::Pulumi.ComponentResource
    {
        [Output("nodeGroup")]
        public Output<Pulumi.Aws.Eks.NodeGroup> NodeGroup { get; private set; } = null!;


        /// <summary>
        /// Create a AttachedNodeGroup resource with the given unique name, arguments, and options.
        /// </summary>
        ///
        /// <param name="name">The unique name of the resource</param>
        /// <param name="args">The arguments used to populate this resource's properties</param>
        /// <param name="options">A bag of options that control this resource's behavior</param>
        public AttachedNodeGroup(string name, AttachedNodeGroupArgs args, ComponentResourceOptions? options = null)
            : base("lbrlabs-eks:index:AttachedNodeGroup", name, args ?? new AttachedNodeGroupArgs(), MakeResourceOptions(options, ""), remote: true)
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

    public sealed class AttachedNodeGroupArgs : global::Pulumi.ResourceArgs
    {
        /// <summary>
        /// The cluster name to attach the nodegroup tp.
        /// </summary>
        [Input("clusterName", required: true)]
        public Input<string> ClusterName { get; set; } = null!;

        /// <summary>
        /// The initial number of nodes in the node autoscaling group.
        /// </summary>
        [Input("nodeDesiredCount")]
        public Input<double>? NodeDesiredCount { get; set; }

        [Input("nodeInstanceTypes")]
        private InputList<string>? _nodeInstanceTypes;
        public InputList<string> NodeInstanceTypes
        {
            get => _nodeInstanceTypes ?? (_nodeInstanceTypes = new InputList<string>());
            set => _nodeInstanceTypes = value;
        }

        /// <summary>
        /// The maximum number of nodes in the node autoscaling group.
        /// </summary>
        [Input("nodeMaxCount")]
        public Input<double>? NodeMaxCount { get; set; }

        /// <summary>
        /// The minimum number of nodes in the node autoscaling group.
        /// </summary>
        [Input("nodeMinCount")]
        public Input<double>? NodeMinCount { get; set; }

        [Input("subnetIds", required: true)]
        private InputList<string>? _subnetIds;
        public InputList<string> SubnetIds
        {
            get => _subnetIds ?? (_subnetIds = new InputList<string>());
            set => _subnetIds = value;
        }

        public AttachedNodeGroupArgs()
        {
        }
        public static new AttachedNodeGroupArgs Empty => new AttachedNodeGroupArgs();
    }
}

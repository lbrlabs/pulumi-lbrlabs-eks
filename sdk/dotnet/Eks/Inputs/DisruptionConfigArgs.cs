// *** WARNING: this file was generated by Pulumi SDK Generator. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;
using Pulumi;

namespace Lbrlabs.PulumiPackage.Eks.Inputs
{

    /// <summary>
    /// Configuration for Autoscaled nodes disruption.
    /// </summary>
    public sealed class DisruptionConfigArgs : global::Pulumi.ResourceArgs
    {
        [Input("budgets")]
        private InputList<Inputs.BudgetConfigArgs>? _budgets;

        /// <summary>
        /// Budgets control the speed Karpenter can scale down nodes.
        /// </summary>
        public InputList<Inputs.BudgetConfigArgs> Budgets
        {
            get => _budgets ?? (_budgets = new InputList<Inputs.BudgetConfigArgs>());
            set => _budgets = value;
        }

        /// <summary>
        /// The amount of time Karpenter should wait after discovering a consolidation decision. This value can currently only be set when the consolidationPolicy is 'WhenEmpty'. You can choose to disable consolidation entirely by setting the string value 'Never' here.
        /// </summary>
        [Input("consolidateAfter")]
        public Input<string>? ConsolidateAfter { get; set; }

        /// <summary>
        /// Describes which types of Nodes Karpenter should consider for consolidation.
        /// </summary>
        [Input("consolidationPolicy")]
        public Input<string>? ConsolidationPolicy { get; set; }

        /// <summary>
        /// The amount of time a Node can live on the cluster before being removed.
        /// </summary>
        [Input("expireAfter")]
        public Input<string>? ExpireAfter { get; set; }

        public DisruptionConfigArgs()
        {
            ConsolidateAfter = "10m";
            ConsolidationPolicy = "WhenEmpty";
        }
        public static new DisruptionConfigArgs Empty => new DisruptionConfigArgs();
    }
}

// *** WARNING: this file was generated by Pulumi SDK Generator. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as inputs from "../types/input";
import * as outputs from "../types/output";

/**
 * Represents a single requirement with key, operator, and values.
 */
export interface RequirementArgs {
    /**
     * The key of the requirement.
     */
    key?: pulumi.Input<string>;
    /**
     * The operator for the requirement (e.g., In, Gt).
     */
    operator?: pulumi.Input<string>;
    /**
     * The list of values for the requirement.
     */
    values?: pulumi.Input<pulumi.Input<string>[]>;
}
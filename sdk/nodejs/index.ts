// *** WARNING: this file was generated by Pulumi SDK Generator. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as utilities from "./utilities";

// Export members:
export { AttachedNodeGroupArgs } from "./attachedNodeGroup";
export type AttachedNodeGroup = import("./attachedNodeGroup").AttachedNodeGroup;
export const AttachedNodeGroup: typeof import("./attachedNodeGroup").AttachedNodeGroup = null as any;
utilities.lazyLoad(exports, ["AttachedNodeGroup"], () => require("./attachedNodeGroup"));

export { ClusterArgs } from "./cluster";
export type Cluster = import("./cluster").Cluster;
export const Cluster: typeof import("./cluster").Cluster = null as any;
utilities.lazyLoad(exports, ["Cluster"], () => require("./cluster"));

export { IamRoleMappingArgs } from "./iamRoleMapping";
export type IamRoleMapping = import("./iamRoleMapping").IamRoleMapping;
export const IamRoleMapping: typeof import("./iamRoleMapping").IamRoleMapping = null as any;
utilities.lazyLoad(exports, ["IamRoleMapping"], () => require("./iamRoleMapping"));

export { IamServiceAccountRoleArgs } from "./iamServiceAccountRole";
export type IamServiceAccountRole = import("./iamServiceAccountRole").IamServiceAccountRole;
export const IamServiceAccountRole: typeof import("./iamServiceAccountRole").IamServiceAccountRole = null as any;
utilities.lazyLoad(exports, ["IamServiceAccountRole"], () => require("./iamServiceAccountRole"));

export { ProviderArgs } from "./provider";
export type Provider = import("./provider").Provider;
export const Provider: typeof import("./provider").Provider = null as any;
utilities.lazyLoad(exports, ["Provider"], () => require("./provider"));


const _module = {
    version: utilities.getVersion(),
    construct: (name: string, type: string, urn: string): pulumi.Resource => {
        switch (type) {
            case "lbrlabs-eks:index:AttachedNodeGroup":
                return new AttachedNodeGroup(name, <any>undefined, { urn })
            case "lbrlabs-eks:index:Cluster":
                return new Cluster(name, <any>undefined, { urn })
            case "lbrlabs-eks:index:IamRoleMapping":
                return new IamRoleMapping(name, <any>undefined, { urn })
            case "lbrlabs-eks:index:IamServiceAccountRole":
                return new IamServiceAccountRole(name, <any>undefined, { urn })
            default:
                throw new Error(`unknown resource type ${type}`);
        }
    },
};
pulumi.runtime.registerResourceModule("lbrlabs-eks", "index", _module)
pulumi.runtime.registerResourcePackage("lbrlabs-eks", {
    version: utilities.getVersion(),
    constructProvider: (name: string, type: string, urn: string): pulumi.ProviderResource => {
        if (type !== "pulumi:providers:lbrlabs-eks") {
            throw new Error(`unknown provider type ${type}`);
        }
        return new Provider(name, <any>undefined, { urn });
    },
});

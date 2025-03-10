# coding=utf-8
# *** WARNING: this file was generated by Pulumi SDK Generator. ***
# *** Do not edit by hand unless you're certain you know what you are doing! ***

import copy
import warnings
import sys
import pulumi
import pulumi.runtime
from typing import Any, Mapping, Optional, Sequence, Union, overload
if sys.version_info >= (3, 11):
    from typing import NotRequired, TypedDict, TypeAlias
else:
    from typing_extensions import NotRequired, TypedDict, TypeAlias
from . import _utilities

__all__ = ['IamRoleMappingArgs', 'IamRoleMapping']

@pulumi.input_type
class IamRoleMappingArgs:
    def __init__(__self__, *,
                 groups: pulumi.Input[Sequence[pulumi.Input[str]]],
                 role_arn: pulumi.Input[str],
                 username: pulumi.Input[str]):
        """
        The set of arguments for constructing a IamRoleMapping resource.
        :param pulumi.Input[Sequence[pulumi.Input[str]]] groups: An array of groups to map the IAM role to.
        :param pulumi.Input[str] role_arn: The arn of the role to map to a Kubernetes group.
        :param pulumi.Input[str] username: The username to assign to the rolemapping.
        """
        pulumi.set(__self__, "groups", groups)
        pulumi.set(__self__, "role_arn", role_arn)
        pulumi.set(__self__, "username", username)

    @property
    @pulumi.getter
    def groups(self) -> pulumi.Input[Sequence[pulumi.Input[str]]]:
        """
        An array of groups to map the IAM role to.
        """
        return pulumi.get(self, "groups")

    @groups.setter
    def groups(self, value: pulumi.Input[Sequence[pulumi.Input[str]]]):
        pulumi.set(self, "groups", value)

    @property
    @pulumi.getter(name="roleArn")
    def role_arn(self) -> pulumi.Input[str]:
        """
        The arn of the role to map to a Kubernetes group.
        """
        return pulumi.get(self, "role_arn")

    @role_arn.setter
    def role_arn(self, value: pulumi.Input[str]):
        pulumi.set(self, "role_arn", value)

    @property
    @pulumi.getter
    def username(self) -> pulumi.Input[str]:
        """
        The username to assign to the rolemapping.
        """
        return pulumi.get(self, "username")

    @username.setter
    def username(self, value: pulumi.Input[str]):
        pulumi.set(self, "username", value)


class IamRoleMapping(pulumi.ComponentResource):
    @overload
    def __init__(__self__,
                 resource_name: str,
                 opts: Optional[pulumi.ResourceOptions] = None,
                 groups: Optional[pulumi.Input[Sequence[pulumi.Input[str]]]] = None,
                 role_arn: Optional[pulumi.Input[str]] = None,
                 username: Optional[pulumi.Input[str]] = None,
                 __props__=None):
        """
        Create a IamRoleMapping resource with the given unique name, props, and options.
        :param str resource_name: The name of the resource.
        :param pulumi.ResourceOptions opts: Options for the resource.
        :param pulumi.Input[Sequence[pulumi.Input[str]]] groups: An array of groups to map the IAM role to.
        :param pulumi.Input[str] role_arn: The arn of the role to map to a Kubernetes group.
        :param pulumi.Input[str] username: The username to assign to the rolemapping.
        """
        ...
    @overload
    def __init__(__self__,
                 resource_name: str,
                 args: IamRoleMappingArgs,
                 opts: Optional[pulumi.ResourceOptions] = None):
        """
        Create a IamRoleMapping resource with the given unique name, props, and options.
        :param str resource_name: The name of the resource.
        :param IamRoleMappingArgs args: The arguments to use to populate this resource's properties.
        :param pulumi.ResourceOptions opts: Options for the resource.
        """
        ...
    def __init__(__self__, resource_name: str, *args, **kwargs):
        resource_args, opts = _utilities.get_resource_args_opts(IamRoleMappingArgs, pulumi.ResourceOptions, *args, **kwargs)
        if resource_args is not None:
            __self__._internal_init(resource_name, opts, **resource_args.__dict__)
        else:
            __self__._internal_init(resource_name, *args, **kwargs)

    def _internal_init(__self__,
                 resource_name: str,
                 opts: Optional[pulumi.ResourceOptions] = None,
                 groups: Optional[pulumi.Input[Sequence[pulumi.Input[str]]]] = None,
                 role_arn: Optional[pulumi.Input[str]] = None,
                 username: Optional[pulumi.Input[str]] = None,
                 __props__=None):
        opts = pulumi.ResourceOptions.merge(_utilities.get_resource_opts_defaults(), opts)
        if not isinstance(opts, pulumi.ResourceOptions):
            raise TypeError('Expected resource options to be a ResourceOptions instance')
        if opts.id is not None:
            raise ValueError('ComponentResource classes do not support opts.id')
        else:
            if __props__ is not None:
                raise TypeError('__props__ is only valid when passed in combination with a valid opts.id to get an existing resource')
            __props__ = IamRoleMappingArgs.__new__(IamRoleMappingArgs)

            if groups is None and not opts.urn:
                raise TypeError("Missing required property 'groups'")
            __props__.__dict__["groups"] = groups
            if role_arn is None and not opts.urn:
                raise TypeError("Missing required property 'role_arn'")
            __props__.__dict__["role_arn"] = role_arn
            if username is None and not opts.urn:
                raise TypeError("Missing required property 'username'")
            __props__.__dict__["username"] = username
        super(IamRoleMapping, __self__).__init__(
            'lbrlabs-eks:index:IamRoleMapping',
            resource_name,
            __props__,
            opts,
            remote=True)


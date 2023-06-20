# Pulumi LBr Labs EKS 

This repo provides a [multi-language](https://www.pulumi.com/blog/pulumiup-pulumi-packages-multi-language-components/) component that creates a "batteries included" cluster ready for you to attach your EKS nodes to.

> :warning: **This is a work in progress**

It creates:

- an EKS cluster with [CloudTrail logging enabled](https://docs.aws.amazon.com/eks/latest/userguide/control-plane-logs.htmleks), and [secret encryption enabled](https://docs.aws.amazon.com/eks/latest/userguide/enable-kms.html)
- A node group designed to run "system" workloads with a taint
- The [AWS EBS CSI Addon](https://docs.aws.amazon.com/eks/latest/userguide/ebs-csi.html) with an [IAM role using IAM Roles for Service accounts](https://docs.aws.amazon.com/eks/latest/userguide/iam-roles-for-service-accounts.html)
- The [AWS VPC CBI Addon](https://docs.aws.amazon.com/eks/latest/userguide/managing-vpc-cni.html) with an [IAM role using IAM Roles for Service accounts](https://docs.aws.amazon.com/eks/latest/userguide/iam-roles-for-service-accounts.html)
- The CoreDNS Addon
- An internal and external [NGINX ingress controller](https://github.com/kubernetes/ingress-nginx) with relevant ingress classes
- [External DNS](https://github.com/kubernetes-sigs/external-dns), with an IAM role that can modify Route53 domains using IAM Roles for service accounts
- [Cert Manager](https://cert-manager.io/), with an IAM role that can modify Route53 domains using IAM Roles for service accounts

It is designed to be an opinionated implementation of EKS, without the overhead of having to install all of the things required for your cluster to be functional.

It also provides a mechanism to quickly attached a workload node to your newly created cluster, and create an [IAM role for Service accounts](https://docs.aws.amazon.com/eks/latest/userguide/iam-roles-for-service-accounts.html) with your cluster's OIDC provider.

## Examples

Examples for all languages are in the [examples](examples/) directory. 

Note, you need to create a VPC, and also add your worker nodes. 

## FAQs

### Can you add support for X

Add an issue, but this is mainly designed to be useful for workloads I run, so I reserve the right to refuse.

### Can you make X optional?

I have no plans to make any of the batteries included optional at this time

## Installing

This package is available in many languages in the standard packaging formats.

### Node.js (Java/TypeScript)

To use from JavaScript or TypeScript in Node.js, install using either `npm`:

```
$ npm install @lbrlabs/pulumi-eks
```

or `yarn`:

```
$ yarn add @lbrlabs/pulumi-eks
```

### Python

To use from Python, install using `pip`:

```
$ pip install lbrlabs_pulumi_eks
```

### Go

To use from Go, use `go get` to grab the latest version of the library

```
$ go get github.com/lbrlabs/pulumi-lbrlabs-eks/sdk/go/...
```

### .NET

To use from Dotnet, use `dotnet add package` to install into your project. You must specify the version if it is a pre-release version.


```
$ dotnet add package Lbrlabs.PulumiPackage.Eks
```

## Reference

See the Pulumi registry for API docs:

https://www.pulumi.com/registry/packages/lbrlabs-eks/api-docs/
import * as pulumi from "@pulumi/pulumi";
import * as awsx from "@pulumi/awsx";
import * as kubernetes from "@pulumi/kubernetes";
import * as lbrlabs_eks from "@lbrlabs/pulumi-eks";

const vpc = new awsx.ec2.Vpc("vpc", {
  cidrBlock: "172.16.0.0/16",
  subnetStrategy: awsx.ec2.SubnetAllocationStrategy.Auto,
  subnetSpecs: [
    {
      type: awsx.ec2.SubnetType.Public,
      cidrMask: 20,
      tags: {
        "kubernetes.io/role/elb": "1",
      },
    },
    {
      type: awsx.ec2.SubnetType.Private,
      cidrMask: 19,
      tags: {
        "kubernetes.io/role/internal-elb": "1",
      },
    },
  ],
});

const cluster = new lbrlabs_eks.Cluster("cluster", {
  clusterSubnetIds: vpc.privateSubnetIds,
  letsEncryptEmail: "mail@lbrlabs.com",
  systemNodeSubnetIds: vpc.publicSubnetIds,
  systemNodeDesiredCount: 2,
});

const workloadNodes = new lbrlabs_eks.AttachedNodeGroup("workload", {
  clusterName: cluster.clusterName,
  subnetIds: vpc.privateSubnetIds,
  scalingConfig: {
    desiredSize: 3,
    maxSize: 10,
    minSize: 1,
  },
});

const provider = new kubernetes.Provider("provider", {
  kubeconfig: cluster.kubeconfig,
});

const roleMapping = new lbrlabs_eks.IamRoleMapping(
  "nodes",
  {
    roleArn: workloadNodes.nodeRole.arn,
    username: "system:node:{{EC2PrivateDNSName}}",
    groups: ["system:bootstrappers", "system:nodes"],
  },
  {
    provider: provider,
  }
);

const wordpress = new kubernetes.helm.v3.Release(
  "wordpress",
  {
    chart: "wordpress",
    repositoryOpts: {
      repo: "https://charts.bitnami.com/bitnami",
    },
    values: {
      wordpressUsername: "lbrlabs",
      wordpressPassword: "correct-horse-battery-stable",
      wordpressEmail: "mail@lbrlabs.com",
      ingress: {
        enabled: true,
        ingressClassName: "external",
        hostname: "wordpress.aws.briggs.work",
        tls: true,
        annotations: {
          "cert-manager.io/cluster-issuer": "letsencrypt-prod",
          "nginx.ingress.kubernetes.io/force-ssl-redirect": "true",
        },
      },
    },
  },
  {
    provider: provider,
  }
);
export const kubeconfig = cluster.kubeconfig;

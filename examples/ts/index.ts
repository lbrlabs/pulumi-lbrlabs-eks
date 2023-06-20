import * as pulumi from "@pulumi/pulumi";
import * as awsx from "@pulumi/awsx";
import * as kubernetes from "@pulumi/kubernetes";

const vpc = new awsx.ec2.Vpc("vpc", {
    cidrBlock: "172.16.0.0/16",
    subnetSpecs: [
        {
            type: awsx.ec2.SubnetType.Public,
            tags: {
                "kubernetes.io/role/elb": "1",
            },
        },
        {
            type: awsx.ec2.SubnetType.Private,
            tags: {
                "kubernetes.io/role/internal-elb": "1",
            },
        },
    ],
});
const provider = new kubernetes.Provider("provider", {kubeconfig: cluster.kubeconfig});
const wordpress = new kubernetes.helm.v3.Release("wordpress", {
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
}, {
    provider: provider,
});
export const kubeconfig = cluster.kubeconfig;

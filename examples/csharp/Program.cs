using System.Collections.Generic;
using System.Linq;
using Pulumi;
using Awsx = Pulumi.Awsx;
using Aws = Pulumi.Aws;
using Kubernetes = Pulumi.Kubernetes;
using LbrlabsEks = Lbrlabs.PulumiPackage.LbrlabsEks;

return await Deployment.RunAsync(() =>
{
    var vpc = new Awsx.Ec2.Vpc("vpc", new()
    {
        CidrBlock = "172.16.0.0/16",
        SubnetSpecs = new List<Awsx.Ec2.Inputs.SubnetSpecArgs>
        {
            new Awsx.Ec2.Inputs.SubnetSpecArgs
            {
                Type = Awsx.Ec2.SubnetType.Public,
                Tags = new InputMap<string>
                {
                    { "kubernetes.io/role/elb", "1" },
                },
            },
            new Awsx.Ec2.Inputs.SubnetSpecArgs
            {
                Type = Awsx.Ec2.SubnetType.Private,
                Tags = new InputMap<string>
                {
                    { "kubernetes.io/role/internal-elb", "1" },
                },
            }
        }
    });

    var cluster = new LbrlabsEks.Cluster("cluster", new()
    {
        ClusterSubnetIds = vpc.PublicSubnetIds,
        SystemNodeSubnetIds = vpc.PrivateSubnetIds,
        LetsEncryptEmail = "mail@lbrlabs.com",
        SystemNodeInstanceTypes = new[]
        {
            "t3.large",
        },
        SystemNodeDesiredCount = 4,
    });

    var workloadNodes = new LbrlabsEks.AttachedNodeGroup("workloadNodes", new()
    {
        ClusterName = cluster.ControlPlane.Apply(controlPlane => controlPlane.Name),
        SubnetIds = vpc.PrivateSubnetIds,
        // ScalingConfig = new Aws.Eks.Inputs.NodeGroupScalingConfigArgs
        // {
        //     DesiredSize = 4,
        //     MaxSize = 4,
        //     MinSize = 4,
        // },
    });

    var provider = new Kubernetes.Provider("provider", new()
    {
        KubeConfig = cluster.Kubeconfig,
    });

    var wordpress = new Kubernetes.Helm.V3.Release("wordpress", new()
    {
        Chart = "wordpress",
        RepositoryOpts = new Kubernetes.Types.Inputs.Helm.V3.RepositoryOptsArgs
        {
            Repo = "https://charts.bitnami.com/bitnami",
        },
        Values = new Dictionary<string, object>
        {
            ["ingress"] = new Dictionary<string, object>
            {
                ["annotations"] = new Dictionary<string, object>
                {
                    ["cert-manager.io/cluster-issuer"] = "letsencrypt-prod",
                    ["nginx.ingress.kubernetes.io/force-ssl-redirect"] = "true",
                },
                ["enabled"] = true,
                ["ingressClassName"] = "external",
                ["hostname"] = "wordpress.aws.briggs.work",
                ["tls"] = true,
            },
            ["wordpressUsername"] = "lbrlabs",
            ["wordpressPassword"] = "correct-horse-battery-stable",
            ["wordpressEmail"] = "mail@lbrlabs.com",
        }
    }, new CustomResourceOptions
    {
        Provider = provider,
    });

    return new Dictionary<string, object?>
    {
        ["kubeconfig"] = cluster.Kubeconfig,
    };
});


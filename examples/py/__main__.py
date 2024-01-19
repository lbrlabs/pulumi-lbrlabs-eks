import pulumi
import lbrlabs_pulumi_eks as lbrlabs_eks
import pulumi_aws as aws
import pulumi_awsx as awsx
import pulumi_kubernetes as kubernetes

vpc = awsx.ec2.Vpc(
    "vpc",
    cidr_block="172.16.0.0/16",
    subnet_strategy=awsx.ec2.SubnetAllocationStrategy.AUTO,
    subnet_specs=[
        awsx.ec2.SubnetSpecArgs(
            type=awsx.ec2.SubnetType.PUBLIC,
            cidr_mask=20,
            tags={
                "kubernetes.io/role/elb": "1",
            },
        ),
        awsx.ec2.SubnetSpecArgs(
            type=awsx.ec2.SubnetType.PRIVATE,
            cidr_mask=19,
            tags={
                "kubernetes.io/role/internal-elb": "1",
            },
        ),
    ],
)
cluster = lbrlabs_eks.Cluster(
    "cluster",
    cluster_subnet_ids=vpc.public_subnet_ids,
    system_node_subnet_ids=vpc.private_subnet_ids,
    system_node_instance_types=["t3.large"],
    system_node_desired_count=4,
)

provider = kubernetes.Provider("provider", kubeconfig=cluster.kubeconfig)

workload_nodes = lbrlabs_eks.AttachedNodeGroup(
    "workload",
    cluster_name=cluster.control_plane.name,
    subnet_ids=vpc.private_subnet_ids,
    scaling_config=aws.eks.NodeGroupScalingConfigArgs(
        desired_size=4,
        max_size=10,
        min_size=1,
    ),
    opts=pulumi.ResourceOptions(
        parent=cluster,
        providers={"kubernetes": provider},
    ),
)

wordpress = kubernetes.helm.v3.Release(
    "wordpress",
    chart="wordpress",
    repository_opts=kubernetes.helm.v3.RepositoryOptsArgs(
        repo="https://charts.bitnami.com/bitnami",
    ),
    values={
        "wordpressUsername": "lbrlabs",
        "wordpressPassword": "correct-horse-battery-stable",
        "wordpressEmail": "mail@lbrlabs.com",
        "ingress": {
            "enabled": True,
            "ingressClassName": "external",
            "hostname": "wordpress.aws.briggs.work",
            "tls": True,
            "annotations": {
                "cert-manager.io/cluster-issuer": "letsencrypt-prod",
                "nginx.ingress.kubernetes.io/force-ssl-redirect": "true",
            },
        },
    },
    opts=pulumi.ResourceOptions(provider=provider),
)
pulumi.export("kubeconfig", cluster.kubeconfig)

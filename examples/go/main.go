package main

import (
	"fmt"

	lbrlabs "github.com/lbrlabs/pulumi-lbrlabs-eks/sdk/go/eks"
	"github.com/pulumi/pulumi-awsx/sdk/go/awsx/ec2"
	"github.com/pulumi/pulumi-kubernetes/sdk/v3/go/kubernetes"
	helm "github.com/pulumi/pulumi-kubernetes/sdk/v3/go/kubernetes/helm/v3"
	eks "github.com/pulumi/pulumi-aws/sdk/v5/go/aws/eks"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

func main() {
	pulumi.Run(func(ctx *pulumi.Context) error {
		// Create an AWS resource (S3 Bucket)

		cidrBlock := "172.16.0.0/16"
		vpc, err := ec2.NewVpc(ctx, "vpc", &ec2.VpcArgs{
			CidrBlock: &cidrBlock,
			SubnetSpecs: []ec2.SubnetSpecArgs{
				{
					Type: ec2.SubnetTypePublic,
				},
				{
					Type: ec2.SubnetTypePrivate,
				},
			},
		})
		if err != nil {
			return fmt.Errorf("error creating VPC")
		}

		cluster, err := lbrlabs.NewCluster(ctx, "cluster", &lbrlabs.ClusterArgs{
			ClusterSubnetIds:    vpc.PublicSubnetIds,
			SystemNodeSubnetIds: vpc.PrivateSubnetIds,
			SystemNodeInstanceTypes: pulumi.StringArray{
				pulumi.String("t3.large"),
			},
			SystemNodeDesiredCount: pulumi.Float64Ptr(4),
			LetsEncryptEmail:       pulumi.String("mail@lbrlabs.com"),
		})

		workloadNodes, err := lbrlabs.NewAttachedNodeGroup(ctx, "workloadNodes", &lbrlabs.AttachedNodeGroupArgs{
			ClusterName: cluster.ControlPlane.Name(),
			SubnetIds:   vpc.PrivateSubnetIds,
			ScalingConfig: &eks.NodeGroupScalingConfigArgs{
				DesiredSize: pulumi.Int(4),
				MaxSize:     pulumi.Int(10),
				MinSize:     pulumi.Int(1),
			},
		})

		_, err = lbrlabs.NewIamRoleMapping(ctx, "roleMapping", &lbrlabs.IamRoleMappingArgs{
			RoleArn:  workloadNodes.NodeRole.Arn(),
			Username: pulumi.String("system:node:{{EC2PrivateDNSName}}"),
			Groups: pulumi.StringArray{
				pulumi.String("system:bootstrappers"),
				pulumi.String("system:nodes"),
			},
		})

		provider, err := kubernetes.NewProvider(ctx, "provider", &kubernetes.ProviderArgs{
			Kubeconfig: cluster.Kubeconfig,
		})

		_, err = helm.NewRelease(ctx, "wordpress", &helm.ReleaseArgs{
			Chart: pulumi.String("wordpress"),
			RepositoryOpts: &helm.RepositoryOptsArgs{
				Repo: pulumi.String("https://charts.bitnami.com/bitnami"),
			},
			Values: pulumi.Map{
				"wordpressUsername": pulumi.String("user"),
				"wordpressPassword": pulumi.String("correct-horse-battery-stable"),
				"ingress": pulumi.Map{
					"enabled":          pulumi.Bool(true),
					"ingressClassName": pulumi.String("external"),
					"hostname":         pulumi.String("wordpress.aws.briggs.work"),
					"tls":              pulumi.Bool(true),
					"annotations": pulumi.Map{
						"cert-manager.io/cluster-issuer":                 pulumi.String("letsencrypt-prod"),
						"nginx.ingress.kubernetes.io/force-ssl-redirect": pulumi.String("true"),
					},
				},
			},
		}, pulumi.Provider(provider))

		ctx.Export("vpcId", vpc.VpcId)

		return nil
	})
}

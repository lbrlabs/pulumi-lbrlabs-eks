package main

import (
	"fmt"

	lbrlabs "github.com/lbrlabs/pulumi-lbrlabs-eks/sdk/go/eks"
	eks "github.com/pulumi/pulumi-aws/sdk/v6/go/aws/eks"
	"github.com/pulumi/pulumi-awsx/sdk/go/awsx/ec2"
	helm "github.com/pulumi/pulumi-kubernetes/sdk/v3/go/kubernetes/helm/v3"
	"github.com/pulumi/pulumi-kubernetes/sdk/v4/go/kubernetes"
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

		letsEncryptEmail := "mail@lbrlabs.com"

		cluster, err := lbrlabs.NewCluster(ctx, "cluster", &lbrlabs.ClusterArgs{
			ClusterSubnetIds:    vpc.PublicSubnetIds,
			SystemNodeSubnetIds: vpc.PrivateSubnetIds,
			SystemNodeInstanceTypes: pulumi.StringArray{
				pulumi.String("t3.large"),
			},
			SystemNodeDesiredCount: pulumi.Float64Ptr(4),
			LetsEncryptEmail:       &letsEncryptEmail,
		})
		if err != nil {
			return fmt.Errorf("error creating cluster")
		}

		workloadNodes, err := lbrlabs.NewAttachedNodeGroup(ctx, "workloadNodes", &lbrlabs.AttachedNodeGroupArgs{
			ClusterName: cluster.ControlPlane.Name(),
			SubnetIds:   vpc.PrivateSubnetIds,
			ScalingConfig: &eks.NodeGroupScalingConfigArgs{
				DesiredSize: pulumi.Int(4),
				MaxSize:     pulumi.Int(10),
				MinSize:     pulumi.Int(1),
			},
		})
		if err != nil {
			return fmt.Errorf("error creating workload nodes")
		}

		_, err = lbrlabs.NewAttachedNodeGroup(ctx, "taintedNodes", &lbrlabs.AttachedNodeGroupArgs{
			ClusterName: cluster.ControlPlane.Name(),
			SubnetIds:   vpc.PrivateSubnetIds,
			ScalingConfig: &eks.NodeGroupScalingConfigArgs{
				DesiredSize: pulumi.Int(1),
				MaxSize:     pulumi.Int(10),
				MinSize:     pulumi.Int(1),
			},
			Taints: eks.NodeGroupTaintArray{
				&eks.NodeGroupTaintArgs{
					Effect: pulumi.String("NoSchedule"),
					Key:    pulumi.String("dedicated"),
					Value:  pulumi.String("tainted"),
				},
			},
		})
		if err != nil {
			return fmt.Errorf("error creating workload nodes")
		}

		profile, err := lbrlabs.NewAttachedFargateProfile(ctx, "profile", &lbrlabs.AttachedFargateProfileArgs{
			ClusterName: cluster.ControlPlane.Name(),
			SubnetIds:   vpc.PrivateSubnetIds,
			Selectors: eks.FargateProfileSelectorArray{
				&eks.FargateProfileSelectorArgs{
					Namespace: pulumi.String("default"),
				},
			},
		})
		if err != nil {
			return fmt.Errorf("error creating fargate profile")
		}
		ctx.Export("profileStatus", profile.Profile.Status())

		provider, err := kubernetes.NewProvider(ctx, "provider", &kubernetes.ProviderArgs{
			Kubeconfig: cluster.Kubeconfig,
		})
		if err != nil {
			return fmt.Errorf("error creating provider")
		}

		_, err = lbrlabs.NewIamRoleMapping(ctx, "rolemapping", &lbrlabs.IamRoleMappingArgs{
			RoleArn:  workloadNodes.NodeRole.Arn(),
			Username: pulumi.String("system:node:{{EC2PrivateDNSName}}"),
			Groups: pulumi.StringArray{
				pulumi.String("system:bootstrappers"),
				pulumi.String("system:nodes"),
			},
		}, pulumi.Provider(provider), pulumi.Parent(provider))
		if err != nil {
			return fmt.Errorf("error creating role mapping")
		}

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
		}, pulumi.Provider(provider), pulumi.Parent(provider))
		if err != nil {
			return fmt.Errorf("error creating wordpress helm release")
		}

		ctx.Export("vpcId", vpc.VpcId)

		return nil
	})
}

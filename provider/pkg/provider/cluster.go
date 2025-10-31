package provider

import (
	"encoding/json"
	"fmt"

	"github.com/lbrlabs/pulumi-lbrlabs-eks/pkg/provider/kubeconfig"
	"github.com/pulumi/pulumi-aws/sdk/v6/go/aws"
	"github.com/pulumi/pulumi-aws/sdk/v6/go/aws/cloudwatch"
	"github.com/pulumi/pulumi-aws/sdk/v6/go/aws/eks"
	"github.com/pulumi/pulumi-aws/sdk/v6/go/aws/iam"
	"github.com/pulumi/pulumi-aws/sdk/v6/go/aws/kms"
	"github.com/pulumi/pulumi-aws/sdk/v6/go/aws/sqs"
	"github.com/pulumi/pulumi-kubernetes/sdk/v4/go/kubernetes"
	apiextensions "github.com/pulumi/pulumi-kubernetes/sdk/v4/go/kubernetes/apiextensions"
	apiextensionsv1 "github.com/pulumi/pulumi-kubernetes/sdk/v4/go/kubernetes/apiextensions/v1"
	corev1 "github.com/pulumi/pulumi-kubernetes/sdk/v4/go/kubernetes/core/v1"
	helm "github.com/pulumi/pulumi-kubernetes/sdk/v4/go/kubernetes/helm/v3"
	metav1 "github.com/pulumi/pulumi-kubernetes/sdk/v4/go/kubernetes/meta/v1"
	storagev1 "github.com/pulumi/pulumi-kubernetes/sdk/v4/go/kubernetes/storage/v1"
	yaml "github.com/pulumi/pulumi-kubernetes/sdk/v4/go/kubernetes/yaml"

	tls "github.com/pulumi/pulumi-tls/sdk/v5/go/tls"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// ingress configuration args (deprecated, use NginxIngressConfig)
type IngressConfig struct {
	EnableMetrics           pulumi.BoolInput   `pulumi:"enableMetrics"`
	EnableServiceMonitor    pulumi.BoolInput   `pulumi:"enableServiceMonitor"`
	ServiceMonitorNamespace pulumi.StringInput `pulumi:"serviceMonitorNamespace"`
	ControllerReplicas      pulumi.IntInput    `pulumi:"controllerReplicas"`
	AdditionalConfig        pulumi.MapInput    `pulumi:"additionalConfig"`
	NlbTargetType           pulumi.StringInput `pulumi:"nlbTargetType"`
	ExtraServiceAnnotations pulumi.MapInput    `pulumi:"extraServiceAnnotations"`
	AllowSnippetAnnotations pulumi.BoolInput   `pulumi:"allowSnippetAnnotations"`
	// EnableExternal controls whether to create the external-facing ingress controller
	// TODO: In future versions, this will override the EnableExternalIngress cluster arg
	EnableExternal pulumi.BoolInput `pulumi:"enableExternal"`
	// EnableInternal controls whether to create the internal-facing ingress controller
	// TODO: In future versions, this will override the EnableInternalIngress cluster arg
	EnableInternal pulumi.BoolInput `pulumi:"enableInternal"`
}

// nginx ingress configuration args
type NginxIngressConfig struct {
	EnableMetrics           pulumi.BoolInput   `pulumi:"enableMetrics"`
	EnableServiceMonitor    pulumi.BoolInput   `pulumi:"enableServiceMonitor"`
	ServiceMonitorNamespace pulumi.StringInput `pulumi:"serviceMonitorNamespace"`
	ControllerReplicas      pulumi.IntInput    `pulumi:"controllerReplicas"`
	AdditionalConfig        pulumi.MapInput    `pulumi:"additionalConfig"`
	NlbTargetType           pulumi.StringInput `pulumi:"nlbTargetType"`
	ExtraServiceAnnotations pulumi.MapInput    `pulumi:"extraServiceAnnotations"`
	AllowSnippetAnnotations pulumi.BoolInput   `pulumi:"allowSnippetAnnotations"`
	// EnableExternal controls whether to create the external-facing ingress controller
	EnableExternal pulumi.BoolInput `pulumi:"enableExternal"`
	// EnableInternal controls whether to create the internal-facing ingress controller
	EnableInternal pulumi.BoolInput `pulumi:"enableInternal"`
}

// The set of arguments for creating a Cluster component resource.
type ClusterArgs struct {
	ClusterSubnetIds             pulumi.StringArrayInput  `pulumi:"clusterSubnetIds"`
	ClusterEndpointPublicAccess  pulumi.BoolInput         `pulumi:"clusterEndpointPublicAccess"`
	ClusterEndpointPrivateAccess pulumi.BoolInput         `pulumi:"clusterEndpointPrivateAccess"`
	SystemNodeSubnetIds          pulumi.StringArrayInput  `pulumi:"systemNodeSubnetIds"`
	SystemNodeInstanceTypes      *pulumi.StringArrayInput `pulumi:"systemNodeInstanceTypes"`
	SystemNodeMaxCount           *pulumi.IntInput         `pulumi:"systemNodeMaxCount"`
	SystemNodeMinCount           *pulumi.IntInput         `pulumi:"systemNodeMinCount"`
	SystemNodeDesiredCount       *pulumi.IntInput         `pulumi:"systemNodeDesiredCount"`
	ClusterVersion               pulumi.StringPtrInput    `pulumi:"clusterVersion"`
	EnableOtel                   bool                     `pulumi:"enableOtel"`
	EnableCloudWatchAgent        bool                     `pulumi:"enableCloudWatchAgent"`
	EnableExternalDNS            bool                     `pulumi:"enableExternalDns"`
	EnableCertManager            bool                     `pulumi:"enableCertManager"`
	EnableKarpenter              bool                     `pulumi:"enableKarpenter"`
	KarpenterVersion             string                   `pulumi:"karpenterVersion"`
	LetsEncryptEmail             string                   `pulumi:"letsEncryptEmail"`
	IngressConfig                *IngressConfig           `pulumi:"ingressConfig"`
	NginxIngressConfig           *NginxIngressConfig      `pulumi:"nginxIngressConfig"`
	// EnableInternalIngress controls whether to create the internal ingress controller
	// To disable, set this to false. In future versions, this will be controlled by
	// NginxIngressConfig.EnableInternal
	EnableInternalIngress bool `pulumi:"enableInternalIngress"`
	// EnableExternalIngress controls whether to create the external ingress controller
	// To disable, set this to false. In future versions, this will be controlled by
	// NginxIngressConfig.EnableExternal
	EnableExternalIngress       bool                     `pulumi:"enableExternalIngress"`
	LbType                      pulumi.StringInput       `pulumi:"lbType"`
	CertificateArn              *pulumi.StringInput      `pulumi:"certificateArn"`
	Tags                        *pulumi.StringMapInput   `pulumi:"tags"`
	NginxIngressVersion         pulumi.StringInput       `pulumi:"nginxIngressVersion"`
	NginxIngressRegistry        pulumi.StringInput       `pulumi:"nginxIngressRegistry"`
	NginxIngressTag             pulumi.StringInput       `pulumi:"nginxIngressTag"`
	EksIamAuthControllerVersion pulumi.StringInput       `pulumi:"eksIamAuthControllerVersion"`
	ExternalDNSVersion          pulumi.StringInput       `pulumi:"externalDNSVersion"`
	CertManagerVersion          pulumi.StringInput       `pulumi:"certManagerVersion"`
	EnabledClusterLogTypes      *pulumi.StringArrayInput `pulumi:"enabledClusterLogTypes"`
	AdminAccessPrincipal        pulumi.StringInput       `pulumi:"adminAccessPrincipal"`
}

// The Cluster component resource.
type Cluster struct {
	pulumi.ResourceState

	ClusterName        pulumi.StringOutput           `pulumi:"clusterName"`
	ControlPlane       *eks.Cluster                  `pulumi:"controlPlane"`
	SystemNodes        *NodeGroup                    `pulumi:"systemNodes"`
	OidcProvider       *iam.OpenIdConnectProvider    `pulumi:"oidcProvider"`
	KubeConfig         pulumi.StringOutput           `pulumi:"kubeconfig"`
	ClusterIssuer      *apiextensions.CustomResource `pulumi:"clusterIssuer"`
	KarpenterRole      *iam.Role                     `pulumi:"karpenterRole"`
	KarpenterNodeRole  *iam.Role                     `pulumi:"karpenterNodeRole"`
	KarpenterQueueName pulumi.StringPtrOutput        `pulumi:"karpenterQueueName"`
}

// event struct
type Event struct {
	Name         string
	Description  string
	EventPattern map[string][]string
}

// NewCluster creates a new EKS Cluster component resource.
func NewCluster(ctx *pulumi.Context,
	name string, args *ClusterArgs, opts ...pulumi.ResourceOption) (*Cluster, error) {
	if args == nil {
		args = &ClusterArgs{}
	}

	var tags pulumi.StringMapInput

	if args.Tags != nil {
		tags = *args.Tags
	} else {
		tags = pulumi.StringMap{}
	}

	component := &Cluster{}
	err := ctx.RegisterComponentResource("lbrlabs-eks:index:Cluster", name, component, opts...)
	if err != nil {
		return nil, err
	}

	callerIdentity, err := aws.GetCallerIdentity(ctx, nil, pulumi.Parent(component))
	if err != nil {
		return nil, fmt.Errorf("error getting caller identity: %w", err)
	}

	err = ctx.Log.Debug(fmt.Sprintf("Current user: %s", callerIdentity.Arn), &pulumi.LogArgs{Resource: component})
	if err != nil {
		return nil, err
	}

	current, err := aws.GetPartition(ctx, nil, pulumi.Parent(component))
	if err != nil {
		return nil, fmt.Errorf("error getting partition: %w", err)
	}

	region, err := aws.GetRegion(ctx, nil, pulumi.Parent(component))
	if err != nil {
		return nil, fmt.Errorf("error getting region: %w", err)
	}

	// FIXME: make this strongly typed instead of using interfaces
	clusterRoleJSON, err := json.Marshal(map[string]interface{}{
		"Version": "2012-10-17",
		"Statement": []interface{}{
			map[string]interface{}{
				"Action": "sts:AssumeRole",
				"Principal": map[string]interface{}{
					"Service": []interface{}{
						"eks.amazonaws.com",
					},
				},
				"Effect": "Allow",
			},
		},
	})
	if err != nil {
		return nil, fmt.Errorf("error marshalling cluster role json: %w", err)
	}

	role, err := iam.NewRole(ctx, fmt.Sprintf("%s-cluster-role", name), &iam.RoleArgs{
		AssumeRolePolicy: pulumi.String(clusterRoleJSON),
		Tags:             tags,
	}, pulumi.Parent(component))
	if err != nil {
		return nil, fmt.Errorf("error creating cluster role: %w", err)
	}

	_, err = iam.NewRolePolicyAttachment(ctx, fmt.Sprintf("%s-cluster-policy", name), &iam.RolePolicyAttachmentArgs{
		Role:      role.Name,
		PolicyArn: pulumi.String("arn:aws:iam::aws:policy/AmazonEKSClusterPolicy"),
	}, pulumi.Parent(role))
	if err != nil {
		return nil, fmt.Errorf("error attaching cluster policy: %w", err)
	}

	_, err = iam.NewRolePolicyAttachment(ctx, fmt.Sprintf("%s-cluster-policy-vpc", name), &iam.RolePolicyAttachmentArgs{
		Role:      role.Name,
		PolicyArn: pulumi.String("arn:aws:iam::aws:policy/AmazonEKSVPCResourceController"),
	}, pulumi.Parent(role))
	if err != nil {
		return nil, fmt.Errorf("error attaching cluster policy for VPC: %w", err)
	}

	// FIXME: ensure we have a key policy for this key that's sane
	kmsKey, err := kms.NewKey(ctx, fmt.Sprintf("%s-cluster-kms-key", name), &kms.KeyArgs{
		EnableKeyRotation: pulumi.Bool(true),
		Description:       pulumi.String("KMS key for EKS cluster secrets"),
		Tags:              tags,
	}, pulumi.Parent(component))
	if err != nil {
		return nil, fmt.Errorf("error creating cluster kms key: %w", err)
	}

	keyPolicyDocument := iam.GetPolicyDocumentOutput(ctx, iam.GetPolicyDocumentOutputArgs{
		Statements: iam.GetPolicyDocumentStatementArray{
			iam.GetPolicyDocumentStatementArgs{
				Sid: pulumi.String("AllowAccessToKmsKey"),
				Actions: pulumi.StringArray{
					pulumi.String("kms:Encrypt"),
					pulumi.String("kms:Decrypt"),
					pulumi.String("kms:ListGrants"),
					pulumi.String("kms:DescribeKey"),
				},
				Effect: pulumi.String("Allow"),
				Resources: pulumi.StringArray{
					kmsKey.Arn,
				},
			},
		},
	})

	clusterKmsPolicy, err := iam.NewPolicy(ctx, fmt.Sprintf("%s-cluster-kms-policy", name), &iam.PolicyArgs{
		Description: pulumi.String("KMS key policy for EKS cluster secrets"),
		Policy:      keyPolicyDocument.Json(),
		Tags:        tags,
	}, pulumi.Parent(role))
	if err != nil {
		return nil, fmt.Errorf("error creating KMS key policy: %w", err)
	}

	_, err = iam.NewRolePolicyAttachment(ctx, fmt.Sprintf("%s-cluster-policy-kms", name), &iam.RolePolicyAttachmentArgs{
		Role:      role.Name,
		PolicyArn: clusterKmsPolicy.Arn,
	}, pulumi.Parent(role))
	if err != nil {
		return nil, fmt.Errorf("error attaching cluster policy for KMS: %w", err)
	}

	var enabledClusterLogTypes pulumi.StringArrayInput

	if args.EnabledClusterLogTypes == nil {
		enabledClusterLogTypes = pulumi.StringArray{
			pulumi.String("api"),
			pulumi.String("audit"),
			pulumi.String("authenticator"),
			pulumi.String("controllerManager"),
			pulumi.String("scheduler"),
		}
	} else {
		enabledClusterLogTypes = *args.EnabledClusterLogTypes
	}

	controlPlane, err := eks.NewCluster(ctx, name, &eks.ClusterArgs{
		RoleArn: role.Arn,
		Version: args.ClusterVersion,
		AccessConfig: eks.ClusterAccessConfigArgs{
			AuthenticationMode: pulumi.String("API_AND_CONFIG_MAP"),
		},
		VpcConfig: &eks.ClusterVpcConfigArgs{
			SubnetIds:             args.ClusterSubnetIds,
			EndpointPublicAccess:  args.ClusterEndpointPublicAccess,
			EndpointPrivateAccess: args.ClusterEndpointPrivateAccess,
		},
		EncryptionConfig: &eks.ClusterEncryptionConfigArgs{
			Resources: pulumi.StringArray{
				pulumi.String("secrets"),
			},
			Provider: &eks.ClusterEncryptionConfigProviderArgs{
				KeyArn: kmsKey.Arn,
			},
		},
		EnabledClusterLogTypes: enabledClusterLogTypes,
		Tags:                   tags,
	}, pulumi.Parent(component))
	if err != nil {
		return nil, fmt.Errorf("error creating cluster control plane: %w", err)
	}

	accessEntry, err := eks.NewAccessEntry(ctx, fmt.Sprintf("%s-admin-access", name), &eks.AccessEntryArgs{
		ClusterName:  controlPlane.Name,
		Type:         pulumi.String("STANDARD"),
		PrincipalArn: args.AdminAccessPrincipal,
	}, pulumi.Parent(controlPlane))

	if err != nil {
		return nil, fmt.Errorf("error creating access entry: %w", err)
	}

	accessPolicy, err := eks.NewAccessPolicyAssociation(ctx, fmt.Sprintf("%s-admin-policy", name), &eks.AccessPolicyAssociationArgs{
		AccessScope: eks.AccessPolicyAssociationAccessScopeArgs{
			Type: pulumi.String("cluster"),
		},
		ClusterName:  controlPlane.Name,
		PolicyArn:    pulumi.String("arn:aws:eks::aws:cluster-access-policy/AmazonEKSClusterAdminPolicy"),
		PrincipalArn: accessEntry.PrincipalArn,
	}, pulumi.Parent(accessEntry))
	if err != nil {
		return nil, fmt.Errorf("error creating access policy association: %w", err)
	}

	kc, err := kubeconfig.Generate(name, controlPlane.Endpoint, controlPlane.CertificateAuthorities.Index(pulumi.Int(0)).Data().Elem(), controlPlane.Name)
	if err != nil {
		return nil, fmt.Errorf("error generating kubeconfig: %w", err)
	}

	provider, err := kubernetes.NewProvider(ctx, fmt.Sprintf("%s-k8s-provider", name), &kubernetes.ProviderArgs{
		Kubeconfig:               kc,
		SuppressHelmHookWarnings: pulumi.Bool(true),
	}, pulumi.Parent(controlPlane), pulumi.DependsOn([]pulumi.Resource{controlPlane, accessPolicy}))
	if err != nil {
		return nil, fmt.Errorf("error creating kubernetes provider: %w", err)
	}

	cert := tls.GetCertificateOutput(ctx, tls.GetCertificateOutputArgs{
		Url: controlPlane.Identities.Index(pulumi.Int(0)).Oidcs().Index(pulumi.Int(0)).Issuer().Elem(),
	}, pulumi.Parent(component))

	oidcProvider, err := iam.NewOpenIdConnectProvider(ctx, fmt.Sprintf("%s-oidc-provider", name), &iam.OpenIdConnectProviderArgs{
		ClientIdLists: pulumi.StringArray{
			pulumi.String("sts.amazonaws.com"),
		},
		Url: controlPlane.Identities.Index(pulumi.Int(0)).Oidcs().Index(pulumi.Int(0)).Issuer().Elem(),
		ThumbprintLists: pulumi.StringArray{
			cert.Certificates().Index(pulumi.Int(0)).Sha1Fingerprint(),
		},
		Tags: tags,
	}, pulumi.Parent(controlPlane))
	if err != nil {
		return nil, fmt.Errorf("error creating OIDC provider: %w", err)
	}

	var instanceTypes pulumi.StringArrayInput

	if args.SystemNodeInstanceTypes == nil {
		if err := ctx.Log.Debug("No instance types provided, defaulting to t3.medium", &pulumi.LogArgs{Resource: component}); err != nil {
			return nil, err
		}
		instanceTypes = pulumi.StringArray{
			pulumi.String("t3.medium"),
		}
	} else {
		instanceTypes = *args.SystemNodeInstanceTypes
	}

	var systemNodeMaxCount pulumi.IntInput
	if args.SystemNodeMaxCount == nil {
		if err := ctx.Log.Debug("No max count provided, defaulting to 10", &pulumi.LogArgs{Resource: component}); err != nil {
			return nil, err
		}
		systemNodeMaxCount = pulumi.Int(10)
	} else {
		systemNodeMaxCount = *args.SystemNodeMaxCount
	}

	var systemNodeMinCount pulumi.IntInput
	if args.SystemNodeMinCount == nil {
		if err := ctx.Log.Debug("No min count provided, defaulting to 1", &pulumi.LogArgs{Resource: component}); err != nil {
			return nil, err
		}
		systemNodeMinCount = pulumi.Int(1)
	} else {
		systemNodeMinCount = *args.SystemNodeMinCount
	}

	var systemNodeDesiredCount pulumi.IntInput
	if args.SystemNodeDesiredCount == nil {
		if err := ctx.Log.Debug("No desired count provided, defaulting to 1", &pulumi.LogArgs{Resource: component}); err != nil {
			return nil, err
		}
		systemNodeDesiredCount = pulumi.Int(1)
	} else {
		systemNodeDesiredCount = *args.SystemNodeDesiredCount
	}

	systemNodeLabels := pulumi.StringMap{
		"node.lbrlabs.com/system": pulumi.String("system"),
	}

	taints := eks.NodeGroupTaintArray{
		eks.NodeGroupTaintArgs{
			Effect: pulumi.String("NO_SCHEDULE"),
			Key:    pulumi.String("node.lbrlabs.com/system"),
			Value:  pulumi.String("true"),
		},
	}

	systemNodes, err := NewNodeGroup(ctx, fmt.Sprintf("%s-system", name), &NodeGroupArgs{
		ClusterName:   controlPlane.Name,
		SubnetIds:     args.SystemNodeSubnetIds,
		InstanceTypes: &instanceTypes,
		Labels:        systemNodeLabels,
		Taints:        taints,
		ScalingConfig: eks.NodeGroupScalingConfigArgs{
			MaxSize:     systemNodeMaxCount,
			MinSize:     systemNodeMinCount,
			DesiredSize: systemNodeDesiredCount,
		},
		Tags: &tags,
	}, pulumi.Parent(controlPlane), pulumi.DependsOn([]pulumi.Resource{controlPlane, accessPolicy}), pulumi.ProviderMap(map[string]pulumi.ProviderResource{
		"kubernetes": provider,
	}))
	if err != nil {
		return nil, fmt.Errorf("error creating system nodegroup: %w", err)
	}

	coreDNSConfig, err := json.Marshal(map[string]interface{}{
		"tolerations": []map[string]interface{}{
			{
				"key":      "node.lbrlabs.com/system",
				"operator": "Equal",
				"value":    "true",
				"effect":   "NoSchedule",
			},
		},
	})
	if err != nil {
		return nil, fmt.Errorf("error marshalling coredns config: %w", err)
	}

	_, err = eks.NewAddon(ctx, fmt.Sprintf("%s-coredns", name), &eks.AddonArgs{
		AddonName:                pulumi.String("coredns"),
		ClusterName:              controlPlane.Name,
		ResolveConflictsOnCreate: pulumi.String("OVERWRITE"),
		ResolveConflictsOnUpdate: pulumi.String("PRESERVE"),
		ConfigurationValues:      pulumi.String(coreDNSConfig),
		Tags:                     tags,
	}, pulumi.Parent(controlPlane), pulumi.DependsOn([]pulumi.Resource{systemNodes}))
	if err != nil {
		return nil, fmt.Errorf("error installing coredns: %w", err)
	}

	vpcCsiRole, err := NewIamServiceAccountRole(ctx, fmt.Sprintf("%s-vpc-csi-role", name), &IamServiceAccountRoleArgs{
		OidcProviderArn:    oidcProvider.Arn,
		OidcProviderURL:    oidcProvider.Url,
		NamespaceName:      pulumi.String("kube-system"),
		ServiceAccountName: pulumi.String("aws-node"),
	}, pulumi.Parent(controlPlane))
	if err != nil {
		return nil, fmt.Errorf("error creating iam service account role for VPC CSI: %w", err)
	}

	_, err = iam.NewRolePolicyAttachment(ctx, fmt.Sprintf("%s-vpc-csi-policy", name), &iam.RolePolicyAttachmentArgs{
		Role:      vpcCsiRole.Role.Name,
		PolicyArn: pulumi.String("arn:aws:iam::aws:policy/AmazonEKS_CNI_Policy"),
	}, pulumi.Parent(vpcCsiRole))
	if err != nil {
		return nil, fmt.Errorf("error attaching cni policy to role: %w", err)
	}

	_, err = eks.NewAddon(ctx, fmt.Sprintf("%s-vpc-cni", name), &eks.AddonArgs{
		AddonName:             pulumi.String("vpc-cni"),
		ClusterName:           controlPlane.Name,
		ServiceAccountRoleArn: vpcCsiRole.Role.Arn,
		Tags:                  tags,
	}, pulumi.Parent(vpcCsiRole))
	if err != nil {
		return nil, fmt.Errorf("error installing vpc cni: %w", err)
	}

	ebsCsiRole, err := NewIamServiceAccountRole(ctx, fmt.Sprintf("%s-ebs-csi-role", name), &IamServiceAccountRoleArgs{
		OidcProviderArn:    oidcProvider.Arn,
		OidcProviderURL:    oidcProvider.Url,
		NamespaceName:      pulumi.String("kube-system"),
		ServiceAccountName: pulumi.String("ebs-csi-controller-sa"),
		Tags:               &tags,
	}, pulumi.Parent(controlPlane))
	if err != nil {
		return nil, fmt.Errorf("error creating iam service account role for EBS CSI: %w", err)
	}

	_, err = iam.NewRolePolicyAttachment(ctx, fmt.Sprintf("%s-ebs-csi-policy", name), &iam.RolePolicyAttachmentArgs{
		Role:      ebsCsiRole.Role.Name,
		PolicyArn: pulumi.String("arn:aws:iam::aws:policy/service-role/AmazonEBSCSIDriverPolicy"),
	}, pulumi.Parent(ebsCsiRole))
	if err != nil {
		return nil, fmt.Errorf("error attaching EBS policy to role: %w", err)
	}

	ebsCsiConfig, err := json.Marshal(map[string]interface{}{
		"controller": map[string]interface{}{
			"tolerations": []map[string]interface{}{
				{
					"key":      "node.lbrlabs.com/system",
					"operator": "Equal",
					"value":    "true",
					"effect":   "NoSchedule",
				},
			},
		},
	})
	if err != nil {
		return nil, fmt.Errorf("error marshalling EBS CSI config: %w", err)
	}

	ebsCsiAddon, err := eks.NewAddon(ctx, fmt.Sprintf("%s-ebs-csi", name), &eks.AddonArgs{
		AddonName:             pulumi.String("aws-ebs-csi-driver"),
		ClusterName:           controlPlane.Name,
		ServiceAccountRoleArn: ebsCsiRole.Role.Arn,
		ConfigurationValues:   pulumi.String(ebsCsiConfig),
		Tags:                  tags,
	}, pulumi.Parent(ebsCsiRole), pulumi.DependsOn([]pulumi.Resource{systemNodes}))
	if err != nil {
		return nil, fmt.Errorf("error installing EBS csi: %w", err)
	}

	serverSideProvider, err := kubernetes.NewProvider(ctx, fmt.Sprintf("%s-k8s-ssa-provider", name), &kubernetes.ProviderArgs{
		Kubeconfig:            kc,
		EnableServerSideApply: pulumi.Bool(true),
	}, pulumi.Parent(controlPlane), pulumi.DependsOn([]pulumi.Resource{controlPlane, accessPolicy}))
	if err != nil {
		return nil, fmt.Errorf("error creating server side apply kubernetes provider: %w", err)
	}

	authCrds, err := apiextensionsv1.NewCustomResourceDefinition(ctx, fmt.Sprintf("%s-iam-identity-mapping-crd", name), &apiextensionsv1.CustomResourceDefinitionArgs{
		Metadata: &metav1.ObjectMetaArgs{
			Name: pulumi.String("iamidentitymappings.iamauthenticator.k8s.aws"),
		},
		Spec: apiextensionsv1.CustomResourceDefinitionSpecArgs{
			Group: pulumi.String("iamauthenticator.k8s.aws"),
			Versions: apiextensionsv1.CustomResourceDefinitionVersionArray{
				apiextensionsv1.CustomResourceDefinitionVersionArgs{
					Name:    pulumi.String("v1alpha1"),
					Served:  pulumi.Bool(true),
					Storage: pulumi.Bool(true),
					Schema: apiextensionsv1.CustomResourceValidationArgs{
						OpenAPIV3Schema: apiextensionsv1.JSONSchemaPropsArgs{
							Type: pulumi.String("object"),
							Properties: apiextensionsv1.JSONSchemaPropsMap{
								"spec": apiextensionsv1.JSONSchemaPropsArgs{
									Type: pulumi.String("object"),
									Required: pulumi.StringArray{
										pulumi.String("arn"),
										pulumi.String("username"),
									},
									Properties: apiextensionsv1.JSONSchemaPropsMap{
										"arn": apiextensionsv1.JSONSchemaPropsArgs{
											Type: pulumi.String("string"),
										},
										"username": apiextensionsv1.JSONSchemaPropsArgs{
											Type: pulumi.String("string"),
										},
										"groups": apiextensionsv1.JSONSchemaPropsArgs{
											Type: pulumi.String("array"),
											Items: pulumi.StringMap{
												"type": pulumi.String("string"),
											},
										},
									},
								},
							},
						},
					},
				},
			},
			Scope: pulumi.String("Cluster"),
			Names: apiextensionsv1.CustomResourceDefinitionNamesArgs{
				Plural:   pulumi.String("iamidentitymappings"),
				Singular: pulumi.String("iamidentitymapping"),
				Kind:     pulumi.String("IAMIdentityMapping"),
				Categories: pulumi.StringArray{
					pulumi.String("all"),
				},
			},
		},
	}, pulumi.Parent(controlPlane), pulumi.Provider(provider))
	if err != nil {
		return nil, fmt.Errorf("error creating iam identity mapping crd: %w", err)
	}

	// install the aws-auth operator to handle aws-auth stuff
	_, err = helm.NewRelease(ctx, fmt.Sprintf("%s-aws-auth", name), &helm.ReleaseArgs{
		Chart:     pulumi.String("rustrial-aws-eks-iam-auth-controller"),
		Namespace: pulumi.String("kube-system"),
		Version:   args.EksIamAuthControllerVersion,
		RepositoryOpts: &helm.RepositoryOptsArgs{
			Repo: pulumi.String("https://rustrial.github.io/aws-eks-iam-auth-controller"),
		},
		Values: pulumi.Map{
			"tolerations": pulumi.MapArray{
				pulumi.Map{
					"key":      pulumi.String("node.lbrlabs.com/system"),
					"operator": pulumi.String("Equal"),
					"value":    pulumi.String("true"),
					"effect":   pulumi.String("NoSchedule"),
				},
			},
		},
	}, pulumi.DeletedWith(controlPlane), pulumi.Provider(provider), pulumi.Parent(authCrds), pulumi.DependsOn([]pulumi.Resource{systemNodes, authCrds}))
	if err != nil {
		return nil, fmt.Errorf("error installing aws-auth operator: %w", err)
	}

	// FIXME: this is a workaround for EKS creating a broken default storage class
	// FIXME: what we likely want to do here in future is delete this
	_, err = storagev1.NewStorageClass(ctx, fmt.Sprintf("%s-gp2-storage-class", name), &storagev1.StorageClassArgs{
		Metadata: &metav1.ObjectMetaArgs{
			Name: pulumi.String("gp2"),
			Annotations: pulumi.StringMap{
				"pulumi.com/patchForce":                       pulumi.String("true"),
				"storageclass.kubernetes.io/is-default-class": pulumi.String("false"),
			},
		},
		VolumeBindingMode: pulumi.String("WaitForFirstConsumer"),
		Provisioner:       pulumi.String("kubernetes.io/aws-ebs"),
		ReclaimPolicy:     pulumi.String("Delete"),
	}, pulumi.DeletedWith(controlPlane), pulumi.Parent(serverSideProvider), pulumi.Provider(serverSideProvider))
	if err != nil {
		return nil, fmt.Errorf("error creating gp2 storage class: %w", err)
	}

	_, err = storagev1.NewStorageClass(ctx, fmt.Sprintf("%s-gp3-storage-class", name), &storagev1.StorageClassArgs{
		Metadata: &metav1.ObjectMetaArgs{
			Name: pulumi.String("gp3"),
			Annotations: pulumi.StringMap{
				"storageclass.kubernetes.io/is-default-class": pulumi.String("true"),
			},
		},
		Provisioner:       pulumi.String("ebs.csi.aws.com"),
		VolumeBindingMode: pulumi.String("WaitForFirstConsumer"),
		ReclaimPolicy:     pulumi.String("Delete"),
		Parameters: pulumi.StringMap{
			"csi.storage.k8s.io/fstype": pulumi.String("ext4"),
			"type":                      pulumi.String("gp3"),
		},
	}, pulumi.DeletedWith(controlPlane), pulumi.Parent(provider), pulumi.Provider(provider), pulumi.DeleteBeforeReplace(true))
	if err != nil {
		return nil, fmt.Errorf("error creating gp3 storage class: %w", err)
	}

	var externalAnnotations pulumi.Map

	if args.CertificateArn != nil {
		externalAnnotations = pulumi.Map{
			"service.beta.kubernetes.io/aws-load-balancer-ssl-cert":         *args.CertificateArn,
			"service.beta.kubernetes.io/aws-load-balancer-ssl-ports":        pulumi.String("https"),
			"service.beta.kubernetes.io/aws-load-balancer-backend-protocol": pulumi.String("tcp"),
			"service.beta.kubernetes.io/aws-load-balancer-type":             args.LbType,
		}

		if args.IngressConfig != nil && args.IngressConfig.NlbTargetType != nil {
			externalAnnotations["service.beta.kubernetes.io/aws-load-balancer-nlb-target-type"] = args.IngressConfig.NlbTargetType
		}
	} else {
		externalAnnotations = pulumi.Map{
			"service.beta.kubernetes.io/aws-load-balancer-ssl-ports":        pulumi.String("https"),
			"service.beta.kubernetes.io/aws-load-balancer-backend-protocol": pulumi.String("tcp"),
			"service.beta.kubernetes.io/aws-load-balancer-type":             args.LbType,
		}
		if args.IngressConfig != nil && args.IngressConfig.NlbTargetType != nil {
			externalAnnotations["service.beta.kubernetes.io/aws-load-balancer-nlb-target-type"] = args.IngressConfig.NlbTargetType
		}
		if args.NginxIngressConfig != nil && args.NginxIngressConfig.NlbTargetType != nil {
			externalAnnotations["service.beta.kubernetes.io/aws-load-balancer-nlb-target-type"] = args.NginxIngressConfig.NlbTargetType
		}
	}

	// mergeNginxIngressConfig merges non-nil fields from source into destination.
	// This ensures that zero values (false, 0, "", nil) don't override defaults -
	// only explicitly set values take precedence. This follows Pulumi's principle
	// that unset values should not override configured defaults.
	mergeNginxIngressConfig := func(source, dest *NginxIngressConfig) {
		if source == nil || dest == nil {
			return
		}
		if source.EnableMetrics != nil {
			dest.EnableMetrics = source.EnableMetrics
		}
		if source.EnableServiceMonitor != nil {
			dest.EnableServiceMonitor = source.EnableServiceMonitor
		}
		if source.ServiceMonitorNamespace != nil {
			dest.ServiceMonitorNamespace = source.ServiceMonitorNamespace
		}
		if source.ControllerReplicas != nil {
			dest.ControllerReplicas = source.ControllerReplicas
		}
		if source.AdditionalConfig != nil {
			dest.AdditionalConfig = source.AdditionalConfig
		}
		if source.NlbTargetType != nil {
			dest.NlbTargetType = source.NlbTargetType
		}
		if source.ExtraServiceAnnotations != nil {
			dest.ExtraServiceAnnotations = source.ExtraServiceAnnotations
		}
		if source.AllowSnippetAnnotations != nil {
			dest.AllowSnippetAnnotations = source.AllowSnippetAnnotations
		}
		if source.EnableExternal != nil {
			dest.EnableExternal = source.EnableExternal
		}
		if source.EnableInternal != nil {
			dest.EnableInternal = source.EnableInternal
		}
	}

	// Determine which ingress configuration to use with backward compatibility
	var realisedIngressConfig NginxIngressConfig

	// Start with defaults
	defaultConfig := NginxIngressConfig{
		EnableMetrics:           pulumi.Bool(false),
		EnableServiceMonitor:    pulumi.Bool(false),
		ControllerReplicas:      pulumi.Int(1),
		AllowSnippetAnnotations: pulumi.Bool(false),
		EnableExternal:          pulumi.Bool(true),
		EnableInternal:          pulumi.Bool(true),
	}

	// Apply old IngressConfig if provided (for backward compatibility)
	if args.IngressConfig != nil {
		realisedIngressConfig = NginxIngressConfig{
			EnableMetrics:           args.IngressConfig.EnableMetrics,
			EnableServiceMonitor:    args.IngressConfig.EnableServiceMonitor,
			ServiceMonitorNamespace: args.IngressConfig.ServiceMonitorNamespace,
			ControllerReplicas:      args.IngressConfig.ControllerReplicas,
			AdditionalConfig:        args.IngressConfig.AdditionalConfig,
			NlbTargetType:           args.IngressConfig.NlbTargetType,
			ExtraServiceAnnotations: args.IngressConfig.ExtraServiceAnnotations,
			AllowSnippetAnnotations: args.IngressConfig.AllowSnippetAnnotations,
			EnableExternal:          args.IngressConfig.EnableExternal,
			EnableInternal:          args.IngressConfig.EnableInternal,
		}
	} else {
		realisedIngressConfig = defaultConfig
	}

	// Merge with new NginxIngressConfig if provided (takes precedence for explicitly set fields)
	// Note: Only non-nil values override defaults to preserve backward compatibility
	mergeNginxIngressConfig(args.NginxIngressConfig, &realisedIngressConfig)

	if args.EnableExternalIngress {
		// Check realisedIngressConfig.EnableExternal to allow controlling this via IngressConfig/NginxIngressConfig
		enableExternal := realisedIngressConfig.EnableExternal
		if enableExternal == nil {
			enableExternal = pulumi.Bool(true)
		}

		// Convert to output for conditional logic
		enableExternalOutput := enableExternal.ToBoolPtrOutput()

		// Use ApplyT on the output to conditionally create the nginx ingress external chart
		nginxIngressExternal := enableExternalOutput.ApplyT(func(enabled *bool) (interface{}, error) {
			if enabled != nil && *enabled {
				chart, err := helm.NewChart(ctx, fmt.Sprintf("%s-nginx-ext", name), helm.ChartArgs{
					Chart:     pulumi.String("ingress-nginx"),
					Namespace: pulumi.String("kube-system"),
					Version:   args.NginxIngressVersion,

					FetchArgs: &helm.FetchArgs{
						Repo: pulumi.String("https://kubernetes.github.io/ingress-nginx"),
					},
					Values: pulumi.Map{
						"controller": pulumi.Map{
							"allowSnippetAnnotations": realisedIngressConfig.AllowSnippetAnnotations,
							"image": pulumi.Map{
								"registry": args.NginxIngressRegistry,
								"tag":      args.NginxIngressTag,
							},
							"metrics": pulumi.Map{
								"enabled": realisedIngressConfig.EnableMetrics,
								"serviceMonitor": pulumi.Map{
									"enabled":   realisedIngressConfig.EnableServiceMonitor,
									"namespace": realisedIngressConfig.ServiceMonitorNamespace,
								},
							},
							"config":       realisedIngressConfig.AdditionalConfig,
							"replicaCount": realisedIngressConfig.ControllerReplicas,
							"admissionWebhooks": pulumi.Map{
								"patch": pulumi.Map{
									"image": pulumi.Map{
										"registry": args.NginxIngressRegistry,
									},
									"tolerations": pulumi.MapArray{
										pulumi.Map{
											"key":      pulumi.String("node.lbrlabs.com/system"),
											"operator": pulumi.String("Equal"),
											"value":    pulumi.String("true"),
											"effect":   pulumi.String("NoSchedule"),
										},
									},
								},
							},
							"tolerations": pulumi.MapArray{
								pulumi.Map{
									"key":      pulumi.String("node.lbrlabs.com/system"),
									"operator": pulumi.String("Equal"),
									"value":    pulumi.String("true"),
									"effect":   pulumi.String("NoSchedule"),
								},
							},
							"ingressClassResource": pulumi.Map{
								"name":            pulumi.String("external"),
								"default":         pulumi.Bool(true),
								"controllerValue": pulumi.String("k8s.io/ingress-nginx/external"),
							},
							"ingressClass": pulumi.String("external"),
							"service": pulumi.Map{
								"annotations": externalAnnotations,
							},
						},
						"defaultBackend": pulumi.Map{
							"image": pulumi.Map{
								"registry": args.NginxIngressRegistry,
								"tag":      args.NginxIngressTag,
							},
							"tolerations": pulumi.MapArray{
								pulumi.Map{
									"key":      pulumi.String("node.lbrlabs.com/system"),
									"operator": pulumi.String("Equal"),
									"value":    pulumi.String("true"),
									"effect":   pulumi.String("NoSchedule"),
								},
							},
						},
					},
				}, pulumi.Parent(controlPlane), pulumi.Provider(provider), pulumi.DependsOn([]pulumi.Resource{systemNodes, controlPlane, ebsCsiAddon}))
				if err != nil {
					return nil, fmt.Errorf("error installing nginx ingress helm release: %w", err)
				}
				return chart, nil
			}
			return nil, nil // Return nil when disabled
		})

		_ = nginxIngressExternal
	}

	if args.EnableInternalIngress {
		// Check realisedIngressConfig.EnableInternal to allow controlling this via IngressConfig/NginxIngressConfig
		enableInternal := realisedIngressConfig.EnableInternal
		if enableInternal == nil {
			enableInternal = pulumi.Bool(true)
		}

		// Convert to output for conditional logic
		enableInternalOutput := enableInternal.ToBoolPtrOutput()

		// Use ApplyT on the output to conditionally create the nginx ingress internal chart
		nginxIngressInternal := enableInternalOutput.ApplyT(func(enabled *bool) (interface{}, error) {
			if enabled != nil && *enabled {
				var internalAnnotations pulumi.Map

				if args.CertificateArn != nil {
					internalAnnotations = pulumi.Map{
						"service.beta.kubernetes.io/aws-load-balancer-ssl-cert":         *args.CertificateArn,
						"service.beta.kubernetes.io/aws-load-balancer-ssl-ports":        pulumi.String("https"),
						"service.beta.kubernetes.io/aws-load-balancer-internal":         pulumi.Bool(true),
						"service.beta.kubernetes.io/aws-load-balancer-backend-protocol": pulumi.String("tcp"),
						"service.beta.kubernetes.io/aws-load-balancer-type":             args.LbType,
					}

					if args.IngressConfig != nil && args.IngressConfig.NlbTargetType != nil {
						internalAnnotations["service.beta.kubernetes.io/aws-load-balancer-nlb-target-type"] = args.IngressConfig.NlbTargetType
					}
					if args.NginxIngressConfig != nil && args.NginxIngressConfig.NlbTargetType != nil {
						internalAnnotations["service.beta.kubernetes.io/aws-load-balancer-nlb-target-type"] = args.NginxIngressConfig.NlbTargetType
					}
				} else {
					internalAnnotations = pulumi.Map{
						"service.beta.kubernetes.io/aws-load-balancer-ssl-ports":        pulumi.String("https"),
						"service.beta.kubernetes.io/aws-load-balancer-internal":         pulumi.Bool(true),
						"service.beta.kubernetes.io/aws-load-balancer-backend-protocol": pulumi.String("tcp"),
						"service.beta.kubernetes.io/aws-load-balancer-type":             args.LbType,
					}
					if args.IngressConfig != nil && args.IngressConfig.NlbTargetType != nil {
						internalAnnotations["service.beta.kubernetes.io/aws-load-balancer-nlb-target-type"] = args.IngressConfig.NlbTargetType
					}
					if args.NginxIngressConfig != nil && args.NginxIngressConfig.NlbTargetType != nil {
						internalAnnotations["service.beta.kubernetes.io/aws-load-balancer-nlb-target-type"] = args.NginxIngressConfig.NlbTargetType
					}
				}

				chart, err := helm.NewChart(ctx, fmt.Sprintf("%s-nginx-int", name), helm.ChartArgs{
					Chart:     pulumi.String("ingress-nginx"),
					Namespace: pulumi.String("kube-system"),
					Version:   args.NginxIngressVersion,
					FetchArgs: &helm.FetchArgs{
						Repo: pulumi.String("https://kubernetes.github.io/ingress-nginx"),
					},
					Values: pulumi.Map{
						"controller": pulumi.Map{
							"allowSnippetAnnotations": realisedIngressConfig.AllowSnippetAnnotations,
							"image": pulumi.Map{
								"registry": args.NginxIngressRegistry,
								"tag":      args.NginxIngressTag,
							},
							"replicaCount": realisedIngressConfig.ControllerReplicas,
							"metrics": pulumi.Map{
								"enabled": realisedIngressConfig.EnableMetrics,
								"serviceMonitor": pulumi.Map{
									"enabled":   realisedIngressConfig.EnableServiceMonitor,
									"namespace": realisedIngressConfig.ServiceMonitorNamespace,
								},
							},
							"config": realisedIngressConfig.AdditionalConfig,
							"admissionWebhooks": pulumi.Map{
								"patch": pulumi.Map{
									"tolerations": pulumi.MapArray{
										pulumi.Map{
											"key":      pulumi.String("node.lbrlabs.com/system"),
											"operator": pulumi.String("Equal"),
											"value":    pulumi.String("true"),
											"effect":   pulumi.String("NoSchedule"),
										},
									},
								},
							},
							"tolerations": pulumi.MapArray{
								pulumi.Map{
									"key":      pulumi.String("node.lbrlabs.com/system"),
									"operator": pulumi.String("Equal"),
									"value":    pulumi.String("true"),
									"effect":   pulumi.String("NoSchedule"),
								},
							},
							"ingressClassResource": pulumi.Map{
								"name":            pulumi.String("internal"),
								"default":         pulumi.Bool(true),
								"controllerValue": pulumi.String("k8s.io/ingress-nginx/internal"),
							},
							"ingressClass": pulumi.String("internal"),
							"service": pulumi.Map{
								"annotations": internalAnnotations,
							},
						},
						"defaultBackend": pulumi.Map{
							"image": pulumi.Map{
								"registry": args.NginxIngressRegistry,
								"tag":      args.NginxIngressTag,
							},
							"tolerations": pulumi.MapArray{
								pulumi.Map{
									"key":      pulumi.String("node.lbrlabs.com/system"),
									"operator": pulumi.String("Equal"),
									"value":    pulumi.String("true"),
									"effect":   pulumi.String("NoSchedule"),
								},
							},
						},
					},
				}, pulumi.Parent(controlPlane), pulumi.Provider(provider), pulumi.DependsOn([]pulumi.Resource{systemNodes, controlPlane, ebsCsiAddon}))
				if err != nil {
					return nil, fmt.Errorf("error installing nginx ingress helm release: %w", err)
				}
				return chart, nil
			}
			return nil, nil // Return nil when disabled
		})

		_ = nginxIngressInternal
	}

	if args.EnableExternalDNS {
		externalDNSRole, err := NewIamServiceAccountRole(ctx, fmt.Sprintf("%s-external-dns-role", name), &IamServiceAccountRoleArgs{
			OidcProviderArn:    oidcProvider.Arn,
			OidcProviderURL:    oidcProvider.Url,
			NamespaceName:      pulumi.String("kube-system"),
			ServiceAccountName: pulumi.String("external-dns"),
			Tags:               &tags,
		}, pulumi.Parent(controlPlane))
		if err != nil {
			return nil, fmt.Errorf("error creating iam service account role for external dns: %w", err)
		}

		externalDNSPolicyDocument := iam.GetPolicyDocumentOutput(ctx, iam.GetPolicyDocumentOutputArgs{
			Statements: iam.GetPolicyDocumentStatementArray{
				iam.GetPolicyDocumentStatementArgs{
					Sid: pulumi.String("AllowAccessToRoute53HostedZones"),
					Actions: pulumi.StringArray{
						pulumi.String("route53:ChangeResourceRecordSets"),
					},
					Effect: pulumi.String("Allow"),
					Resources: pulumi.StringArray{
						pulumi.String("arn:aws:route53:::hostedzone/*"),
					},
				},
				iam.GetPolicyDocumentStatementArgs{
					Sid: pulumi.String("AllowAccessToRoute53RecordSets"),
					Actions: pulumi.StringArray{
						pulumi.String("route53:ListHostedZones"),
						pulumi.String("route53:ListResourceRecordSets"),
					},
					Effect: pulumi.String("Allow"),
					Resources: pulumi.StringArray{
						pulumi.String("*"),
					},
				},
			},
		})

		externalDNSPolicy, err := iam.NewPolicy(ctx, fmt.Sprintf("%s-external-dns-policy", name), &iam.PolicyArgs{
			Description: pulumi.String("Policy for external-dns to modify route53 "),
			Policy:      externalDNSPolicyDocument.Json(),
			Tags:        tags,
		}, pulumi.Parent(role))
		if err != nil {
			return nil, fmt.Errorf("error creating external DNS policy: %w", err)
		}

		_, err = iam.NewRolePolicyAttachment(ctx, fmt.Sprintf("%s-cluster-external-dns-policy-attachment", name), &iam.RolePolicyAttachmentArgs{
			Role:      externalDNSRole.Role.Name,
			PolicyArn: externalDNSPolicy.Arn,
		}, pulumi.Parent(externalDNSRole.Role))
		if err != nil {
			return nil, fmt.Errorf("error attaching cluster policy for external dns: %w", err)
		}

		externalDNSServiceAccount, err := corev1.NewServiceAccount(ctx, fmt.Sprintf("%s-external-dns-service-account", name), &corev1.ServiceAccountArgs{
			Metadata: &metav1.ObjectMetaArgs{
				Name:      pulumi.String("external-dns"),
				Namespace: pulumi.String("kube-system"),
				Annotations: pulumi.StringMap{
					"eks.amazonaws.com/role-arn": externalDNSRole.Role.Arn,
				},
			},
		}, pulumi.DeletedWith(controlPlane), pulumi.Parent(externalDNSRole), pulumi.Provider(provider))
		if err != nil {
			return nil, fmt.Errorf("error creating external dns service account: %w", err)
		}

		externalDNS, err := helm.NewRelease(ctx, fmt.Sprintf("%s-external-dns", name), &helm.ReleaseArgs{
			Chart:     pulumi.String("external-dns"),
			Namespace: pulumi.String("kube-system"),
			Version:   args.ExternalDNSVersion,
			Timeout:   pulumi.Int(600),
			RepositoryOpts: &helm.RepositoryOptsArgs{
				Repo: pulumi.String("https://kubernetes-sigs.github.io/external-dns/"),
			},
			Values: pulumi.Map{
				"serviceAccount": pulumi.Map{
					"create": pulumi.Bool(false),
					"name":   externalDNSServiceAccount.Metadata.Name(),
				},
				"tolerations": pulumi.MapArray{
					pulumi.Map{
						"key":      pulumi.String("node.lbrlabs.com/system"),
						"operator": pulumi.String("Equal"),
						"value":    pulumi.String("true"),
						"effect":   pulumi.String("NoSchedule"),
					},
				},
			},
		}, pulumi.DeletedWith(controlPlane), pulumi.Parent(externalDNSServiceAccount), pulumi.Provider(provider), pulumi.DependsOn([]pulumi.Resource{systemNodes}))
		if err != nil {
			return nil, fmt.Errorf("error installing external dns helm release: %w", err)
		}

		_ = externalDNS
	}

	if args.EnableCertManager {

		certManagerRole, err := NewIamServiceAccountRole(ctx, fmt.Sprintf("%s-cert-manager-role", name), &IamServiceAccountRoleArgs{
			OidcProviderArn:    oidcProvider.Arn,
			OidcProviderURL:    oidcProvider.Url,
			NamespaceName:      pulumi.String("kube-system"),
			ServiceAccountName: pulumi.String("cert-manager"),
			Tags:               &tags,
		}, pulumi.Parent(controlPlane))
		if err != nil {
			return nil, fmt.Errorf("error creating iam service account role for cert manager: %w", err)
		}

		certManagerPolicyDocument := iam.GetPolicyDocumentOutput(ctx, iam.GetPolicyDocumentOutputArgs{
			Statements: iam.GetPolicyDocumentStatementArray{
				iam.GetPolicyDocumentStatementArgs{
					Sid: pulumi.String("AllowAccessToRoute53Changess"),
					Actions: pulumi.StringArray{
						pulumi.String("route53:GetChange"),
					},
					Effect: pulumi.String("Allow"),
					Resources: pulumi.StringArray{
						pulumi.String("arn:aws:route53:::change/*"),
					},
				},
				iam.GetPolicyDocumentStatementArgs{
					Sid: pulumi.String("AllowAccessToRoute53HostedZones"),
					Actions: pulumi.StringArray{
						pulumi.String("route53:ChangeResourceRecordSets"),
						pulumi.String("route53:ListResourceRecordSets"),
					},
					Effect: pulumi.String("Allow"),
					Resources: pulumi.StringArray{
						pulumi.String("arn:aws:route53:::hostedzone/*"),
					},
				},
				iam.GetPolicyDocumentStatementArgs{
					Sid: pulumi.String("AllowListingHostedZones"),
					Actions: pulumi.StringArray{
						pulumi.String("route53:ListHostedZonesByName"),
					},
					Effect: pulumi.String("Allow"),
					Resources: pulumi.StringArray{
						pulumi.String("*"),
					},
				},
			},
		})

		certManagerPolicy, err := iam.NewPolicy(ctx, fmt.Sprintf("%s-cert-manager-policy", name), &iam.PolicyArgs{
			Description: pulumi.String("Policy for cert-manager to modify route53 "),
			Policy:      certManagerPolicyDocument.Json(),
			Tags:        tags,
		}, pulumi.Parent(role))
		if err != nil {
			return nil, fmt.Errorf("error creating cert manager DNS policy: %w", err)
		}

		_, err = iam.NewRolePolicyAttachment(ctx, fmt.Sprintf("%s-cluster-cert-manager-policy-attachment", name), &iam.RolePolicyAttachmentArgs{
			Role:      certManagerRole.Role.Name,
			PolicyArn: certManagerPolicy.Arn,
		}, pulumi.Parent(certManagerPolicy))
		if err != nil {
			return nil, fmt.Errorf("error attaching cluster policy for cert manager: %w", err)
		}

		certManagerServiceAccount, err := corev1.NewServiceAccount(ctx, fmt.Sprintf("%s-cert-manager-service-account", name), &corev1.ServiceAccountArgs{
			Metadata: &metav1.ObjectMetaArgs{
				Name:      pulumi.String("cert-manager"),
				Namespace: pulumi.String("kube-system"),
				Annotations: pulumi.StringMap{
					"eks.amazonaws.com/role-arn": certManagerRole.Role.Arn,
				},
			},
		}, pulumi.Parent(certManagerRole), pulumi.Provider(provider))
		if err != nil {
			return nil, fmt.Errorf("error creating cert manager service account: %w", err)
		}

		certManagerCrds, err := yaml.NewConfigFile(ctx, fmt.Sprintf("%s-cert-manager-crds", name), &yaml.ConfigFileArgs{
			File: "https://github.com/cert-manager/cert-manager/releases/download/v1.12.2/cert-manager.crds.yaml",
		}, pulumi.DeletedWith(controlPlane), pulumi.Parent(provider), pulumi.Provider(provider))
		if err != nil {
			return nil, fmt.Errorf("error creating cert manager crds: %w", err)
		}

		certManager, err := helm.NewRelease(ctx, fmt.Sprintf("%s-cert-manager", name), &helm.ReleaseArgs{
			Chart:           pulumi.String("cert-manager"),
			Namespace:       pulumi.String("kube-system"),
			DisableCRDHooks: pulumi.Bool(true),
			Version:         args.CertManagerVersion,
			SkipAwait:       pulumi.Bool(true), // FIXME: this is a very unreliable chart
			Timeout:         pulumi.Int(600),
			RepositoryOpts: &helm.RepositoryOptsArgs{
				Repo: pulumi.String("https://charts.jetstack.io"),
			},
			Values: pulumi.Map{
				"serviceAccount": pulumi.Map{
					"create": pulumi.Bool(false),
					"name":   certManagerServiceAccount.Metadata.Name(),
				},
				"securityContext": pulumi.Map{
					"fsGroup": pulumi.Int(1001),
				},
				"tolerations": pulumi.MapArray{
					pulumi.Map{
						"key":      pulumi.String("node.lbrlabs.com/system"),
						"operator": pulumi.String("Equal"),
						"value":    pulumi.String("true"),
						"effect":   pulumi.String("NoSchedule"),
					},
				},
				"startupapicheck": pulumi.Map{
					"tolerations": pulumi.MapArray{
						pulumi.Map{
							"key":      pulumi.String("node.lbrlabs.com/system"),
							"operator": pulumi.String("Equal"),
							"value":    pulumi.String("true"),
							"effect":   pulumi.String("NoSchedule"),
						},
					},
				},
				"webhook": pulumi.Map{
					"tolerations": pulumi.MapArray{
						pulumi.Map{
							"key":      pulumi.String("node.lbrlabs.com/system"),
							"operator": pulumi.String("Equal"),
							"value":    pulumi.String("true"),
							"effect":   pulumi.String("NoSchedule"),
						},
					},
				},
				"cainjector": pulumi.Map{
					"tolerations": pulumi.MapArray{
						pulumi.Map{
							"key":      pulumi.String("node.lbrlabs.com/system"),
							"operator": pulumi.String("Equal"),
							"value":    pulumi.String("true"),
							"effect":   pulumi.String("NoSchedule"),
						},
					},
				},
			},
		}, pulumi.DeletedWith(controlPlane), pulumi.Parent(provider), pulumi.Provider(provider), pulumi.DependsOn([]pulumi.Resource{systemNodes, certManagerCrds}))
		if err != nil {
			return nil, fmt.Errorf("error installing cert manager helm release: %w", err)
		}

		_ = certManager

		if args.LetsEncryptEmail == "" {

			err = ctx.Log.Info("No LetsEncrypt email provided, skipping cluster issuer creation", &pulumi.LogArgs{Resource: component})
			if err != nil {
				return nil, fmt.Errorf("error logging: %w", err)
			}

		} else {

			clusterIssuer, err := apiextensions.NewCustomResource(ctx, fmt.Sprintf("%s-cluster-issuer", name), &apiextensions.CustomResourceArgs{
				ApiVersion: pulumi.String("cert-manager.io/v1"),
				Kind:       pulumi.String("ClusterIssuer"),
				Metadata: &metav1.ObjectMetaArgs{
					Name: pulumi.String("letsencrypt-prod"),
				},
				OtherFields: map[string]interface{}{
					"spec": map[string]interface{}{
						"acme": map[string]interface{}{
							"email":  args.LetsEncryptEmail,
							"server": pulumi.String("https://acme-v02.api.letsencrypt.org/directory"),
							"privateKeySecretRef": map[string]interface{}{
								"name": pulumi.String("letsencrypt"),
							},
							"solvers": []interface{}{
								map[string]interface{}{
									"dns01": map[string]interface{}{
										"route53": map[string]interface{}{
											"region": pulumi.String(region.Name),
										},
									},
								},
							},
						},
					},
				},
			}, pulumi.DeletedWith(controlPlane), pulumi.Parent(certManager), pulumi.Provider(provider), pulumi.DeleteBeforeReplace(true))
			if err != nil {
				return nil, fmt.Errorf("error installing cluster issuer: %w", err)
			}

			_ = clusterIssuer
		}
	}

	if args.EnableCloudWatchAgent {

		cloudwatchRole, err := NewIamServiceAccountRole(ctx, fmt.Sprintf("%s-cw-obs-role", name), &IamServiceAccountRoleArgs{
			OidcProviderArn:    oidcProvider.Arn,
			OidcProviderURL:    oidcProvider.Url,
			NamespaceName:      pulumi.String("amazon-cloudwatch"),
			ServiceAccountName: pulumi.String("cloudwatch-agent"),
			Tags:               &tags,
		}, pulumi.Parent(controlPlane))
		if err != nil {
			return nil, fmt.Errorf("error creating iam service account role for EBS CSI: %w", err)
		}

		_, err = iam.NewRolePolicyAttachment(ctx, fmt.Sprintf("%s-cw-obs-policy", name), &iam.RolePolicyAttachmentArgs{
			Role:      cloudwatchRole.Role.Name,
			PolicyArn: pulumi.String("arn:aws:iam::aws:policy/CloudWatchAgentServerPolicy"),
		}, pulumi.Parent(cloudwatchRole.Role))
		if err != nil {
			return nil, fmt.Errorf("error attaching cloudwatch agent policy to role: %w", err)
		}

		_, err = iam.NewRolePolicyAttachment(ctx, fmt.Sprintf("%s-cw-xray-policy", name), &iam.RolePolicyAttachmentArgs{
			Role:      cloudwatchRole.Role.Name,
			PolicyArn: pulumi.String("arn:aws:iam::aws:policy/AWSXrayWriteOnlyAccess"),
		}, pulumi.Parent(cloudwatchRole.Role))
		if err != nil {
			return nil, fmt.Errorf("error attaching cloudwatch agent policy to role: %w", err)
		}

		ebsPolicyJSON, err := json.Marshal(map[string]interface{}{
			"Version": "2012-10-17",
			"Statement": []map[string]interface{}{
				{
					"Action": []string{
						"ec2:DescribeVolumes",
					},
					"Effect":   "Allow",
					"Resource": "*",
				},
			},
		})
		if err != nil {
			return nil, fmt.Errorf("error marshalling EBS policy json: %w", err)
		}

		ebsPolicy, err := iam.NewPolicy(ctx, fmt.Sprintf("%s-cw-ebs-policy", name), &iam.PolicyArgs{
			Description: pulumi.String("Policy for EBS metrics"),
			Policy:      pulumi.String(ebsPolicyJSON),
			Tags:        tags,
		}, pulumi.Parent(cloudwatchRole.Role))
		if err != nil {
			return nil, fmt.Errorf("error creating EBS policy: %w", err)
		}

		_, err = iam.NewRolePolicyAttachment(ctx, fmt.Sprintf("%s-cw-ebs-policy", name), &iam.RolePolicyAttachmentArgs{
			Role:      cloudwatchRole.Role.Name,
			PolicyArn: ebsPolicy.Arn,
		}, pulumi.Parent(ebsPolicy))
		if err != nil {
			return nil, fmt.Errorf("error attaching EBS policy to role: %w", err)
		}

		_, err = eks.NewAddon(ctx, fmt.Sprintf("%s-cloudwatch-observability", name), &eks.AddonArgs{
			AddonName:             pulumi.String("amazon-cloudwatch-observability"),
			ClusterName:           controlPlane.Name,
			ServiceAccountRoleArn: cloudwatchRole.Role.Arn,
			Tags:                  tags,
		}, pulumi.Parent(controlPlane))
		if err != nil {
			return nil, fmt.Errorf("error installing Cloudwatch observability addon: %w", err)
		}

	}

	if args.EnableOtel {

		if !args.EnableCertManager {
			if err := ctx.Log.Error("Cert Manager must be installed for telemetry to execute successfully.", &pulumi.LogArgs{Resource: component}); err != nil {
				return nil, fmt.Errorf("error logging: %w", err)
			}
		}

		otelConfig, err := json.Marshal(map[string]interface{}{
			"tolerations": []map[string]interface{}{
				{
					"key":      "node.lbrlabs.com/system",
					"operator": "Equal",
					"value":    "true",
					"effect":   "NoSchedule",
				},
			},
		})
		if err != nil {
			return nil, fmt.Errorf("error marshalling Otel config: %w", err)
		}

		_, err = eks.NewAddon(ctx, fmt.Sprintf("%s-otel", name), &eks.AddonArgs{
			AddonName:           pulumi.String("adot"),
			ClusterName:         controlPlane.Name,
			ConfigurationValues: pulumi.String(otelConfig),
			Tags:                tags,
		}, pulumi.Parent(controlPlane))

		if err != nil {
			return nil, fmt.Errorf("error installing otel addon: %w", err)
		}
	}

	var karpenterRole *IamServiceAccountRole
	var karpenterNodeRole *iam.Role

	if args.EnableKarpenter {

		// create a spot termination queue
		queue, err := sqs.NewQueue(ctx, fmt.Sprintf("%s-karpenter-spot", name), &sqs.QueueArgs{
			MessageRetentionSeconds: pulumi.Int(300),
			SqsManagedSseEnabled:    pulumi.Bool(true),
			Tags:                    tags,
		}, pulumi.Parent(component))
		if err != nil {
			return nil, fmt.Errorf("error creating spot termination queue: %w", err)
		}

		component.KarpenterQueueName = queue.Name.ToStringPtrOutput()

		// add a queue policy
		// FIXME: make this strongly typed instead of using interfaces
		queuePolicy := iam.GetPolicyDocumentOutput(ctx, iam.GetPolicyDocumentOutputArgs{
			Statements: iam.GetPolicyDocumentStatementArray{
				iam.GetPolicyDocumentStatementArgs{
					Actions: pulumi.StringArray{
						pulumi.String("sqs:SendMessage"),
					},
					Resources: pulumi.StringArray{
						queue.Arn,
					},
					Principals: iam.GetPolicyDocumentStatementPrincipalArray{
						iam.GetPolicyDocumentStatementPrincipalArgs{
							Type: pulumi.String("Service"),
							Identifiers: pulumi.StringArray{
								pulumi.String("events.amazonaws.com"),
								pulumi.String("sqs.amazonaws.com"),
							},
						},
					},
				},
			},
		}, pulumi.Parent(queue))

		_, err = sqs.NewQueuePolicy(ctx, fmt.Sprintf("%s-karpenter-spot-policy", name), &sqs.QueuePolicyArgs{
			QueueUrl: queue.Url,
			Policy:   queuePolicy.Json(),
		}, pulumi.Parent(queue))
		if err != nil {
			return nil, fmt.Errorf("error creating spot termination queue policy: %w", err)
		}

		events := map[string]Event{
			fmt.Sprintf("%-s-health-event", name): {
				Name:        "HealthEvent",
				Description: "Karpenter interrupt - AWS health event",
				EventPattern: map[string][]string{
					"source":      {"aws.health"},
					"detail-type": {"AWS Health Event"},
				},
			},
			fmt.Sprintf("%s-spot-interrupt", name): {
				Name:        "SpotInterrupt",
				Description: "Karpenter interrupt - EC2 spot instance interruption warning",
				EventPattern: map[string][]string{
					"source":      {"aws.ec2"},
					"detail-type": {"EC2 Spot Instance Interruption Warning"},
				},
			},
			fmt.Sprintf("%s-instance-rebalance", name): {
				Name:        "InstanceRebalance",
				Description: "Karpenter interrupt - EC2 instance rebalance recommendation",
				EventPattern: map[string][]string{
					"source":      {"aws.ec2"},
					"detail-type": {"EC2 Instance Rebalance Recommendation"},
				},
			},
			fmt.Sprintf("%s-instance-state-change", name): {
				Name:        "InstanceStateChange",
				Description: "Karpenter interrupt - EC2 instance state-change notification",
				EventPattern: map[string][]string{
					"source":      {"aws.ec2"},
					"detail-type": {"EC2 Instance State-change Notification"},
				},
			},
		}

		for key, event := range events {
			eventPatternJSON, err := json.Marshal(event.EventPattern)
			if err != nil {
				return nil, fmt.Errorf("error marshalling event pattern json: %w", err)
			}

			eventRule, err := cloudwatch.NewEventRule(ctx, fmt.Sprintf("%s-rule", key), &cloudwatch.EventRuleArgs{
				Description:  pulumi.String(event.Description),
				EventPattern: pulumi.String(string(eventPatternJSON)),
				Tags:         tags,
			}, pulumi.Parent(queue))
			if err != nil {
				return nil, fmt.Errorf("error creating event rule: %w", err)
			}

			_, err = cloudwatch.NewEventTarget(ctx, key, &cloudwatch.EventTargetArgs{
				Rule:     eventRule.Name,
				TargetId: pulumi.String("KarpenterInterruptionQueueTarget"),
				Arn:      queue.Arn,
			}, pulumi.Parent(queue))
			if err != nil {
				return nil, fmt.Errorf("error creating event target: %w", err)
			}
		}

		// create a karpenter role
		serviceAccount, err := corev1.NewServiceAccount(ctx, fmt.Sprintf("%s-karpenter", name), &corev1.ServiceAccountArgs{
			Metadata: &metav1.ObjectMetaArgs{
				Namespace: pulumi.String("kube-system"),
			},
		}, pulumi.Parent(controlPlane), pulumi.Provider(provider))
		if err != nil {
			return nil, fmt.Errorf("error creating karpenter service account: %w", err)
		}

		karpenterRole, err = NewIamServiceAccountRole(ctx, fmt.Sprintf("%s-karpenter-role", name), &IamServiceAccountRoleArgs{
			OidcProviderArn:    oidcProvider.Arn,
			OidcProviderURL:    oidcProvider.Url,
			NamespaceName:      pulumi.String("kube-system"),
			ServiceAccountName: serviceAccount.Metadata.Name().Elem(),
			Tags:               &tags,
		}, pulumi.Parent(controlPlane))
		if err != nil {
			return nil, fmt.Errorf("error creating iam service account role for karpenter: %w", err)
		}

		karpenterServiceAccountAnnotations, err := corev1.NewServiceAccountPatch(ctx, fmt.Sprintf("%s-karpenter-patch", name), &corev1.ServiceAccountPatchArgs{
			Metadata: &metav1.ObjectMetaPatchArgs{
				Namespace: serviceAccount.Metadata.Namespace(),
				Name:      serviceAccount.Metadata.Name(),
				Annotations: pulumi.StringMap{
					"eks.amazonaws.com/role-arn": karpenterRole.Role.Arn,
				},
			},
		}, pulumi.Parent(serviceAccount), pulumi.Provider(provider))
		if err != nil {
			return nil, fmt.Errorf("error patching karpenter service account: %w", err)
		}

		karpenterPolicyDoc := iam.GetPolicyDocumentOutput(ctx, iam.GetPolicyDocumentOutputArgs{
			Statements: iam.GetPolicyDocumentStatementArray{
				iam.GetPolicyDocumentStatementArgs{
					Sid:    pulumi.String("AllowScopedEC2InstanceActions"),
					Effect: pulumi.String("Allow"),
					Actions: pulumi.StringArray{
						pulumi.String("ec2:RunInstances"),
						pulumi.String("ec2:CreateFleet"),
					},
					Resources: pulumi.StringArray{
						pulumi.Sprintf("arn:%s:ec2:%s:*:image/*", current.Partition, region.Name),
						pulumi.Sprintf("arn:%s:ec2:%s:*:snapshot/*", current.Partition, region.Name),
						pulumi.Sprintf("arn:%s:ec2:%s:*:spot-instances-request/*", current.Partition, region.Name),
						pulumi.Sprintf("arn:%s:ec2:%s:*:security-group/*", current.Partition, region.Name),
						pulumi.Sprintf("arn:%s:ec2:%s:*:subnet/*", current.Partition, region.Name),
						pulumi.Sprintf("arn:%s:ec2:%s:*:launch-template/*", current.Partition, region.Name),
					},
				},
				iam.GetPolicyDocumentStatementArgs{
					Sid:    pulumi.String("AllowScopedEC2InstanceActionsWithTags"),
					Effect: pulumi.String("Allow"),
					Actions: pulumi.StringArray{
						pulumi.String("ec2:RunInstances"),
						pulumi.String("ec2:CreateFleet"),
						pulumi.String("ec2:CreateLaunchTemplate"),
						pulumi.String("ec2:CreateTags"),
					},
					Resources: pulumi.StringArray{
						pulumi.Sprintf("arn:%s:ec2:%s:*:fleet/*", current.Partition, region.Name),
						pulumi.Sprintf("arn:%s:ec2:%s:*:instance/*", current.Partition, region.Name),
						pulumi.Sprintf("arn:%s:ec2:%s:*:volume/*", current.Partition, region.Name),
						pulumi.Sprintf("arn:%s:ec2:%s:*:network-interface/*", current.Partition, region.Name),
						pulumi.Sprintf("arn:%s:ec2:%s:*:launch-template/*", current.Partition, region.Name),
						pulumi.Sprintf("arn:%s:ec2:%s:*:spot-instances-request/*", current.Partition, region.Name),
					},
				},
				iam.GetPolicyDocumentStatementArgs{
					Sid:    pulumi.String("AllowScopedDeletion"),
					Effect: pulumi.String("Allow"),
					Actions: pulumi.StringArray{
						pulumi.String("ec2:TerminateInstances"),
						pulumi.String("ec2:DeleteLaunchTemplate"),
					},
					Resources: pulumi.StringArray{
						pulumi.Sprintf("arn:%s:ec2:%s:*:instance/*", current.Partition, region.Name),
						pulumi.Sprintf("arn:%s:ec2:%s:*:launch-template/*", current.Partition, region.Name),
					},
				},
				iam.GetPolicyDocumentStatementArgs{
					Sid:    pulumi.String("AllowReadActions"),
					Effect: pulumi.String("Allow"),
					Actions: pulumi.StringArray{
						pulumi.String("ec2:DescribeAvailabilityZones"),
						pulumi.String("ec2:DescribeImages"),
						pulumi.String("ec2:DescribeInstances"),
						pulumi.String("ec2:DescribeInstanceTypeOfferings"),
						pulumi.String("ec2:DescribeInstanceTypes"),
						pulumi.String("ec2:DescribeLaunchTemplates"),
						pulumi.String("ec2:DescribeSecurityGroups"),
						pulumi.String("ec2:DescribeSpotPriceHistory"),
						pulumi.String("ec2:DescribeSubnets"),
					},
					Resources: pulumi.StringArray{
						pulumi.String("*"),
					},
				},
				iam.GetPolicyDocumentStatementArgs{
					Sid:    pulumi.String("AllowSSMReadActions"),
					Effect: pulumi.String("Allow"),
					Actions: pulumi.StringArray{
						pulumi.String("ssm:GetParameter"),
					},
					Resources: pulumi.StringArray{
						pulumi.Sprintf("arn:%s:ssm:%s::parameter/aws/service/*", current.Partition, region.Name),
					},
				},
				iam.GetPolicyDocumentStatementArgs{
					Sid:    pulumi.String("AllowPricingReadActions"),
					Effect: pulumi.String("Allow"),
					Actions: pulumi.StringArray{
						pulumi.String("pricing:GetProducts"),
					},
					Resources: pulumi.StringArray{
						pulumi.String("*"),
					},
				},
				iam.GetPolicyDocumentStatementArgs{
					Sid:    pulumi.String("AllowInterruptionQueueActions"),
					Effect: pulumi.String("Allow"),
					Actions: pulumi.StringArray{
						pulumi.String("sqs:DeleteMessage"),
						pulumi.String("sqs:GetQueueUrl"),
						pulumi.String("sqs:ReceiveMessage"),
					},
					Resources: pulumi.StringArray{
						queue.Arn,
					},
				},
				iam.GetPolicyDocumentStatementArgs{
					Sid:    pulumi.String("AllowPassingInstanceRole"),
					Effect: pulumi.String("Allow"),
					Actions: pulumi.StringArray{
						pulumi.String("iam:PassRole"),
					},
					Resources: pulumi.StringArray{
						pulumi.String("*"),
					},
					Conditions: iam.GetPolicyDocumentStatementConditionArray{
						iam.GetPolicyDocumentStatementConditionArgs{
							Test:     pulumi.String("StringEquals"),
							Values:   pulumi.StringArray{pulumi.String("ec2.amazonaws.com")},
							Variable: pulumi.String("iam:PassedToService"),
						},
					},
				},
				iam.GetPolicyDocumentStatementArgs{
					Sid:    pulumi.String("AllowScopedInstanceProfileCreationActions"),
					Effect: pulumi.String("Allow"),
					Actions: pulumi.StringArray{
						pulumi.String("iam:CreateInstanceProfile"),
						pulumi.String("iam:TagInstanceProfile"),
						pulumi.String("iam:AddRoleToInstanceProfile"),
						pulumi.String("iam:RemoveRoleFromInstanceProfile"),
						pulumi.String("iam:DeleteInstanceProfile"),
						pulumi.String("iam:GetInstanceProfile"),
						pulumi.String("iam:ListInstanceProfiles"),
					},
					Resources: pulumi.StringArray{
						pulumi.String("*"),
					},
				},
				iam.GetPolicyDocumentStatementArgs{
					Sid:    pulumi.String("AllowAPIServerEndpointDiscovery"),
					Effect: pulumi.String("Allow"),
					Actions: pulumi.StringArray{
						pulumi.String("eks:DescribeCluster"),
					},
					Resources: pulumi.StringArray{
						controlPlane.Arn,
					},
				},
			},
		}, pulumi.Parent(karpenterRole.Role))

		karpenterPolicy, err := iam.NewPolicy(ctx, fmt.Sprintf("%s-karpenter-policy", name), &iam.PolicyArgs{
			Policy: karpenterPolicyDoc.Json(),
			Tags:   tags,
		}, pulumi.Parent(karpenterRole.Role))
		if err != nil {
			return nil, fmt.Errorf("error creating karpenter policy: %w", err)
		}

		_, err = iam.NewRolePolicyAttachment(ctx, fmt.Sprintf("%s-karpenter-policy", name), &iam.RolePolicyAttachmentArgs{
			Role:      karpenterRole.Role.Name,
			PolicyArn: karpenterPolicy.Arn,
		}, pulumi.Parent(karpenterRole.Role))
		if err != nil {
			return nil, fmt.Errorf("error attaching karpenter policy to role: %w", err)
		}

		nodePolicyJSON, err := json.Marshal(map[string]interface{}{
			"Statement": []map[string]interface{}{
				{
					"Action": "sts:AssumeRole",
					"Effect": "Allow",
					"Principal": map[string]interface{}{
						"Service": "ec2.amazonaws.com",
					},
				},
			},
			"Version": "2012-10-17",
		})
		if err != nil {
			return nil, fmt.Errorf("error marshalling node policy: %w", err)
		}

		karpenterNodeRole, err = iam.NewRole(ctx, fmt.Sprintf("%s-karpenter-node-role", name), &iam.RoleArgs{
			AssumeRolePolicy: pulumi.String(nodePolicyJSON),
			Tags:             tags,
		}, pulumi.Parent(component))
		if err != nil {
			return nil, fmt.Errorf("error creating karpenter node role: %w", err)
		}

		_, err = iam.NewRolePolicyAttachment(ctx, fmt.Sprintf("%s-karpenter-node-worker-policy", name), &iam.RolePolicyAttachmentArgs{
			PolicyArn: pulumi.String("arn:aws:iam::aws:policy/AmazonEKSWorkerNodePolicy"),
			Role:      karpenterNodeRole.Name,
		}, pulumi.Parent(karpenterNodeRole))
		if err != nil {
			return nil, fmt.Errorf("error attaching karpenter worker policy: %w", err)
		}

		_, err = iam.NewRolePolicyAttachment(ctx, fmt.Sprintf("%s-karpenter-node-ecr-policy", name), &iam.RolePolicyAttachmentArgs{
			PolicyArn: pulumi.String("arn:aws:iam::aws:policy/AmazonEC2ContainerRegistryReadOnly"),
			Role:      karpenterNodeRole.Name,
		}, pulumi.Parent(karpenterNodeRole))
		if err != nil {
			return nil, fmt.Errorf("error attaching karpenter node ecr policy: %w", err)
		}

		_, err = iam.NewRolePolicyAttachment(ctx, fmt.Sprintf("%s-karpenter-node-ssm-policy", name), &iam.RolePolicyAttachmentArgs{
			PolicyArn: pulumi.String("arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"),
			Role:      karpenterNodeRole.Name,
		}, pulumi.Parent(karpenterNodeRole))
		if err != nil {
			return nil, fmt.Errorf("error attaching karpenter node ecr policy: %w", err)
		}

		_, err = NewRoleMapping(ctx, fmt.Sprintf("%s-karpenter-aws-auth-role-mapping", name), &RoleMappingArgs{
			RoleArn:  karpenterNodeRole.Arn,
			Username: pulumi.String("system:node:{{EC2PrivateDNSName}}"),
			Groups: pulumi.StringArray{
				pulumi.String("system:bootstrappers"),
				pulumi.String("system:nodes"),
			},
		}, pulumi.Parent(karpenterNodeRole), pulumi.Provider(provider))
		if err != nil {
			return nil, fmt.Errorf("error creating aws-auth karpenter role mapping: %w", err)
		}

		_, err = iam.NewInstanceProfile(ctx, fmt.Sprintf("%s-karpenter-node-instance-profile", name), &iam.InstanceProfileArgs{
			Role: karpenterNodeRole.Name,
			Tags: tags,
		}, pulumi.Parent(karpenterNodeRole))
		if err != nil {
			return nil, fmt.Errorf("error creating karpenter node instance profile: %w", err)
		}

		crds, err := helm.NewRelease(ctx, fmt.Sprintf("%s-karpenter-crds", name), &helm.ReleaseArgs{
			Chart:     pulumi.String("oci://public.ecr.aws/karpenter/karpenter-crd"),
			Version:   pulumi.String(args.KarpenterVersion),
			Namespace: pulumi.String("kube-system"),
			SkipCrds:  pulumi.Bool(false),
		}, pulumi.Parent(controlPlane), pulumi.Provider(provider), pulumi.DependsOn([]pulumi.Resource{karpenterServiceAccountAnnotations}))
		if err != nil {
			return nil, fmt.Errorf("error installing karpenter crds: %w", err)
		}

		_, err = helm.NewRelease(
			ctx, fmt.Sprintf("%s-karpenter", name), &helm.ReleaseArgs{
				Chart:     pulumi.String("oci://public.ecr.aws/karpenter/karpenter"),
				Version:   pulumi.String(args.KarpenterVersion),
				Namespace: pulumi.String("kube-system"),
				SkipCrds:  pulumi.Bool(true),
				Values: pulumi.Map{
					"tolerations": pulumi.MapArray{
						pulumi.Map{
							"key":      pulumi.String("node.lbrlabs.com/system"),
							"operator": pulumi.String("Equal"),
							"value":    pulumi.String("true"),
							"effect":   pulumi.String("NoSchedule"),
						},
					},
					"controller": pulumi.Map{
						"resources": pulumi.Map{
							"requests": pulumi.Map{
								"cpu":    pulumi.String("1"),
								"memory": pulumi.String("1Gi"),
							},
							"limits": pulumi.Map{
								"cpu":    pulumi.String("1"),
								"memory": pulumi.String("1Gi"),
							},
						},
					},
					"serviceAccount": pulumi.Map{
						"create": pulumi.Bool(false),
						"name":   serviceAccount.Metadata.Name(),
					},
					"settings": pulumi.Map{
						"clusterName":       controlPlane.Name,
						"interruptionQueue": queue.Name,
					},
				},
			}, pulumi.Parent(controlPlane), pulumi.Provider(provider), pulumi.DependsOn([]pulumi.Resource{crds}),
		)
		if err != nil {
			return nil, fmt.Errorf("error installing karpenter helm release: %w", err)
		}

	}

	component.ClusterName = controlPlane.Name
	component.ControlPlane = controlPlane
	component.OidcProvider = oidcProvider
	component.SystemNodes = systemNodes
	if karpenterRole != nil {
		component.KarpenterRole = karpenterRole.Role
	}
	component.KarpenterNodeRole = karpenterNodeRole
	component.KubeConfig = kc

	if err := ctx.RegisterResourceOutputs(component, pulumi.Map{
		"clusterName":           controlPlane.Name,
		"controlPlane":          controlPlane,
		"oidcProvider":          oidcProvider,
		"kubeconfig":            kc,
		"clusterSecurityGroups": controlPlane.VpcConfig.SecurityGroupIds(),
		"karpenterQueueName":    component.KarpenterQueueName,
		"karpenterRole":         component.KarpenterRole,
	}); err != nil {
		return nil, err
	}

	return component, nil
}

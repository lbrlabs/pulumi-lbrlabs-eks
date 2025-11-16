package provider

import (
	"fmt"

	"github.com/pulumi/pulumi-aws/sdk/v6/go/aws/eks"
	"github.com/pulumi/pulumi-kubernetes/sdk/v4/go/kubernetes"
	helm "github.com/pulumi/pulumi-kubernetes/sdk/v4/go/kubernetes/helm/v3"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// IngressConfig represents the configuration for the deprecated ingress controller.
// Deprecated: Use NginxIngressConfig instead.
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
	EnableExternal pulumi.BoolInput `pulumi:"enableExternal"`
	// EnableInternal controls whether to create the internal-facing ingress controller
	EnableInternal pulumi.BoolInput `pulumi:"enableInternal"`
}

// NginxIngressConfig represents the configuration for the F5 NGINX Ingress Controller.
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

// IngressDeploymentArgs contains all the arguments needed to deploy NGINX Ingress Controllers.
type IngressDeploymentArgs struct {
	Name                  string
	IngressConfig         *IngressConfig
	NginxIngressConfig    *NginxIngressConfig
	EnableExternalIngress bool
	EnableInternalIngress bool
	NginxIngressVersion   pulumi.StringInput
	LbType                pulumi.StringInput
	CertificateArn        *pulumi.StringInput
	ControlPlane          *eks.Cluster
	Provider              *kubernetes.Provider
	SystemNodes           *NodeGroup
	EbsCsiAddon           *eks.Addon
}

// mergeNginxIngressConfig merges non-nil fields from source into destination.
// This ensures that zero values (false, 0, "", nil) don't override defaults -
// only explicitly set values take precedence. This follows Pulumi's principle
// that unset values should not override configured defaults.
func mergeNginxIngressConfig(source, dest *NginxIngressConfig) {
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

// buildServiceAnnotations creates the service annotations for the load balancer.
func buildServiceAnnotations(lbType pulumi.StringInput, certificateArn *pulumi.StringInput, nlbTargetType pulumi.StringInput, internal bool) pulumi.Map {
	annotations := pulumi.Map{
		"service.beta.kubernetes.io/aws-load-balancer-ssl-ports":        pulumi.String("https"),
		"service.beta.kubernetes.io/aws-load-balancer-backend-protocol": pulumi.String("tcp"),
		"service.beta.kubernetes.io/aws-load-balancer-type":             lbType,
	}

	if certificateArn != nil {
		annotations["service.beta.kubernetes.io/aws-load-balancer-ssl-cert"] = *certificateArn
	}

	if internal {
		annotations["service.beta.kubernetes.io/aws-load-balancer-internal"] = pulumi.Bool(true)
	}

	if nlbTargetType != nil {
		annotations["service.beta.kubernetes.io/aws-load-balancer-nlb-target-type"] = nlbTargetType
	}

	return annotations
}

// DeployNginxIngressControllers deploys the F5 NGINX Ingress Controllers (external and/or internal).
func DeployNginxIngressControllers(ctx *pulumi.Context, args *IngressDeploymentArgs) error {
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
	mergeNginxIngressConfig(args.NginxIngressConfig, &realisedIngressConfig)

	// Deploy external ingress controller
	if args.EnableExternalIngress {
		if err := deployExternalIngressController(ctx, args, &realisedIngressConfig); err != nil {
			return err
		}
	}

	// Deploy internal ingress controller
	if args.EnableInternalIngress {
		if err := deployInternalIngressController(ctx, args, &realisedIngressConfig); err != nil {
			return err
		}
	}

	return nil
}

// deployExternalIngressController deploys the external-facing NGINX Ingress Controller.
func deployExternalIngressController(ctx *pulumi.Context, args *IngressDeploymentArgs, config *NginxIngressConfig) error {
	enableExternal := config.EnableExternal
	if enableExternal == nil {
		enableExternal = pulumi.Bool(true)
	}

	enableExternalOutput := enableExternal.ToBoolPtrOutput()

	nginxIngressExternal := enableExternalOutput.ApplyT(func(enabled *bool) (interface{}, error) {
		if enabled != nil && *enabled {
			externalAnnotations := buildServiceAnnotations(
				args.LbType,
				args.CertificateArn,
				config.NlbTargetType,
				false, // not internal
			)

			release, err := helm.NewRelease(ctx, fmt.Sprintf("%s-nginx-ext", args.Name), &helm.ReleaseArgs{
				Chart:     pulumi.String("oci://ghcr.io/nginx/charts/nginx-ingress"),
				Namespace: pulumi.String("kube-system"),
				Version:   args.NginxIngressVersion,
				Values: pulumi.Map{
					"controller": pulumi.Map{
						"enableSnippets": config.AllowSnippetAnnotations,
						"replicaCount":   config.ControllerReplicas,
						"tolerations": pulumi.MapArray{
							pulumi.Map{
								"key":      pulumi.String("node.lbrlabs.com/system"),
								"operator": pulumi.String("Equal"),
								"value":    pulumi.String("true"),
								"effect":   pulumi.String("NoSchedule"),
							},
						},
						"ingressClass": pulumi.Map{
							"name": pulumi.String("external"),
						},
						"service": pulumi.Map{
							"annotations": externalAnnotations,
						},
						"config": pulumi.Map{
							"entries": config.AdditionalConfig,
						},
					},
					"prometheus": pulumi.Map{
						"create": config.EnableMetrics,
						"serviceMonitor": pulumi.Map{
							"create": config.EnableServiceMonitor,
						},
					},
				},
			}, pulumi.Parent(args.ControlPlane), pulumi.Provider(args.Provider), pulumi.DependsOn([]pulumi.Resource{args.SystemNodes, args.ControlPlane, args.EbsCsiAddon}))
			if err != nil {
				return nil, fmt.Errorf("error installing external nginx ingress helm release: %w", err)
			}
			return release, nil
		}
		return nil, nil
	})

	_ = nginxIngressExternal
	return nil
}

// deployInternalIngressController deploys the internal-facing NGINX Ingress Controller.
func deployInternalIngressController(ctx *pulumi.Context, args *IngressDeploymentArgs, config *NginxIngressConfig) error {
	enableInternal := config.EnableInternal
	if enableInternal == nil {
		enableInternal = pulumi.Bool(true)
	}

	enableInternalOutput := enableInternal.ToBoolPtrOutput()

	nginxIngressInternal := enableInternalOutput.ApplyT(func(enabled *bool) (interface{}, error) {
		if enabled != nil && *enabled {
			internalAnnotations := buildServiceAnnotations(
				args.LbType,
				args.CertificateArn,
				config.NlbTargetType,
				true, // internal
			)

			release, err := helm.NewRelease(ctx, fmt.Sprintf("%s-nginx-int", args.Name), &helm.ReleaseArgs{
				Chart:     pulumi.String("oci://ghcr.io/nginx/charts/nginx-ingress"),
				Namespace: pulumi.String("kube-system"),
				Version:   args.NginxIngressVersion,
				Values: pulumi.Map{
					"controller": pulumi.Map{
						"enableSnippets": config.AllowSnippetAnnotations,
						"replicaCount":   config.ControllerReplicas,
						"tolerations": pulumi.MapArray{
							pulumi.Map{
								"key":      pulumi.String("node.lbrlabs.com/system"),
								"operator": pulumi.String("Equal"),
								"value":    pulumi.String("true"),
								"effect":   pulumi.String("NoSchedule"),
							},
						},
						"ingressClass": pulumi.Map{
							"name": pulumi.String("internal"),
						},
						"service": pulumi.Map{
							"annotations": internalAnnotations,
						},
						"config": pulumi.Map{
							"entries": config.AdditionalConfig,
						},
					},
					"prometheus": pulumi.Map{
						"create": config.EnableMetrics,
						"serviceMonitor": pulumi.Map{
							"create": config.EnableServiceMonitor,
						},
					},
				},
			}, pulumi.Parent(args.ControlPlane), pulumi.Provider(args.Provider), pulumi.DependsOn([]pulumi.Resource{args.SystemNodes, args.ControlPlane, args.EbsCsiAddon}))
			if err != nil {
				return nil, fmt.Errorf("error installing internal nginx ingress helm release: %w", err)
			}
			return release, nil
		}
		return nil, nil
	})

	_ = nginxIngressInternal
	return nil
}

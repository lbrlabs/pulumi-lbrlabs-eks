package kubeconfig

import (
	"encoding/json"

	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

type KubeConfig struct {
	APIVersion     string      `json:"apiVersion"`
	Clusters       []Clusters  `json:"clusters"`
	Contexts       []Contexts  `json:"contexts"`
	CurrentContext string      `json:"current-context"`
	Kind           string      `json:"kind"`
	Preferences    Preferences `json:"preferences"`
	Users          []Users     `json:"users"`
}
type Cluster struct {
	Server                   string `json:"server"`
	CertificateAuthorityData string `json:"certificate-authority-data"`
}
type Clusters struct {
	Cluster Cluster `json:"cluster"`
	Name    string  `json:"name"`
}
type Context struct {
	Cluster string `json:"cluster"`
	User    string `json:"user"`
}
type Contexts struct {
	Context Context `json:"context"`
	Name    string  `json:"name"`
}
type Preferences struct {
}
type Exec struct {
	APIVersion string   `json:"apiVersion"`
	Command    string   `json:"command"`
	Args       []string `json:"args"`
	Env        []Env    `json:"env"`
}
type Env struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}
type User struct {
	Exec Exec `json:"exec"`
}
type Users struct {
	Name string `json:"name"`
	User User   `json:"user"`
}

func Generate(name string, clusterEndpoint pulumi.StringOutput, certData pulumi.StringOutput, clusterName pulumi.StringOutput) (pulumi.StringOutput, error) {

	rawKubeConfig, err := json.Marshal(&KubeConfig{
		APIVersion: "v1",
		Clusters: []Clusters{
			{
				Cluster: Cluster{
					Server:                   "%s",
					CertificateAuthorityData: "%s",
				},
				Name: name,
			},
		},
		Contexts: []Contexts{
			{
				Context: Context{
					Cluster: name,
					User:    name,
				},
				Name: name,
			},
		},
		Kind:           "Config",
		CurrentContext: name,
		Users: []Users{
			{
				Name: name,
				User: User{
					Exec: Exec{
						APIVersion: "client.authentication.k8s.io/v1beta1",
						Command:    "aws",
						Args: []string{
							"eks",
							"get-token",
							"--cluster-name",
							"%s",
						},
						Env: []Env{
							{
								Name:  "KUBERNETES_EXEC_INFO",
								Value: "{\"apiVersion\": \"client.authentication.k8s.io/v1beta1\"}",
							},
						},
					},
				},
			},
		},
	})

	if err != nil {
		return pulumi.StringOutput{}, err
	}

	return pulumi.Sprintf(string(rawKubeConfig), clusterEndpoint, certData, clusterName), nil
}

package main

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

func main() {
	if len(os.Args) < 4 {
		fmt.Printf("Usage: %s <language> <out-dir> <schema-file>\n", os.Args[0])
		os.Exit(1)
	}

	language, outdir, schemaPath := os.Args[1], os.Args[2], os.Args[3]

	err := emitSDK(language, outdir, schemaPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed: %s\n", err)
		os.Exit(1)
	}
}

func emitSDK(language, outdir, schemaPath string) error {
	switch language {
	case "go", "nodejs", "python", "dotnet":
	default:
		return fmt.Errorf("unrecognized language %q", language)
	}
	var yarnConfig []byte
	var yarnConfigMode os.FileMode
	if language == "nodejs" {
		yarnConfigPath := filepath.Join(outdir, ".yarnrc.yml")
		info, err := os.Stat(yarnConfigPath)
		if err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("reading nodejs yarn configuration: %w", err)
		}
		if err == nil {
			yarnConfig, err = os.ReadFile(yarnConfigPath)
			if err != nil {
				return fmt.Errorf("reading nodejs yarn configuration: %w", err)
			}
			yarnConfigMode = info.Mode()
		}
	}

	schemaDir, err := filepath.Abs(filepath.Dir(schemaPath))
	if err != nil {
		return fmt.Errorf("resolving schema directory: %w", err)
	}

	providerPath := filepath.Join(schemaDir, "bin", "pulumi-resource-lbrlabs-eks")
	command := exec.Command("pulumi", "package", "gen-sdk", providerPath, "--language", language,
		"--out", filepath.Dir(outdir), "--version", "0.0.0")
	command.Stdout = os.Stdout
	command.Stderr = os.Stderr
	if err := command.Run(); err != nil {
		return fmt.Errorf("generating %s package: %w", language, err)
	}

	if language == "nodejs" {
		if yarnConfig != nil {
			if err := os.WriteFile(filepath.Join(outdir, ".yarnrc.yml"), yarnConfig, yarnConfigMode); err != nil {
				return fmt.Errorf("restoring nodejs yarn configuration: %w", err)
			}
		}
		return normalizeNodeJSPackage(outdir)
	}

	return normalizeSDKVersion(language, outdir)
}

func normalizeNodeJSPackage(outdir string) error {
	packageJSONPath := filepath.Join(outdir, "package.json")
	packageJSON, err := os.ReadFile(packageJSONPath)
	if err != nil {
		return fmt.Errorf("reading nodejs package metadata: %w", err)
	}

	var metadata nodeJSPackageMetadata
	if err := json.Unmarshal(packageJSON, &metadata); err != nil {
		return fmt.Errorf("unmarshalling nodejs package metadata: %w", err)
	}

	metadata.Repository = nodeJSPackageRepository{
		Type: "git",
		URL:  "git+https://github.com/lbrlabs/pulumi-lbrlabs-eks.git",
	}
	metadata.Version = "${VERSION}"
	metadata.PackageManager = "yarn@1.22.22"

	normalizedPackageJSON, err := json.MarshalIndent(metadata, "", "    ")
	if err != nil {
		return fmt.Errorf("marshalling nodejs package metadata: %w", err)
	}
	if err := os.WriteFile(packageJSONPath, append(normalizedPackageJSON, '\n'), 0644); err != nil {
		return fmt.Errorf("writing nodejs package metadata: %w", err)
	}

	return nil
}

type nodeJSPackageMetadata struct {
	Name            string              `json:"name"`
	Version         string              `json:"version"`
	Keywords        []string            `json:"keywords,omitempty"`
	Repository      interface{}         `json:"repository"`
	PackageManager  string              `json:"packageManager"`
	Scripts         map[string]string   `json:"scripts,omitempty"`
	Dependencies    map[string]string   `json:"dependencies,omitempty"`
	DevDependencies map[string]string   `json:"devDependencies,omitempty"`
	Pulumi          nodeJSPackagePulumi `json:"pulumi"`
}

type nodeJSPackageRepository struct {
	Type string `json:"type"`
	URL  string `json:"url"`
}

type nodeJSPackagePulumi struct {
	Resource bool   `json:"resource"`
	Name     string `json:"name"`
	Server   string `json:"server"`
}

func normalizeSDKVersion(language, outdir string) error {
	pluginManifestPath := ""
	switch language {
	case "go":
		pluginManifestPath = filepath.Join(outdir, "eks", "pulumi-plugin.json")
		utilitiesPath := filepath.Join(outdir, "eks", "internal", "pulumiUtilities.go")
		utilities, err := os.ReadFile(utilitiesPath)
		if err != nil {
			return fmt.Errorf("reading go sdk utilities: %w", err)
		}

		const generatedVersion = `semver.MustParse("0.0.0")`
		if !strings.Contains(string(utilities), generatedVersion) {
			return fmt.Errorf("go sdk utilities did not contain the generated version")
		}
		utilities = []byte(strings.ReplaceAll(string(utilities), generatedVersion, "SdkVersion"))
		if err := os.WriteFile(utilitiesPath, utilities, 0644); err != nil {
			return fmt.Errorf("writing go sdk utilities: %w", err)
		}
	case "python":
		pluginManifestPath = filepath.Join(outdir, "lbrlabs_pulumi_eks", "pulumi-plugin.json")
	case "dotnet":
		pluginManifestPath = filepath.Join(outdir, "pulumi-plugin.json")
		projectPath := filepath.Join(outdir, "Lbrlabs.PulumiPackage.Eks.csproj")
		project, err := os.ReadFile(projectPath)
		if err != nil {
			return fmt.Errorf("reading dotnet project: %w", err)
		}
		project = []byte(strings.Replace(string(project), "    <Version>0.0.0</Version>\n", "", 1))
		if err := os.WriteFile(projectPath, project, 0644); err != nil {
			return fmt.Errorf("writing dotnet project: %w", err)
		}
	}

	return normalizePluginManifest(pluginManifestPath)
}

func normalizePluginManifest(path string) error {
	manifest, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("reading plugin manifest: %w", err)
	}

	var metadata map[string]interface{}
	if err := json.Unmarshal(manifest, &metadata); err != nil {
		return fmt.Errorf("unmarshalling plugin manifest: %w", err)
	}
	delete(metadata, "version")

	normalizedManifest, err := json.MarshalIndent(metadata, "", "  ")
	if err != nil {
		return fmt.Errorf("marshalling plugin manifest: %w", err)
	}
	if err := os.WriteFile(path, append(normalizedManifest, '\n'), 0644); err != nil {
		return fmt.Errorf("writing plugin manifest: %w", err)
	}

	return nil
}

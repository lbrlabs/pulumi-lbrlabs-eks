package main

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
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
	if language == "nodejs" {
		var err error
		yarnConfig, err = os.ReadFile(filepath.Join(outdir, ".yarnrc.yml"))
		if err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("reading nodejs yarn configuration: %w", err)
		}
	}

	schemaDir, err := filepath.Abs(filepath.Dir(schemaPath))
	if err != nil {
		return fmt.Errorf("resolving schema directory: %w", err)
	}

	providerPath := filepath.Join(schemaDir, "bin", "pulumi-resource-lbrlabs-eks")
	command := exec.Command("pulumi", "package", "gen-sdk", providerPath, "--language", language, "--out", filepath.Dir(outdir))
	command.Stdout = os.Stdout
	command.Stderr = os.Stderr
	if err := command.Run(); err != nil {
		return fmt.Errorf("generating %s package: %w", language, err)
	}

	if language == "nodejs" {
		if yarnConfig != nil {
			if err := os.WriteFile(filepath.Join(outdir, ".yarnrc.yml"), yarnConfig, 0600); err != nil {
				return fmt.Errorf("restoring nodejs yarn configuration: %w", err)
			}
		}
		return normalizeNodeJSPackage(outdir)
	}

	return nil
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
	metadata.PackageManager = "yarn@1.22.22"

	normalizedPackageJSON, err := json.MarshalIndent(metadata, "", "    ")
	if err != nil {
		return fmt.Errorf("marshalling nodejs package metadata: %w", err)
	}
	if err := os.WriteFile(packageJSONPath, append(normalizedPackageJSON, '\n'), 0600); err != nil {
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

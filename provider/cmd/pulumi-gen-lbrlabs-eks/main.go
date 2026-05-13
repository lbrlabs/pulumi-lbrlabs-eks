package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/ghodss/yaml"
	"github.com/pkg/errors"
	dotnetgen "github.com/pulumi/pulumi/pkg/v3/codegen/dotnet"
	gogen "github.com/pulumi/pulumi/pkg/v3/codegen/go"
	nodejsgen "github.com/pulumi/pulumi/pkg/v3/codegen/nodejs"
	pygen "github.com/pulumi/pulumi/pkg/v3/codegen/python"
	"github.com/pulumi/pulumi/pkg/v3/codegen/schema"
)

func main() {
	if len(os.Args) < 4 {
		fmt.Printf("Usage: %s <language> <out-dir> <schema-file>\n", os.Args[0])
		os.Exit(1)
	}

	language, outdir, schemaPath := os.Args[1], os.Args[2], os.Args[3]

	err := emitSDK(language, outdir, schemaPath)
	if err != nil {
		fmt.Printf("Failed: %s", err.Error())
	}
}

func emitSDK(language, outdir, schemaPath string) error {
	pkg, err := readSchema(schemaPath)
	if err != nil {
		return err
	}

	tool := "Pulumi SDK Generator"
	extraFiles := map[string][]byte{}

	var generator func() (map[string][]byte, error)
	switch language {
	case "dotnet":
		generator = func() (map[string][]byte, error) { return dotnetgen.GeneratePackage(tool, pkg, extraFiles, nil) }
	case "go":
		generator = func() (map[string][]byte, error) { return gogen.GeneratePackage(tool, pkg, nil) }
	case "nodejs":
		generator = func() (map[string][]byte, error) {
			return nodejsgen.GeneratePackage(tool, pkg, extraFiles, nil, false, nil)
		}
	case "python":
		generator = func() (map[string][]byte, error) { return pygen.GeneratePackage(tool, pkg, extraFiles, nil) }
	default:
		return errors.Errorf("Unrecognized language %q", language)
	}

	files, err := generator()
	if err != nil {
		return errors.Wrapf(err, "generating %s package", language)
	}
	if language == "nodejs" {
		if err := normalizeNodeJSPackage(files); err != nil {
			return err
		}
	}

	for f, contents := range files {
		if err := emitFile(outdir, f, contents); err != nil {
			return errors.Wrapf(err, "emitting file %v", f)
		}
	}

	return nil
}

func normalizeNodeJSPackage(files map[string][]byte) error {
	packageJSON, ok := files["package.json"]
	if !ok {
		return nil
	}

	var metadata nodeJSPackageMetadata
	if err := json.Unmarshal(packageJSON, &metadata); err != nil {
		return errors.Wrap(err, "unmarshalling nodejs package metadata")
	}

	metadata.Repository = nodeJSPackageRepository{
		Type: "git",
		URL:  "git+https://github.com/lbrlabs/pulumi-lbrlabs-eks.git",
	}
	metadata.PackageManager = "yarn@1.22.22"

	normalizedPackageJSON, err := json.MarshalIndent(metadata, "", "    ")
	if err != nil {
		return errors.Wrap(err, "marshalling nodejs package metadata")
	}
	files["package.json"] = append(normalizedPackageJSON, '\n')

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

func readSchema(schemaPath string) (*schema.Package, error) {
	schemaBytes, err := os.ReadFile(schemaPath)
	if err != nil {
		return nil, errors.Wrap(err, "reading schema")
	}

	if strings.HasSuffix(schemaPath, ".yaml") {
		schemaBytes, err = yaml.YAMLToJSON(schemaBytes)
		if err != nil {
			return nil, errors.Wrap(err, "reading YAML schema")
		}
	}

	var spec schema.PackageSpec
	if err = json.Unmarshal(schemaBytes, &spec); err != nil {
		return nil, errors.Wrap(err, "unmarshalling schema")
	}

	pkg, err := schema.ImportSpec(spec, nil, schema.ValidationOptions{})
	if err != nil {
		return nil, errors.Wrap(err, "importing schema")
	}
	return pkg, nil
}

func emitFile(rootDir, filename string, contents []byte) error {
	outPath := filepath.Join(rootDir, filename)
	if err := os.MkdirAll(filepath.Dir(outPath), 0755); err != nil {
		return err
	}
	if err := os.WriteFile(outPath, contents, 0600); err != nil {
		return err
	}
	return nil
}

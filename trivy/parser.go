package trivy

import (
	"github.com/CycloneDX/cyclonedx-go"
	"gitlab.com/code-secure/analyzer"
	"strings"
)

func NewSBOMParser(sbom cyclonedx.BOM) *SBOMParser {
	mComponents := make(map[string]cyclonedx.Component)
	mDependencies := make(map[string]cyclonedx.Dependency)
	var appComponents []cyclonedx.Component
	if sbom.Components != nil {
		for _, component := range *sbom.Components {
			if component.Type == cyclonedx.ComponentTypeApplication {
				appComponents = append(appComponents, component)
			} else {
				if component.PackageURL != "" {
					mComponents[component.BOMRef] = component
				}
			}
		}
	}
	if sbom.Dependencies != nil {
		for _, dependency := range *sbom.Dependencies {
			mDependencies[dependency.Ref] = dependency
		}
	}
	return &SBOMParser{
		mComponents:   mComponents,
		mDependencies: mDependencies,
		appComponents: appComponents,
	}
}

type SBOMParser struct {
	appComponents []cyclonedx.Component
	mComponents   map[string]cyclonedx.Component
	mDependencies map[string]cyclonedx.Dependency
}

func (parser *SBOMParser) GetProjectPackages() []analyzer.Package {
	var packages []analyzer.Package
	for _, component := range parser.appComponents {
		pkgType := getPkgType(component)
		location := component.Name
		var dependencies []cyclonedx.Component
		if pkgType == "pom" {
			for _, dependency := range parser.GetDependencies(component.BOMRef) {
				dependencies = append(dependencies, parser.GetDependencies(dependency.BOMRef)...)
			}
		} else {
			dependencies = parser.GetDependencies(component.BOMRef)
		}
		for _, dependency := range dependencies {
			packages = append(packages, analyzer.Package{
				PkgId:    dependency.PackageURL,
				Group:    dependency.Group,
				Name:     dependency.Name,
				Version:  dependency.Version,
				Type:     getPkgType(dependency),
				License:  getLicense(dependency),
				Location: &location,
			})
		}
	}
	return packages
}

func (parser *SBOMParser) GetPackageDependencies() []analyzer.PackageDependency {
	var pkgDependencies []analyzer.PackageDependency
	for _, dependency := range parser.mDependencies {
		if pkg, ok := parser.mComponents[dependency.Ref]; ok {
			var dependencies []string
			if dependency.Dependencies != nil {
				for _, depenOn := range *dependency.Dependencies {
					if depenPkg, exist := parser.mComponents[depenOn]; exist {
						dependencies = append(dependencies, depenPkg.PackageURL)
					}
				}
			}
			pkgDependencies = append(pkgDependencies, analyzer.PackageDependency{
				PkgId:        pkg.PackageURL,
				Dependencies: dependencies,
			})
		}
	}
	return pkgDependencies
}

func (parser *SBOMParser) GetDependencies(bomRef string) []cyclonedx.Component {
	var components []cyclonedx.Component
	dependency := parser.mDependencies[bomRef]
	if dependency.Dependencies != nil {
		for _, bomRef := range *dependency.Dependencies {
			if component, ok := parser.mComponents[bomRef]; ok {
				components = append(components, component)
			}
		}
	}
	return components
}

func getPkgType(component cyclonedx.Component) string {
	if component.Properties == nil {
		return "unknown"
	}
	for _, property := range *component.Properties {
		if property.Name == "aquasecurity:trivy:PkgType" || property.Name == "aquasecurity:trivy:Type" {
			return property.Value
		}
	}
	return "unknown"
}

func getLicense(component cyclonedx.Component) string {
	if component.Licenses == nil {
		return ""
	}
	var licenses []string
	for _, license := range *component.Licenses {
		if license.License != nil {
			licenses = append(licenses, license.License.Name)
		}
	}
	return strings.Join(licenses, ", ")
}

package main

import (
	"encoding/json"
	"fmt"
	"github.com/CycloneDX/cyclonedx-go"
	"gitlab.com/code-secure/analyzer"
	"gitlab.com/code-secure/analyzer/logger"
	"os"
	"testing"
	"trivy/trivy"
)

func initEnv() {
	os.Setenv("GITLAB_TOKEN", "change_me")
	os.Setenv("CI_SERVER_URL", "https://gitlab.com")
	//os.Setenv("CI_MERGE_REQUEST_IID", "18")
	os.Setenv("CI_PROJECT_ID", "50471841")
	os.Setenv("CI_PROJECT_URL", "https://gitlab.com/0xduo/vulnado2")
	os.Setenv("CI_PROJECT_NAME", "vulnado2")
	os.Setenv("CI_PROJECT_NAMESPACE", "0xduo")
	os.Setenv("CI_COMMIT_TITLE", "Commit Test2")
	os.Setenv("CI_COMMIT_BRANCH", "main")
	os.Setenv("CI_DEFAULT_BRANCH", "main")
	os.Setenv("CI_JOB_URL", "https://gitlab.com/0xduo/vulnado/-/jobs/8241092355")
	os.Setenv("CI_COMMIT_SHA", "891832b2fdecb72c444af1a6676eba6eb40435ab")
	os.Setenv("CODE_SECURE_TOKEN", "5b615904c5be41cc8af813ddee581432c818f6d9cb01475aa0ff6172c73edeb7")
	os.Setenv("CODE_SECURE_URL", "http://localhost:5272")
}
func TestSBOMParser(t *testing.T) {
	reader, err := os.Open("testdata/sbom.json")
	if err != nil {
		logger.Fatal(err.Error())
	}
	decoder := cyclonedx.NewBOMDecoder(reader, cyclonedx.BOMFileFormatJSON)
	var sbom cyclonedx.BOM
	err = decoder.Decode(&sbom)
	if err != nil {
		logger.Fatal(err.Error())
	}
	parser := trivy.NewSBOMParser(sbom)
	parser.GetProjectPackages()
	data, _ := json.Marshal(parser.GetProjectPackages())
	fmt.Println(string(data))
	data, _ = json.Marshal(parser.GetPackageDependencies())
	fmt.Println(string(data))
}

func TestScanAnalyzer(t *testing.T) {
	initEnv()
	dependencyAnalyzer := analyzer.NewSCAAnalyzer()
	dependencyAnalyzer.RegisterScanner(&trivy.DependencyScanner{
		SkipDbUpdate: true,
		ProjectPath:  "/Users/duo/Downloads/test-cicd-main",
	})
	dependencyAnalyzer.Run()
}

func TestScanMavenAnalyzer(t *testing.T) {
	initEnv()
	os.Setenv("CI_PROJECT_ID", "50471842")
	os.Setenv("CI_PROJECT_URL", "https://gitlab.com/0xduo/spring-boot-multi-module-maven")
	os.Setenv("CI_PROJECT_NAME", "spring-boot-multi-module-maven")
	os.Setenv("CI_PROJECT_NAMESPACE", "0xduo")
	os.Setenv("CI_COMMIT_TITLE", "Commit spring-boot-multi-module-maven")
	dependencyAnalyzer := analyzer.NewSCAAnalyzer()
	dependencyAnalyzer.RegisterScanner(&trivy.DependencyScanner{
		SkipDbUpdate: true,
		ProjectPath:  "/Users/duo/Downloads/spring-boot-multi-module-maven",
	})
	dependencyAnalyzer.Run()
}

package trivy

import (
	"bufio"
	"encoding/json"
	"fmt"
	"github.com/CycloneDX/cyclonedx-go"
	"github.com/califio/code-secure-analyzer"
	"github.com/califio/code-secure-analyzer/logger"
	"io"
	"os"
	"os/exec"
)

const CyclonedxFormat = "cyclonedx"
const JSONFormat = "json"
const ScannerName = "trivy"

type DependencyScanner struct {
	SkipDbUpdate bool
	ProjectPath  string
}

func (scanner *DependencyScanner) Type() analyzer.ScannerType {
	return analyzer.ScannerTypeDependency
}

func (scanner *DependencyScanner) Name() string {
	return ScannerName
}

func (scanner *DependencyScanner) Scan() (*analyzer.SCAResult, error) {
	sbom, err := scanner.ScanSBOM()
	if err != nil {
		return nil, err
	}
	var result analyzer.SCAResult
	bomParser := NewSBOMParser(*sbom)
	result.Packages = bomParser.GetProjectPackages()
	result.PackageDependencies = bomParser.GetPackageDependencies()
	vulnerabilities, err := scanner.ScanVulnerabilities()
	if err != nil {
		logger.Error(err.Error())
	}
	result.Vulnerabilities = vulnerabilities
	return &result, nil
}

func (scanner *DependencyScanner) ScanSBOM() (*cyclonedx.BOM, error) {
	reader, err := scanner.scanWithOutputFormat(CyclonedxFormat, "sbom.json")
	if err != nil {
		return nil, err
	}
	bom := new(cyclonedx.BOM)
	decoder := cyclonedx.NewBOMDecoder(reader, cyclonedx.BOMFileFormatJSON)
	if err = decoder.Decode(bom); err != nil {
		return nil, err
	}
	return bom, nil
}

func (scanner *DependencyScanner) ScanVulnerabilities() ([]analyzer.Vulnerability, error) {
	reader, err := scanner.scanWithOutputFormat(JSONFormat, "vulnerabilities.json")
	if err != nil {
		return nil, err
	}
	bytes, err := io.ReadAll(reader)
	if err != nil {
		return nil, err
	}
	var report TrivyJSONFormat
	err = json.Unmarshal(bytes, &report)
	if err != nil {
		return nil, err
	}
	var vulnerabilities []analyzer.Vulnerability
	for _, result := range report.Results {
		for _, vulnerability := range result.Vulnerabilities {
			cvss := ""
			cvssScore := ""
			if vulnerability.CVSS.Nvd.V3Vector != "" {
				cvss = vulnerability.CVSS.Nvd.V3Vector
				cvssScore = fmt.Sprintf("%f", vulnerability.CVSS.Nvd.V3Score)
			} else if vulnerability.CVSS.Ghsa.V3Vector != "" {
				cvss = vulnerability.CVSS.Ghsa.V3Vector
				cvssScore = fmt.Sprintf("%f", vulnerability.CVSS.Ghsa.V3Score)
			}
			vulnerabilities = append(vulnerabilities, analyzer.Vulnerability{
				Identity:     vulnerability.VulnerabilityID,
				Name:         vulnerability.Title,
				Description:  vulnerability.Description,
				FixedVersion: vulnerability.FixedVersion,
				Severity:     parseSeverity(vulnerability.Severity),
				PkgId:        vulnerability.PkgIdentifier.PURL,
				PkgName:      vulnerability.PkgName,
				PublishedAt:  nil,
				Metadata: &analyzer.FindingMetadata{
					Cwes:       vulnerability.CweIDs,
					References: vulnerability.References,
					Cvss:       &cvss,
					CvssScore:  &cvssScore,
				},
			})
		}
	}
	return vulnerabilities, nil
}

func parseSeverity(severity string) analyzer.Severity {
	if severity == "CRITICAL" {
		return analyzer.SeverityCritical
	}
	if severity == "HIGH" {
		return analyzer.SeverityHigh
	}
	if severity == "MEDIUM" {
		return analyzer.SeverityMedium
	}
	if severity == "LOW" {
		return analyzer.SeverityLow
	}
	return analyzer.SeverityInfo
}

func (scanner *DependencyScanner) scanWithOutputFormat(format string, output string) (io.Reader, error) {
	args := []string{
		"repo",
		"--scanners", "vuln",
		"--ignore-unfixed",
		"--output", output,
		"--format", format,
	}
	if scanner.SkipDbUpdate {
		args = append(args, "--skip-db-update")
	}
	args = append(args, scanner.ProjectPath)

	cmd := exec.Command("trivy", args...)
	logger.Info(cmd.String())
	cmd.Env = os.Environ()
	stdout, _ := cmd.StdoutPipe()
	stderr, _ := cmd.StderrPipe()
	err := cmd.Start()
	if err != nil {
		return nil, err
	}
	go printStdout(stdout)
	go printStdout(stderr)
	err = cmd.Wait()
	if err != nil {
		return nil, err
	}
	return os.Open(output)
}

func printStdout(stdout io.ReadCloser) {
	reader := bufio.NewReader(stdout)
	line, _, err := reader.ReadLine()
	for {
		if err != nil || line == nil {
			break
		}
		logger.Println(string(line))
		line, _, err = reader.ReadLine()
	}
}

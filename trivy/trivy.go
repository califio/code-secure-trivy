package trivy

import "time"

type CVSS struct {
	V2Vector string  `json:"V2Vector,omitempty"`
	V3Vector string  `json:"V3Vector,omitempty"`
	V2Score  float32 `json:"V2Score,omitempty"`
	V3Score  float32 `json:"V3Score,omitempty"`
}
type Vulnerability struct {
	VulnerabilityID string `json:"VulnerabilityID"`
	PkgID           string `json:"PkgID"`
	PkgName         string `json:"PkgName"`
	PkgIdentifier   struct {
		PURL string `json:"PURL"`
		UID  string `json:"UID"`
	} `json:"PkgIdentifier"`
	InstalledVersion string `json:"InstalledVersion"`
	FixedVersion     string `json:"FixedVersion,omitempty"`
	Status           string `json:"Status"`
	SeveritySource   string `json:"SeveritySource"`
	PrimaryURL       string `json:"PrimaryURL"`
	DataSource       struct {
		ID   string `json:"ID"`
		Name string `json:"Name"`
		URL  string `json:"URL"`
	} `json:"DataSource"`
	Title       string   `json:"Title"`
	Description string   `json:"Description"`
	Severity    string   `json:"Severity"`
	CweIDs      []string `json:"CweIDs,omitempty"`
	CVSS        struct {
		Ghsa    CVSS `json:"ghsa"`
		Nvd     CVSS `json:"nvd,omitempty"`
		Redhat  CVSS `json:"redhat,omitempty"`
		Bitnami CVSS `json:"bitnami,omitempty"`
	} `json:"CVSS"`
	References       []string   `json:"References"`
	PublishedDate    *time.Time `json:"PublishedDate"`
	LastModifiedDate *time.Time `json:"LastModifiedDate"`
}

type TrivyJSONFormat struct {
	Results []struct {
		Target          string          `json:"Target"`
		Type            string          `json:"Type"`
		Vulnerabilities []Vulnerability `json:"Vulnerabilities"`
	} `json:"Results"`
}

package main

import "time"

type (
	totalLevel struct {
		Critical int
		High     int
		Medium   int
		Low      int
	}

	VulnCheck struct {
		Version string     `json:"version"`
		Schema  string     `json:"$schema"`
		Runs    []VulnRuns `json:"runs"`
	}
	VulnShortDescription struct {
		Text string `json:"text"`
	}
	VulnFullDescription struct {
		Text string `json:"text"`
	}
	VulnHelp struct {
		Text string `json:"text"`
	}
	VulnProperties struct {
		Tags []string `json:"tags"`
	}
	VulnRules struct {
		ID               string               `json:"id"`
		ShortDescription VulnShortDescription `json:"shortDescription"`
		FullDescription  VulnFullDescription  `json:"fullDescription"`
		Help             VulnHelp             `json:"help"`
		HelpURI          string               `json:"helpUri"`
		Properties       VulnProperties       `json:"properties"`
	}
	VulnDriver struct {
		Rules []VulnRules `json:"rules"`
	}
	VulnTool struct {
		Driver VulnDriver `json:"driver"`
	}
	VulnMessage struct {
		Text string `json:"text"`
	}
	VulnArtifactLocation struct {
		URI       string `json:"uri"`
		URIBaseID string `json:"uriBaseId"`
	}
	VulnRegion struct {
		StartLine int `json:"startLine"`
	}
	VulnPhysicalLocation struct {
		ArtifactLocation VulnArtifactLocation `json:"artifactLocation"`
		Region           VulnRegion           `json:"region"`
	}
	VulnLocations struct {
		PhysicalLocation VulnPhysicalLocation `json:"physicalLocation"`
		Message          VulnMessage          `json:"message"`
	}

	VulnRegion0 struct {
		StartLine   int `json:"startLine"`
		StartColumn int `json:"startColumn"`
	}
	VulnPhysicalLocation0 struct {
		ArtifactLocation VulnArtifactLocation `json:"artifactLocation"`
		Region           VulnRegion0          `json:"region"`
	}

	VulnLocation struct {
		PhysicalLocation VulnPhysicalLocation0 `json:"physicalLocation"`
		Message          VulnMessage           `json:"message"`
	}
	VulnLocations0 struct {
		Module   string       `json:"module"`
		Location VulnLocation `json:"location"`
	}
	VulnThreadFlows struct {
		Locations []VulnLocations0 `json:"locations"`
	}

	VulnCodeFlows struct {
		ThreadFlows []VulnThreadFlows `json:"threadFlows"`
		Message     VulnMessage       `json:"message"`
	}
	VulnMessage3 struct {
		Text string `json:"text"`
	}

	VulnLocation0 struct {
		PhysicalLocation VulnPhysicalLocation0 `json:"physicalLocation"`
		Message          VulnMessage           `json:"message"`
	}
	VulnFrames struct {
		Module   string        `json:"module"`
		Location VulnLocation0 `json:"location"`
	}
	VulnStacks struct {
		Message VulnMessage3 `json:"message"`
		Frames  []VulnFrames `json:"frames"`
	}
	VulnResults struct {
		RuleID    string          `json:"ruleId"`
		Level     string          `json:"level"`
		Message   VulnMessage     `json:"message"`
		Locations []VulnLocations `json:"locations"`
		CodeFlows []VulnCodeFlows `json:"codeFlows"`
		Stacks    []VulnStacks    `json:"stacks"`
	}
	VulnRuns struct {
		Tool    VulnTool      `json:"tool"`
		Results []VulnResults `json:"results"`
	}

	// cve
	CveDetail struct {
		Containers  Containers  `json:"containers"`
		CveMetadata CveMetadata `json:"cveMetadata"`
		DataType    string      `json:"dataType"`
		DataVersion string      `json:"dataVersion"`
	}
	Versions struct {
		Status  string `json:"status"`
		Version string `json:"version"`
	}
	Affected struct {
		Product  string     `json:"product"`
		Vendor   string     `json:"vendor"`
		Versions []Versions `json:"versions"`
	}
	Descriptions struct {
		Lang  string `json:"lang"`
		Value string `json:"value"`
	}
	CvssV31 struct {
		AttackComplexity      string  `json:"attackComplexity"`
		AttackVector          string  `json:"attackVector"`
		AvailabilityImpact    string  `json:"availabilityImpact"`
		BaseScore             float64 `json:"baseScore"`
		BaseSeverity          string  `json:"baseSeverity"`
		ConfidentialityImpact string  `json:"confidentialityImpact"`
		IntegrityImpact       string  `json:"integrityImpact"`
		PrivilegesRequired    string  `json:"privilegesRequired"`
		Scope                 string  `json:"scope"`
		UserInteraction       string  `json:"userInteraction"`
		VectorString          string  `json:"vectorString"`
		Version               string  `json:"version"`
	}
	Metrics struct {
		CvssV31 CvssV31 `json:"cvssV3_1"`
	}
	Descriptions0 struct {
		Description string `json:"description"`
		Lang        string `json:"lang"`
		Type        string `json:"type"`
	}
	ProblemTypes struct {
		Descriptions []Descriptions0 `json:"descriptions"`
	}
	ProviderMetadata struct {
		DateUpdated string `json:"dateUpdated"`
		OrgID       string `json:"orgId"`
		ShortName   string `json:"shortName"`
	}
	References struct {
		Tags []string `json:"tags"`
		URL  string   `json:"url"`
	}
	CVEDataMeta struct {
		ASSIGNER string `json:"ASSIGNER"`
		ID       string `json:"ID"`
		STATE    string `json:"STATE"`
	}
	VersionData struct {
		VersionValue string `json:"version_value"`
	}
	Version struct {
		VersionData []VersionData `json:"version_data"`
	}
	ProductData struct {
		ProductName string  `json:"product_name"`
		Version     Version `json:"version"`
	}
	Product struct {
		ProductData []ProductData `json:"product_data"`
	}
	VendorData struct {
		Product    Product `json:"product"`
		VendorName string  `json:"vendor_name"`
	}
	Vendor struct {
		VendorData []VendorData `json:"vendor_data"`
	}
	Affects struct {
		Vendor Vendor `json:"vendor"`
	}
	DescriptionData struct {
		Lang  string `json:"lang"`
		Value string `json:"value"`
	}
	Description struct {
		DescriptionData []DescriptionData `json:"description_data"`
	}
	Cvss struct {
		AttackComplexity      string `json:"attackComplexity"`
		AttackVector          string `json:"attackVector"`
		AvailabilityImpact    string `json:"availabilityImpact"`
		ConfidentialityImpact string `json:"confidentialityImpact"`
		IntegrityImpact       string `json:"integrityImpact"`
		PrivilegesRequired    string `json:"privilegesRequired"`
		Scope                 string `json:"scope"`
		UserInteraction       string `json:"userInteraction"`
		VectorString          string `json:"vectorString"`
		Version               string `json:"version"`
	}
	Impact struct {
		Cvss Cvss `json:"cvss"`
	}
	Description0 struct {
		Lang  string `json:"lang"`
		Value string `json:"value"`
	}
	ProblemtypeData struct {
		Description []Description0 `json:"description"`
	}
	Problemtype struct {
		ProblemtypeData []ProblemtypeData `json:"problemtype_data"`
	}
	ReferenceData struct {
		Name      string `json:"name"`
		Refsource string `json:"refsource"`
		URL       string `json:"url"`
	}
	References0 struct {
		ReferenceData []ReferenceData `json:"reference_data"`
	}
	XLegacyV4Record struct {
		CVEDataMeta CVEDataMeta `json:"CVE_data_meta"`
		Affects     Affects     `json:"affects"`
		DataFormat  string      `json:"data_format"`
		DataType    string      `json:"data_type"`
		DataVersion string      `json:"data_version"`
		Description Description `json:"description"`
		Impact      Impact      `json:"impact"`
		Problemtype Problemtype `json:"problemtype"`
		References  References0 `json:"references"`
	}
	Cna struct {
		Affected         []Affected       `json:"affected"`
		Descriptions     []Descriptions   `json:"descriptions"`
		Metrics          []Metrics        `json:"metrics"`
		ProblemTypes     []ProblemTypes   `json:"problemTypes"`
		ProviderMetadata ProviderMetadata `json:"providerMetadata"`
		References       []References     `json:"references"`
		XLegacyV4Record  XLegacyV4Record  `json:"x_legacyV4Record"`
	}
	ProviderMetadata0 struct {
		OrgID       string    `json:"orgId"`
		ShortName   string    `json:"shortName"`
		DateUpdated time.Time `json:"dateUpdated"`
	}
	References1 struct {
		Tags []string `json:"tags"`
		URL  string   `json:"url"`
	}
	Adp struct {
		ProviderMetadata ProviderMetadata0 `json:"providerMetadata"`
		Title            string            `json:"title"`
		References       []References1     `json:"references"`
		Metrics          []Metrics         `json:"metrics"`
	}
	Containers struct {
		Cna Cna   `json:"cna"`
		Adp []Adp `json:"adp"`
	}
	CveMetadata struct {
		AssignerOrgID     string    `json:"assignerOrgId"`
		AssignerShortName string    `json:"assignerShortName"`
		CveID             string    `json:"cveId"`
		DatePublished     string    `json:"datePublished"`
		DateReserved      string    `json:"dateReserved"`
		DateUpdated       time.Time `json:"dateUpdated"`
		State             string    `json:"state"`
	}
)

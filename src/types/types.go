package types

import (
	sbomTypes "github.com/CodeClarityCE/plugin-sbom-javascript/src/types/sbom/js"
	"github.com/CodeClarityCE/plugin-sca-patching/src/types/patching"
	vulnerabilityFinder "github.com/CodeClarityCE/plugin-sca-vuln-finder/src/types"
	semverVersionTypes "github.com/CodeClarityCE/utility-node-semver/versions"
)

type Dependency struct {
	Vulnerable               bool                            `json:"vulnerable"`
	UpgradeToInstalledVer    bool                            `json:"upgrade_to_installed_ver"`
	UpgradeTo                string                          `json:"upgrade_to"`
	OriginalConstraint       string                          `json:"original_constraint"`
	PotentialBreakingChanges bool                            `json:"potential_breaking_changes"`
	PatchType                patching.PatchType              `json:"patch_type"`
	SeverityDist             patching.SeverityDist           `json:"severity_dist,omitempty"`
	AfterUpgradeSeverityDist patching.SeverityDist           `json:"after_upgrade_severity_dist,omitempty"`
	FullPatch                FullyPatchedVersionInternal     `json:"full_patch,omitempty"`
	PartialPatch             PartiallyPatchedVersionInternal `json:"partial_patch,omitempty"`
	NonePatch                UnPatchedVersionInternal        `json:"none_patch,omitempty"`
}

type VulnerabilityComparisonInfo struct {
	Paths                   [][]string
	PathStrings             []string
	PathsWithVersion        [][]string
	PathsStringsWithVersion []string
	VulnerabilityInternal   vulnerabilityFinder.VulnerabilityMatch
}

type FullyPatchedVersionInternal struct {
	DirectDependency       sbomTypes.Versions
	UpgradeTo              string
	PatchedVulnerabilities []vulnerabilityFinder.Vulnerability
	TransitiveVulnerable   bool
	DirectVulnerable       bool
	InstalledVersion       semverVersionTypes.Semver
	UpgradedVersion        semverVersionTypes.Semver
}

type PartiallyPatchedVersionInternal struct {
	DirectDependency          sbomTypes.Versions
	UpgradeTo                 string
	PatchedVulnerabilities    []vulnerabilityFinder.Vulnerability
	UnPatchedVulnerabilities  []vulnerabilityFinder.Vulnerability
	IntroducedVulnerabilities []vulnerabilityFinder.Vulnerability
	TransitiveVulnerable      bool
	DirectVulnerable          bool
	InstalledVersion          semverVersionTypes.Semver
	UpgradedVersion           semverVersionTypes.Semver
}

type UnPatchedVersionInternal struct {
	DirectDependency         sbomTypes.Versions
	UnPatchedVulnerabilities []vulnerabilityFinder.Vulnerability
	TransitiveVulnerable     bool
	DirectVulnerable         bool
	InstalledVersion         semverVersionTypes.Semver
	UpgradedVersion          semverVersionTypes.Semver
}

type VersionSelectionPreference string

const (
	SELECT_NEWEST = "SELECT_NEWEST"
	SELECT_OLDEST = "SELECT_OLDEST"
)

type PartialFixVersionSelection string

const (
	SELECT_LOWEST_MAX_SEVERITY     = "SELECT_LOWEST_MAX_SEVERITY"
	SELECT_LOWEST_AVERAGE_SEVERITY = "SELECT_LOWEST_AVERAGE_SEVERITY"
)

type UpgradePolicy struct {
	AllowDowngrades            bool
	PartialFixVersionSelection PartialFixVersionSelection
	VersionSelectionPreference VersionSelectionPreference
}

type VulnerabilityOccurencePatchInfo struct {
	PatchType                 patching.PatchType                `json:"patch_type"`
	DirectDepInstalledVersion string                            `json:"direct_dep_installed_version"`
	DirectDepUpgradeVersion   string                            `json:"direct_dep_upgrade_version"`
	DirectDepName             string                            `json:"direct_dep_name"`
	IntroducedOccurences      vulnerabilityFinder.Vulnerability `json:"introduced_occurences"`
	UnPatchedOccurences       vulnerabilityFinder.Vulnerability `json:"unpatched_occurences"`
	PatchedOccurences         vulnerabilityFinder.Vulnerability `json:"patched_occurences"`
}

type VulnerabilityPatchInfo struct {
	IntroductionType patching.IntroductionType                  `json:"introduction_type"`
	PatchType        patching.PatchType                         `json:"patch_type"`
	Patches          map[string]VulnerabilityOccurencePatchInfo `json:"potential_breaking_changes"`
}

type UpgradeWorkSpaceData struct {
	VulnerabilityPatchInfo    map[string]VulnerabilityPatchInfo
	FullyPatchedVersion       map[string]FullyPatchedVersionInternal
	PartiallyPatchedVersions  map[string]PartiallyPatchedVersionInternal
	UnpatchedVersions         map[string]UnPatchedVersionInternal
	IntroducedVulnerabilities []vulnerabilityFinder.Vulnerability
	UnPatchedVulnerabilities  []vulnerabilityFinder.Vulnerability
	PatchedVulnerabilities    []vulnerabilityFinder.Vulnerability
	VulnDirectDepMap          map[string]map[string]VulnerabilityComparisonInfo
}

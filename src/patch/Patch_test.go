package patch

import (
	"encoding/json"
	"testing"

	"github.com/CodeClarityCE/plugin-sca-patching/src/types/patching"
	vulnerabilityFinder "github.com/CodeClarityCE/plugin-sca-vuln-finder/src/types"
	"github.com/CodeClarityCE/utility-node-semver/versions"
	knowledge "github.com/CodeClarityCE/utility-types/knowledge_db"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func directPatcher(dependency string) Patcher {
	return Patcher{patching_info: map[string]patching.PatchInfo{
		dependency: {Patches: map[string]versions.Semver{}},
	}}
}

func rangeEvidence(fixed versions.Semver) (vulnerabilityFinder.VulnerableEvidenceType, vulnerabilityFinder.VulnerableEvidenceRange) {
	return vulnerabilityFinder.VULNERABLE_EVIDENCE_RANGE, vulnerabilityFinder.VulnerableEvidenceRange{
		Vulnerable: vulnerabilityFinder.AffectedRange{FixedSemver: fixed},
	}
}

func TestDirectVulnerabilityWithOnlyAnOSVMatchUsesItsFix(t *testing.T) {
	fixed := versions.Semver{Major: 1, Minor: 2, Patch: 3}
	evidenceType, evidence := rangeEvidence(fixed)
	toPatch := newToPatch(vulnerabilityFinder.Vulnerability{
		OSVMatch: &vulnerabilityFinder.OSVVulnerability{VulnerableEvidenceType: evidenceType, VulnerableEvidenceRange: evidence},
	}, nil)
	patcher := directPatcher("pkg@1.0.0")

	patcher.patchDirectDependencyVulnerable("pkg@1.0.0", toPatch)

	patch := patcher.patching_info["pkg@1.0.0"]
	assert.Equal(t, "FULL", patch.IsPatchable)
	assert.Equal(t, fixed, patch.Update)
}

func TestDirectVulnerabilityWithoutUsableEvidenceIsNotPatchable(t *testing.T) {
	cases := map[string]vulnerabilityFinder.Vulnerability{
		"no matches": {},
		"exact NVD match": {NVDMatch: &vulnerabilityFinder.NVDVulnerability{
			VulnerableEvidenceType: vulnerabilityFinder.VULNERABLE_EVIDENCE_EXACT,
		}},
		"range without a fix": {NVDMatch: &vulnerabilityFinder.NVDVulnerability{
			VulnerableEvidenceType:  vulnerabilityFinder.VULNERABLE_EVIDENCE_RANGE,
			VulnerableEvidenceRange: vulnerabilityFinder.VulnerableEvidenceRange{OpenEnd: true},
		}},
	}
	for name, vulnerability := range cases {
		t.Run(name, func(t *testing.T) {
			patcher := directPatcher("pkg@1.0.0")

			assert.NotPanics(t, func() {
				patcher.patchDirectDependencyVulnerable("pkg@1.0.0", newToPatch(vulnerability, nil))
			})

			patch := patcher.patching_info["pkg@1.0.0"]
			assert.Equal(t, "NONE", patch.IsPatchable)
			assert.Len(t, patch.Unpatchable, 1)
		})
	}
}

func occurrence(name, version string, fix *versions.Semver) patching.ToPatch {
	return patching.ToPatch{DependencyName: name, DependencyVersion: version, AdvisoryFix: fix}
}

func TestTransitiveOccurrenceGetsTheVersionResolvedUnderTheUpgrade(t *testing.T) {
	advisoryFix := versions.Semver{Major: 1, Minor: 18, Patch: 3}
	patches := fixedVersions([]patching.ToPatch{occurrence("body-parser", "1.18.2", &advisoryFix)}, nil,
		map[string]string{"express": "4.17.3", "body-parser": "1.19.2"})

	assert.Equal(t, map[string]versions.Semver{"body-parser@1.18.2": {Major: 1, Minor: 19, Patch: 2}}, patches)
}

func TestOccurrenceOutsideTheResolvedTreeGetsTheAdvisoryFix(t *testing.T) {
	advisoryFix := versions.Semver{Major: 2, Minor: 0, Patch: 1}
	patches := fixedVersions([]patching.ToPatch{
		occurrence("deep", "1.0.0", &advisoryFix),
		occurrence("same", "1.0.0", &advisoryFix),
		occurrence("unknown", "1.0.0", nil),
	}, nil, map[string]string{"same": "1.0.0"})

	assert.Equal(t, map[string]versions.Semver{"deep@1.0.0": advisoryFix, "same@1.0.0": advisoryFix}, patches,
		"no key when no fix is known, and an unchanged version is not a fix")
}

func TestSeveralAdvisoriesOnOnePackageVersionKeepTheHighestFix(t *testing.T) {
	low := versions.Semver{Major: 1, Minor: 2, Patch: 0}
	high := versions.Semver{Major: 1, Minor: 4, Patch: 1}

	for name, order := range map[string][]*versions.Semver{"low first": {&low, &high}, "high first": {&high, &low}} {
		t.Run(name, func(t *testing.T) {
			patches := fixedVersions(nil, []patching.ToPatch{
				occurrence("pkg", "1.0.0", order[0]),
				occurrence("pkg", "1.0.0", order[1]),
			}, nil)

			assert.Equal(t, map[string]versions.Semver{"pkg@1.0.0": high}, patches)
		})
	}
}

func TestAdvisoryFixNeverReplacesTheResolvedVersion(t *testing.T) {
	advisoryFix := versions.Semver{Major: 3, Minor: 0, Patch: 0}
	resolved := map[string]string{"pkg": "2.1.0"}
	// Two advisories hit pkg@1.0.0: the upgrade ends one, the other stays.
	patchable := []patching.ToPatch{occurrence("pkg", "1.0.0", &versions.Semver{Major: 2, Minor: 0, Patch: 0})}
	unpatchable := []patching.ToPatch{occurrence("pkg", "1.0.0", &advisoryFix)}

	patches := fixedVersions(patchable, unpatchable, resolved)

	assert.Equal(t, map[string]versions.Semver{"pkg@1.0.0": {Major: 2, Minor: 1, Patch: 0}}, patches)
}

func TestResolvedVersionsKeepsScopedNames(t *testing.T) {
	assert.Equal(t, map[string]string{"@babel/core": "7.1.0", "lodash": "4.17.21"},
		resolvedVersions([]string{"@babel/core@7.1.0", "lodash@4.17.21"}))
}

func TestOccurrenceStoresOnlyTheVulnerabilityFieldsReadersUse(t *testing.T) {
	full := vulnerabilityFinder.Vulnerability{
		VulnerabilityId:    "CVE-2024-0001",
		AffectedDependency: "pkg",
		AffectedVersion:    "1.0.0",
		Sources:            []vulnerabilityFinder.VulnerabilitySource{vulnerabilityFinder.NVD},
		NVDMatch:           &vulnerabilityFinder.NVDVulnerability{},
		OSVMatch:           &vulnerabilityFinder.OSVVulnerability{},
		Weaknesses:         []vulnerabilityFinder.VulnerabilityMatchWeakness{{WeaknessId: "CWE-79"}},
		Severity: vulnerabilityFinder.VulnerabilityMatchSeverity{
			Severity: 9.8, ConfidentialityImpact: "HIGH", IntegrityImpact: "HIGH", AvailabilityImpact: "NONE",
		},
	}

	data, err := json.Marshal(newToPatch(full, []string{"pkg@1.0.0"}))
	require.NoError(t, err)

	var decoded map[string]any
	require.NoError(t, json.Unmarshal(data, &decoded))
	vulnerability := decoded["Vulnerability"].(map[string]any)
	for _, gone := range []string{"Sources", "NVDMatch", "OSVMatch", "Weaknesses"} {
		assert.NotContains(t, vulnerability, gone)
	}
	assert.Equal(t, "CVE-2024-0001", vulnerability["VulnerabilityId"])
	severity := vulnerability["Severity"].(map[string]any)
	assert.Equal(t, 9.8, severity["Severity"])
	assert.Equal(t, "HIGH", severity["ConfidentialityImpact"])
	assert.NotContains(t, decoded, "AdvisoryFix")
}

func TestIntroducedVulnerabilityCarriesItsNVDSeverity(t *testing.T) {
	item := knowledge.NVDItem{NVDId: "CVE-2024-0002"}
	item.Metrics.CvssMetricV31 = []knowledge.ImpactMetricV31{{}}
	item.Metrics.CvssMetricV31[0].CvssData.BaseScore = 7.5
	item.Metrics.CvssMetricV31[0].CvssData.AvailabilityImpact = "HIGH"

	introduced := convertNVDItemsToPatchItems([]knowledge.NVDItem{item}, "pkg", "2.0.0")

	require.Len(t, introduced, 1)
	assert.Equal(t, 7.5, introduced[0].Vulnerability.Severity.Severity)
	assert.Equal(t, "HIGH", introduced[0].Vulnerability.Severity.AvailabilityImpact)
}

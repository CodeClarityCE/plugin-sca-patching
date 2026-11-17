package patch

import (
	"encoding/json"
	"testing"

	"github.com/CodeClarityCE/plugin-sca-patching/src/types/patching"
	vulnerabilityFinder "github.com/CodeClarityCE/plugin-sca-vuln-finder/src/types"
	"github.com/CodeClarityCE/utility-node-semver/versions"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

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

package patch

import (
	"testing"

	"github.com/CodeClarityCE/plugin-sca-patching/src/types/patching"
	vulnerabilityFinder "github.com/CodeClarityCE/plugin-sca-vuln-finder/src/types"
	"github.com/CodeClarityCE/utility-node-semver/versions"
	"github.com/stretchr/testify/assert"
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
	toPatch := patching.ToPatch{Vulnerability: vulnerabilityFinder.Vulnerability{
		OSVMatch: &vulnerabilityFinder.OSVVulnerability{VulnerableEvidenceType: evidenceType, VulnerableEvidenceRange: evidence},
	}}
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
				patcher.patchDirectDependencyVulnerable("pkg@1.0.0", patching.ToPatch{Vulnerability: vulnerability})
			})

			patch := patcher.patching_info["pkg@1.0.0"]
			assert.Equal(t, "NONE", patch.IsPatchable)
			assert.Len(t, patch.Unpatchable, 1)
		})
	}
}

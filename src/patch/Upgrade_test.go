package patch

import (
	"errors"
	"testing"

	sbomTypes "github.com/CodeClarityCE/plugin-sbom-javascript/src/types/sbom/js"
	"github.com/CodeClarityCE/plugin-sca-patching/src/types/patching"
	vulnerabilityFinder "github.com/CodeClarityCE/plugin-sca-vuln-finder/src/types"
	knowledge_db "github.com/CodeClarityCE/utility-types/knowledge_db"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakeRegistry serves versions and dependency constraints from maps.
type fakeRegistry struct {
	versions     map[string][]string
	dependencies map[string]map[string]string // "name@version" -> constraints
	failing      map[string]bool              // "name@version" whose dependencies cannot be read
}

func (f fakeRegistry) Versions(name string) ([]string, error) { return f.versions[name], nil }

func (f fakeRegistry) Dependencies(name, version string) (map[string]string, error) {
	if f.failing[name+"@"+version] {
		return nil, errors.New("i/o timeout")
	}
	return f.dependencies[name+"@"+version], nil
}

// fakeAdvisories serves OSV and NVD records by package; GCVE is always empty.
type fakeAdvisories struct {
	osv map[string][]knowledge_db.OSVItem // purl -> records
	nvd map[string][]knowledge_db.NVDItem // product -> records
}

func (f fakeAdvisories) OSV(purl string) ([]knowledge_db.OSVItem, error) { return f.osv[purl], nil }
func (f fakeAdvisories) NVD(product string) ([]knowledge_db.NVDItem, error) {
	return f.nvd[product], nil
}
func (f fakeAdvisories) GCVE(string) ([]knowledge_db.GCVEItem, error) { return nil, nil }

// osvAdvisory affects name from introduced up to, not including, fixed.
func osvAdvisory(id, name, introduced, fixed string, aliases ...string) knowledge_db.OSVItem {
	return knowledge_db.OSVItem{
		OSVId:   id,
		Aliases: aliases,
		Affected: []knowledge_db.Affected{{
			Package: knowledge_db.OSVPackage{Name: name, Ecosystem: "npm"},
			Ranges: []knowledge_db.Range{{Type: "SEMVER", Events: []knowledge_db.Event{
				{Introduced: introduced}, {Fixed: fixed},
			}}},
		}},
	}
}

func testPatcher(registry fakeRegistry, advisories fakeAdvisories) Patcher {
	return newPatcher(registry, nil, advisories, sbomTypes.Output{}, vulnerabilityFinder.Output{})
}

func installed(name, version, id string) patching.ToPatch {
	return newToPatch(vulnerabilityFinder.Vulnerability{VulnerabilityId: id, AffectedDependency: name, AffectedVersion: version}, []string{name + "@" + version})
}

func TestVersionOnlyOSVFlagsIsNeverChosen(t *testing.T) {
	// NVD knows nothing about 1.0.1, but OSV says it is still vulnerable.
	advisories := fakeAdvisories{osv: map[string][]knowledge_db.OSVItem{
		"pkg:npm/pkg": {osvAdvisory("GHSA-osv1-only-aaaa", "pkg", "0", "1.0.2")},
	}}
	registry := fakeRegistry{versions: map[string][]string{"pkg": {"1.0.0", "1.0.1", "1.0.2"}}}

	patches := testPatcher(registry, advisories).PatchDependencies(map[string][]patching.ToPatch{
		"pkg@1.0.0": {installed("pkg", "1.0.0", "GHSA-osv1-only-aaaa")},
	})

	patch := patches["pkg@1.0.0"]
	assert.Equal(t, "FULL", patch.IsPatchable)
	assert.Equal(t, "1.0.2", patch.Update.String())
	assert.False(t, patch.PotentiallyBreaking)
}

func TestSameMajorFixIsPreferredOverALaterMajor(t *testing.T) {
	advisories := fakeAdvisories{osv: map[string][]knowledge_db.OSVItem{
		"pkg:npm/axios": {osvAdvisory("GHSA-axio-0000-aaaa", "axios", "0", "0.21.1")},
	}}
	registry := fakeRegistry{versions: map[string][]string{"axios": {"0.18.0", "0.19.0", "0.21.1", "1.0.0"}}}

	patch := testPatcher(registry, advisories).PatchDependencies(map[string][]patching.ToPatch{
		"axios@0.18.0": {installed("axios", "0.18.0", "GHSA-axio-0000-aaaa")},
	})["axios@0.18.0"]

	assert.Equal(t, "FULL", patch.IsPatchable)
	assert.Equal(t, "0.21.1", patch.Update.String())
	assert.False(t, patch.PotentiallyBreaking)
}

func TestLaterMajorFixIsFlaggedAsPotentiallyBreaking(t *testing.T) {
	advisories := fakeAdvisories{osv: map[string][]knowledge_db.OSVItem{
		"pkg:npm/axios": {osvAdvisory("GHSA-axio-1111-aaaa", "axios", "0", "1.6.0")},
	}}
	registry := fakeRegistry{versions: map[string][]string{"axios": {"0.18.0", "0.27.2", "1.6.0", "1.7.0"}}}

	patch := testPatcher(registry, advisories).PatchDependencies(map[string][]patching.ToPatch{
		"axios@0.18.0": {installed("axios", "0.18.0", "GHSA-axio-1111-aaaa")},
	})["axios@0.18.0"]

	assert.Equal(t, "FULL", patch.IsPatchable)
	assert.Equal(t, "1.6.0", patch.Update.String())
	assert.True(t, patch.PotentiallyBreaking)
}

func TestVulnerableGrandchildMakesACandidateUnclean(t *testing.T) {
	// app 1.1.0 -> mid ^1.0.0 -> leaf 2.0.0 (vulnerable); app 1.2.0 -> mid 2.0.0 -> leaf 3.0.0.
	advisories := fakeAdvisories{osv: map[string][]knowledge_db.OSVItem{
		"pkg:npm/leaf": {osvAdvisory("GHSA-leaf-0000-aaaa", "leaf", "0", "3.0.0")},
	}}
	registry := fakeRegistry{
		versions: map[string][]string{"app": {"1.0.0", "1.1.0", "1.2.0"}, "mid": {"1.0.0", "2.0.0"}, "leaf": {"2.0.0", "3.0.0"}},
		dependencies: map[string]map[string]string{
			"app@1.1.0": {"mid": "^1.0.0"}, "app@1.2.0": {"mid": "2.0.0"},
			"mid@1.0.0": {"leaf": "2.0.0"}, "mid@2.0.0": {"leaf": "3.0.0"},
		},
	}

	patch := testPatcher(registry, advisories).PatchDependencies(map[string][]patching.ToPatch{
		"app@1.0.0": {installed("leaf", "2.0.0", "GHSA-leaf-0000-aaaa")},
	})["app@1.0.0"]

	assert.Equal(t, "FULL", patch.IsPatchable)
	assert.Equal(t, "1.2.0", patch.Update.String())
	assert.Equal(t, "3.0.0", patch.Patches["leaf@2.0.0"].String())
}

func TestCandidateWhoseLookupFailsIsSkipped(t *testing.T) {
	registry := fakeRegistry{
		versions: map[string][]string{"pkg": {"1.0.0", "1.0.1", "1.0.2"}},
		failing:  map[string]bool{"pkg@1.0.1": true},
	}

	patch := testPatcher(registry, fakeAdvisories{}).PatchDependencies(map[string][]patching.ToPatch{
		"pkg@1.0.0": {installed("pkg", "1.0.0", "CVE-2024-0001")},
	})["pkg@1.0.0"]

	assert.Equal(t, "1.0.2", patch.Update.String(), "1.0.1 could not be checked, so it is not taken as clean")
}

func TestEveryCandidateFailingIsAnError(t *testing.T) {
	registry := fakeRegistry{
		versions: map[string][]string{"pkg": {"1.0.0", "1.0.1"}},
		failing:  map[string]bool{"pkg@1.0.1": true},
	}

	_, _, err := testPatcher(registry, fakeAdvisories{}).chooseUpgrade("pkg", "1.0.0")

	assert.ErrorIs(t, err, errNoCandidateChecked)
}

func TestCVEInNVDAndGHSAInOSVAreOneInstance(t *testing.T) {
	// Installed today: vuln-finder grouped the NVD CVE and the OSV GHSA under the CVE.
	today := newToPatch(vulnerabilityFinder.Vulnerability{
		VulnerabilityId: "CVE-2024-1234", AffectedDependency: "pkg", AffectedVersion: "1.0.0",
		SourceMatches: []vulnerabilityFinder.SourceMatch{{Source: "nvd", RecordId: "CVE-2024-1234"}, {Source: "osv", RecordId: "GHSA-abcd-efgh-ijkl"}},
	}, nil)
	// Left after the upgrade: only the OSV record matched, without a CVE alias.
	after := newToPatch(vulnerabilityFinder.Vulnerability{
		VulnerabilityId: "GHSA-abcd-efgh-ijkl", AffectedDependency: "pkg", AffectedVersion: "1.0.0",
	}, nil)

	introduced, unpatchable, patchable := generatePatchingResult([]patching.ToPatch{after}, []patching.ToPatch{today})

	assert.Empty(t, introduced)
	assert.Empty(t, patchable)
	require.Len(t, unpatchable, 1)
	assert.Equal(t, "CVE-2024-1234", unpatchable[0].Vulnerability.VulnerabilityId)
}

func TestPartialUpgradeReportsWhatRemainsAndWhatIsNew(t *testing.T) {
	advisories := fakeAdvisories{osv: map[string][]knowledge_db.OSVItem{
		"pkg:npm/pkg": {osvAdvisory("GHSA-forever-aaaa", "pkg", "0", "9.0.0")},
		"pkg:npm/dep": {osvAdvisory("GHSA-dep-new-aaaa", "dep", "2.0.0", "9.0.0")},
		"pkg:npm/old": {osvAdvisory("GHSA-old-gone-aaa", "old", "0", "2.0.0")},
	}}
	registry := fakeRegistry{
		versions:     map[string][]string{"pkg": {"1.0.0", "1.1.0"}, "dep": {"2.0.0"}, "old": {"1.0.0", "2.0.0"}},
		dependencies: map[string]map[string]string{"pkg@1.1.0": {"dep": "2.0.0", "old": "2.0.0"}},
	}

	patch := testPatcher(registry, advisories).PatchDependencies(map[string][]patching.ToPatch{
		"pkg@1.0.0": {installed("pkg", "1.0.0", "GHSA-forever-aaaa"), installed("old", "1.0.0", "GHSA-old-gone-aaa")},
	})["pkg@1.0.0"]

	assert.Equal(t, "PARTIAL", patch.IsPatchable)
	require.Len(t, patch.Patchable, 1)
	assert.Equal(t, "old", patch.Patchable[0].DependencyName)
	assert.Equal(t, "2.0.0", patch.Patches["old@1.0.0"].String())
	require.Len(t, patch.Introduced, 1)
	assert.Equal(t, "GHSA-dep-new-aaaa", patch.Introduced[0].Vulnerability.VulnerabilityId)
}

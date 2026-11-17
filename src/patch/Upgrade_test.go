package patch

import (
	"context"
	"errors"
	"testing"
	"time"

	sbomTypes "github.com/CodeClarityCE/plugin-sbom-javascript/src/types/sbom/js"
	"github.com/CodeClarityCE/plugin-sca-patching/src/types/patching"
	vulnerabilityFinder "github.com/CodeClarityCE/plugin-sca-vuln-finder/src/types"
	semver "github.com/CodeClarityCE/utility-node-semver"
	"github.com/CodeClarityCE/utility-node-semver/versions"
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

// fakeAdvisories serves OSV records by package and fails every lookup with err; NVD and GCVE are empty.
type fakeAdvisories struct {
	osv map[string][]knowledge_db.OSVItem // purl -> records
	err error
}

func (f fakeAdvisories) OSV(_ context.Context, purl string) ([]knowledge_db.OSVItem, error) {
	return f.osv[purl], f.err
}
func (f fakeAdvisories) NVD(context.Context, string) ([]knowledge_db.NVDItem, error) {
	return nil, f.err
}
func (f fakeAdvisories) GCVE(context.Context, string) ([]knowledge_db.GCVEItem, error) {
	return nil, f.err
}

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

// osvExact affects exactly the given versions of name.
func osvExact(id, name string, versions ...string) knowledge_db.OSVItem {
	return knowledge_db.OSVItem{
		OSVId:    id,
		Affected: []knowledge_db.Affected{{Package: knowledge_db.OSVPackage{Name: name, Ecosystem: "npm"}, Versions: versions}},
	}
}

func testPatcher(registry fakeRegistry, advisories fakeAdvisories, options ...Options) Patcher {
	var opts Options
	if len(options) > 0 {
		opts = options[0]
	}
	return newPatcher(registry, nil, advisories, sbomTypes.Output{}, vulnerabilityFinder.Output{}, opts)
}

func patchOne(t *testing.T, patcher Patcher, dependency string, toPatch ...patching.ToPatch) patching.PatchInfo {
	t.Helper()
	patches, err := patcher.PatchDependencies(context.Background(), map[string][]patching.ToPatch{dependency: toPatch})
	require.NoError(t, err)
	return patches[dependency]
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

	patch := patchOne(t, testPatcher(registry, advisories), "pkg@1.0.0", installed("pkg", "1.0.0", "GHSA-osv1-only-aaaa"))

	assert.Equal(t, "FULL", patch.IsPatchable)
	assert.Equal(t, "1.0.2", patch.Update.String())
	assert.False(t, patch.PotentiallyBreaking)
}

func TestSameMajorFixIsPreferredOverALaterMajor(t *testing.T) {
	advisories := fakeAdvisories{osv: map[string][]knowledge_db.OSVItem{
		"pkg:npm/axios": {osvAdvisory("GHSA-axio-0000-aaaa", "axios", "0", "1.6.0")},
	}}
	registry := fakeRegistry{versions: map[string][]string{"axios": {"1.5.0", "1.5.1", "1.6.0", "2.0.0"}}}

	patch := patchOne(t, testPatcher(registry, advisories), "axios@1.5.0", installed("axios", "1.5.0", "GHSA-axio-0000-aaaa"))

	assert.Equal(t, "FULL", patch.IsPatchable)
	assert.Equal(t, "1.6.0", patch.Update.String())
	assert.False(t, patch.PotentiallyBreaking)
}

func TestLaterMajorFixIsFlaggedAsPotentiallyBreaking(t *testing.T) {
	advisories := fakeAdvisories{osv: map[string][]knowledge_db.OSVItem{
		"pkg:npm/axios": {osvAdvisory("GHSA-axio-1111-aaaa", "axios", "0", "2.1.0")},
	}}
	registry := fakeRegistry{versions: map[string][]string{"axios": {"1.5.0", "1.9.0", "2.1.0", "2.2.0"}}}

	patch := patchOne(t, testPatcher(registry, advisories), "axios@1.5.0", installed("axios", "1.5.0", "GHSA-axio-1111-aaaa"))

	assert.Equal(t, "FULL", patch.IsPatchable)
	assert.Equal(t, "2.1.0", patch.Update.String())
	assert.True(t, patch.PotentiallyBreaking)
}

func TestMinorBumpOfAZeroMajorIsPotentiallyBreaking(t *testing.T) {
	// npm's ^0.18.0 allows only 0.18.x, so 0.18 to 0.30 can break like a major bump.
	advisories := fakeAdvisories{osv: map[string][]knowledge_db.OSVItem{
		"pkg:npm/axios": {osvAdvisory("GHSA-axio-2222-aaaa", "axios", "0", "0.30.0")},
	}}
	registry := fakeRegistry{versions: map[string][]string{"axios": {"0.18.0", "0.18.1", "0.30.0", "1.0.0"}}}

	patch := patchOne(t, testPatcher(registry, advisories), "axios@0.18.0", installed("axios", "0.18.0", "GHSA-axio-2222-aaaa"))

	assert.Equal(t, "0.30.0", patch.Update.String())
	assert.True(t, patch.PotentiallyBreaking)
}

func TestCaretCompatible(t *testing.T) {
	cases := []struct {
		installed, candidate string
		want                 bool
	}{
		{"1.2.3", "1.9.0", true},
		{"1.2.3", "2.0.0", false},
		{"0.18.0", "0.18.5", true},
		{"0.18.0", "0.30.0", false},
		{"0.0.3", "0.0.4", false},
	}
	for _, c := range cases {
		installed := mustSemver(t, c.installed)
		candidate := mustSemver(t, c.candidate)
		assert.Equal(t, c.want, caretCompatible(installed, candidate), "%s -> %s", c.installed, c.candidate)
	}
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

	patch := patchOne(t, testPatcher(registry, advisories), "app@1.0.0", installed("leaf", "2.0.0", "GHSA-leaf-0000-aaaa"))

	assert.Equal(t, "FULL", patch.IsPatchable)
	assert.Equal(t, "1.2.0", patch.Update.String())
	assert.Equal(t, "3.0.0", patch.Patches["leaf@2.0.0"].String())
}

func TestUncheckedSubtreeRanksBelowAFullyCheckedCandidate(t *testing.T) {
	// 1.0.1 pulls in a git dependency and an unknown package, so part of its tree is never checked.
	registry := fakeRegistry{
		versions: map[string][]string{"pkg": {"1.0.0", "1.0.1", "1.0.2"}},
		dependencies: map[string]map[string]string{
			"pkg@1.0.1": {"forked": "git+https://example.com/forked.git", "gone": "^1.0.0"},
		},
	}

	patch := patchOne(t, testPatcher(registry, fakeAdvisories{}), "pkg@1.0.0", installed("pkg", "1.0.0", "CVE-2024-0001"))

	assert.Equal(t, "1.0.2", patch.Update.String())
}

func TestCleanButPartlyUncheckedBeatsAVulnerableCandidate(t *testing.T) {
	// 1.0.1 is fully checked and still vulnerable; 1.0.2 is clean but pulls in an unknown package.
	advisories := fakeAdvisories{osv: map[string][]knowledge_db.OSVItem{
		"pkg:npm/pkg": {osvAdvisory("GHSA-pkgg-0000-aaaa", "pkg", "0", "1.0.2")},
	}}
	registry := fakeRegistry{
		versions:     map[string][]string{"pkg": {"1.0.0", "1.0.1", "1.0.2"}},
		dependencies: map[string]map[string]string{"pkg@1.0.2": {"gone": "^1.0.0"}},
	}

	patch := patchOne(t, testPatcher(registry, advisories), "pkg@1.0.0", installed("pkg", "1.0.0", "GHSA-pkgg-0000-aaaa"))

	assert.Equal(t, "FULL", patch.IsPatchable)
	assert.Equal(t, "1.0.2", patch.Update.String())
}

func TestResolveTreeCountsWhatItCannotFollow(t *testing.T) {
	registry := fakeRegistry{
		versions: map[string][]string{"pkg": {"1.0.0"}, "old": {"1.0.0"}},
		dependencies: map[string]map[string]string{"pkg@1.0.0": {
			"forked": "github:user/forked", "gone": "^1.0.0", "old": "^2.0.0", "local": "file:../local",
		}},
	}

	tree, err := resolveTree(registry, "pkg", "1.0.0")

	require.NoError(t, err)
	assert.Equal(t, 4, tree.unchecked)
	assert.Equal(t, map[string][]string{"pkg": {"1.0.0"}}, tree.versions)
}

func TestNoCleanCandidatePrefersOneThatEndsAnInstalledVulnerability(t *testing.T) {
	// 1.1.0 keeps the installed vulnerability; 2.0.0 ends it but brings two new ones.
	advisories := fakeAdvisories{osv: map[string][]knowledge_db.OSVItem{
		"pkg:npm/pkg": {
			osvExact("GHSA-inst-aaaa-aaaa", "pkg", "1.0.0", "1.1.0"),
			osvExact("GHSA-newa-aaaa-aaaa", "pkg", "2.0.0"),
			osvExact("GHSA-newb-aaaa-aaaa", "pkg", "2.0.0"),
		},
	}}
	registry := fakeRegistry{versions: map[string][]string{"pkg": {"1.0.0", "1.1.0", "2.0.0"}}}

	patch := patchOne(t, testPatcher(registry, advisories), "pkg@1.0.0", installed("pkg", "1.0.0", "GHSA-inst-aaaa-aaaa"))

	assert.Equal(t, "PARTIAL", patch.IsPatchable)
	assert.Equal(t, "2.0.0", patch.Update.String())
	assert.True(t, patch.PotentiallyBreaking)
}

func TestNoCleanCandidatePrefersTheCompatibleRangeOverFewerLeft(t *testing.T) {
	// Both end the installed vulnerability; 1.1.0 leaves two, 2.0.0 leaves one.
	advisories := fakeAdvisories{osv: map[string][]knowledge_db.OSVItem{
		"pkg:npm/pkg": {
			osvExact("GHSA-inst-aaaa-aaaa", "pkg", "1.0.0"),
			osvExact("GHSA-left-aaaa-aaaa", "pkg", "1.1.0", "2.0.0"),
			osvExact("GHSA-left-bbbb-aaaa", "pkg", "1.1.0"),
		},
	}}
	registry := fakeRegistry{versions: map[string][]string{"pkg": {"1.0.0", "1.1.0", "2.0.0"}}}

	patch := patchOne(t, testPatcher(registry, advisories), "pkg@1.0.0", installed("pkg", "1.0.0", "GHSA-inst-aaaa-aaaa"))

	assert.Equal(t, "1.1.0", patch.Update.String())
	assert.False(t, patch.PotentiallyBreaking)
}

func TestPackageAtSeveralVersionsGivesTheSameResultEveryRun(t *testing.T) {
	// app 1.1.0 pulls leaf in at 1.5.0 (through a) and 2.0.0 (through b).
	advisories := fakeAdvisories{osv: map[string][]knowledge_db.OSVItem{
		"pkg:npm/leaf": {osvAdvisory("GHSA-leaf-1111-aaaa", "leaf", "0", "1.5.0")},
	}}
	registry := fakeRegistry{
		versions: map[string][]string{"app": {"1.0.0", "1.1.0"}, "a": {"1.0.0"}, "b": {"1.0.0"}, "leaf": {"1.0.0", "1.5.0", "2.0.0"}},
		dependencies: map[string]map[string]string{
			"app@1.1.0": {"a": "1.0.0", "b": "1.0.0"},
			"a@1.0.0":   {"leaf": "~1.5.0"},
			"b@1.0.0":   {"leaf": "2.0.0"},
		},
	}

	for range 50 {
		patch := patchOne(t, testPatcher(registry, advisories), "app@1.0.0", installed("leaf", "1.0.0", "GHSA-leaf-1111-aaaa"))

		require.Equal(t, "1.1.0", patch.Update.String())
		require.Equal(t, "2.0.0", patch.Patches["leaf@1.0.0"].String(), "the highest version of leaf in the tree")
	}
}

func TestNonSemverDirectDependencyIsNotPatchable(t *testing.T) {
	registry := fakeRegistry{versions: map[string][]string{"pkg": {"1.0.0", "2.0.0"}}}
	toPatch := installed("pkg", "github:user/pkg", "CVE-2024-0001")

	patch := patchOne(t, testPatcher(registry, fakeAdvisories{}), "pkg@github:user/pkg", toPatch)

	assert.Equal(t, "NONE", patch.IsPatchable)
	assert.Len(t, patch.Unpatchable, 1)
}

func TestKnowledgeLookupFailureFailsTheRun(t *testing.T) {
	registry := fakeRegistry{versions: map[string][]string{"pkg": {"1.0.0", "1.0.1"}}}
	cause := errors.New("dial tcp pgbouncer:6432: connect: connection refused")

	_, err := testPatcher(registry, fakeAdvisories{err: cause}).PatchDependencies(context.Background(),
		map[string][]patching.ToPatch{"pkg@1.0.0": {installed("pkg", "1.0.0", "CVE-2024-0001")}})

	assert.ErrorIs(t, err, ErrKnowledgeLookup)
	assert.ErrorIs(t, err, cause)
}

func TestRegistryFailureFailsTheRun(t *testing.T) {
	registry := fakeRegistry{
		versions: map[string][]string{"pkg": {"1.0.0", "1.0.1", "1.0.2"}},
		failing:  map[string]bool{"pkg@1.0.1": true},
	}

	_, err := testPatcher(registry, fakeAdvisories{}).PatchDependencies(context.Background(),
		map[string][]patching.ToPatch{"pkg@1.0.0": {installed("pkg", "1.0.0", "CVE-2024-0001")}})

	assert.ErrorIs(t, err, ErrKnowledgeLookup)
}

func TestAdvisoryPublishedAfterTheKnowledgeDateIsIgnored(t *testing.T) {
	later := osvAdvisory("GHSA-late-aaaa-aaaa", "pkg", "1.0.1", "1.0.2")
	later.Published = "2025-06-01T00:00:00Z"
	advisories := fakeAdvisories{osv: map[string][]knowledge_db.OSVItem{"pkg:npm/pkg": {later}}}
	registry := fakeRegistry{versions: map[string][]string{"pkg": {"1.0.0", "1.0.1", "1.0.2"}}}
	asOf := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)

	withDate := patchOne(t, testPatcher(registry, advisories, Options{KnowledgeAsOf: &asOf}), "pkg@1.0.0", installed("pkg", "1.0.0", "CVE-2024-0001"))
	today := patchOne(t, testPatcher(registry, advisories), "pkg@1.0.0", installed("pkg", "1.0.0", "CVE-2024-0001"))

	assert.Equal(t, "1.0.1", withDate.Update.String())
	assert.Empty(t, withDate.Introduced)
	assert.Equal(t, "1.0.2", today.Update.String())
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

	patch := patchOne(t, testPatcher(registry, advisories), "pkg@1.0.0",
		installed("pkg", "1.0.0", "GHSA-forever-aaaa"), installed("old", "1.0.0", "GHSA-old-gone-aaa"))

	assert.Equal(t, "PARTIAL", patch.IsPatchable)
	require.Len(t, patch.Patchable, 1)
	assert.Equal(t, "old", patch.Patchable[0].DependencyName)
	assert.Equal(t, "2.0.0", patch.Patches["old@1.0.0"].String())
	require.Len(t, patch.Introduced, 1)
	assert.Equal(t, "GHSA-dep-new-aaaa", patch.Introduced[0].Vulnerability.VulnerabilityId)
}

func mustSemver(t *testing.T, version string) versions.Semver {
	t.Helper()
	parsed, err := semver.ParseSemver(version)
	require.NoError(t, err)
	return parsed
}

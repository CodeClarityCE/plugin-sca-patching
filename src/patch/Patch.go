package patch

import (
	"errors"
	"fmt"
	"log"
	"strings"

	"github.com/CodeClarityCE/plugin-sca-patching/src/types/patching"
	vulnerabilityFinder "github.com/CodeClarityCE/plugin-sca-vuln-finder/src/types"
	semver "github.com/CodeClarityCE/utility-node-semver"
	"github.com/CodeClarityCE/utility-node-semver/versions"
)

// errNoCandidateChecked means every later version of a dependency failed its knowledge lookups.
var errNoCandidateChecked = errors.New("no upgrade candidate could be checked")

// upgrade is the version chosen for a direct dependency and what it leaves behind.
type upgrade struct {
	version string
	// resolved is the version each package of the upgraded tree resolves to (name -> version).
	resolved map[string]string
	// remaining are the vulnerabilities still in the upgraded tree; empty for a full fix.
	remaining []vulnerabilityFinder.Vulnerability
	// breaking is true when the upgrade leaves the installed major version.
	breaking bool
}

func (patcher Patcher) PatchDependencies(dependenciesToPatch map[string][]patching.ToPatch) map[string]patching.PatchInfo {
	patcher.patching_info = make(map[string]patching.PatchInfo)

	// The vulnerability may be in the direct dependency itself or in one of its transitive dependencies.
	for dependency, toPatch := range dependenciesToPatch {
		patch := patching.PatchInfo{
			Unpatchable: []patching.ToPatch{},
			Patchable:   []patching.ToPatch{},
			Introduced:  []patching.ToPatch{},
			Patches:     make(map[string]versions.Semver),
		}
		name, version := splitNameVersion(dependency)
		for _, occurrence := range toPatch {
			if occurrence.DependencyName == name && occurrence.DependencyVersion == version {
				patch.TopLevelVulnerable = true
			}
		}

		chosen, found, err := patcher.chooseUpgrade(name, version)
		if err != nil {
			panic(err)
		}
		switch {
		case !found:
			patch.IsPatchable = "NONE"
			patch.Unpatchable = toPatch
			patch.Patches = fixedVersions(nil, toPatch, nil)
		case len(chosen.remaining) == 0:
			patch.IsPatchable = "FULL"
			patch.Patchable = toPatch
			patch.Patches = fixedVersions(toPatch, nil, chosen.resolved)
		default:
			introduced, unpatchable, patchable := generatePatchingResult(occurrences(chosen.remaining), toPatch)
			if len(patchable) == 0 {
				// The best upgrade fixes nothing that is installed today.
				patch.IsPatchable = "NONE"
				patch.Unpatchable = toPatch
				patch.Patches = fixedVersions(nil, toPatch, nil)
				break
			}
			patch.IsPatchable = "PARTIAL"
			patch.Introduced = introduced
			patch.Unpatchable = unpatchable
			patch.Patchable = patchable
			patch.Patches = fixedVersions(patchable, unpatchable, chosen.resolved)
		}
		if patch.IsPatchable != "NONE" {
			patch.Update, err = semver.ParseSemver(chosen.version)
			if err != nil {
				panic(err)
			}
			patch.PotentiallyBreaking = chosen.breaking
		}
		patcher.patching_info[dependency] = patch
	}
	return patcher.patching_info
}

// splitNameVersion splits "name@version", keeping the @ of a scoped name.
func splitNameVersion(dependency string) (string, string) {
	at := strings.LastIndex(dependency, "@")
	if at <= 0 {
		return dependency, ""
	}
	return dependency[:at], dependency[at+1:]
}

// chooseUpgrade picks the version to upgrade a direct dependency to:
// the lowest fully fixed version in the installed major, else the lowest fully fixed version
// in a later major (flagged as breaking), else the version with the fewest vulnerabilities left,
// preferring the installed major and then lower versions. A version whose knowledge lookups
// fail is never chosen. found is false when no later version exists.
func (patcher Patcher) chooseUpgrade(name, installed string) (upgrade, bool, error) {
	candidates, err := laterVersions(patcher.registry, name, installed)
	if err != nil {
		return upgrade{}, false, fmt.Errorf("versions of %s: %w", name, err)
	}
	if len(candidates) == 0 {
		return upgrade{}, false, nil
	}
	installedSemver, err := semver.ParseSemver(installed)
	if err != nil {
		return upgrade{}, false, err
	}

	sameMajor, laterMajor := []string{}, []string{}
	for _, candidate := range candidates {
		parsed, err := semver.ParseSemver(candidate)
		if err != nil {
			continue
		}
		if parsed.Major == installedSemver.Major {
			sameMajor = append(sameMajor, candidate)
		} else {
			laterMajor = append(laterMajor, candidate)
		}
	}

	var best upgrade
	checked := 0
	var lastErr error
	for _, group := range []struct {
		versions []string
		breaking bool
	}{{sameMajor, false}, {laterMajor, true}} {
		for _, candidate := range group.versions {
			result, err := patcher.checkCandidate(name, candidate)
			if err != nil {
				log.Printf("Skipping %s@%s as an upgrade: %v", name, candidate, err)
				lastErr = err
				continue
			}
			result.breaking = group.breaking
			if len(result.remaining) == 0 {
				return result, true, nil
			}
			if checked == 0 || countCanonical(result.remaining) < countCanonical(best.remaining) {
				best = result
			}
			checked++
		}
	}
	if checked == 0 {
		return upgrade{}, false, fmt.Errorf("%w for %s: %w", errNoCandidateChecked, name, lastErr)
	}
	return best, true, nil
}

// checkCandidate resolves the tree name@version installs and finds its vulnerabilities.
func (patcher Patcher) checkCandidate(name, version string) (upgrade, error) {
	tree, err := resolveTree(patcher.registry, name, version)
	if err != nil {
		return upgrade{}, err
	}
	remaining, err := patcher.checker.check(tree)
	if err != nil {
		return upgrade{}, err
	}
	resolved := map[string]string{}
	for pkg, versions := range tree {
		resolved[pkg] = versions[0]
	}
	return upgrade{version: version, resolved: resolved, remaining: remaining}, nil
}

// countCanonical counts distinct vulnerable instances: one per canonical vulnerability and package version.
func countCanonical(vulnerabilities []vulnerabilityFinder.Vulnerability) int {
	seen := map[string]bool{}
	for _, v := range vulnerabilities {
		seen[v.VulnerabilityId+" "+v.AffectedDependency+"@"+v.AffectedVersion] = true
	}
	return len(seen)
}

func occurrences(vulnerabilities []vulnerabilityFinder.Vulnerability) []patching.ToPatch {
	out := make([]patching.ToPatch, 0, len(vulnerabilities))
	for _, v := range vulnerabilities {
		out = append(out, newToPatch(v, []string{}))
	}
	return out
}

// fixedVersions gives, for each occurrence's package version, the version that ends it.
// A patchable occurrence takes the version its package resolves to under the upgrade (name -> version).
// Any other occurrence, or one whose package is not in that tree, takes its advisory's fix;
// when several advisories hit one package version, the highest fix is kept, since only it ends all of them.
// A resolved version is never replaced by an advisory's fix. A package version with neither gets no entry.
func fixedVersions(patchable, unpatchable []patching.ToPatch, resolved map[string]string) map[string]versions.Semver {
	patches := map[string]versions.Semver{}
	fromUpgrade := map[string]bool{}
	for _, occurrence := range patchable {
		key := occurrence.DependencyName + "@" + occurrence.DependencyVersion
		version, ok := resolved[occurrence.DependencyName]
		if !ok || version == occurrence.DependencyVersion {
			continue
		}
		if parsed, err := semver.ParseSemver(version); err == nil {
			patches[key] = parsed
			fromUpgrade[key] = true
		}
	}
	for _, occurrence := range append(append([]patching.ToPatch{}, patchable...), unpatchable...) {
		key := occurrence.DependencyName + "@" + occurrence.DependencyVersion
		if fromUpgrade[key] || occurrence.AdvisoryFix == nil {
			continue
		}
		if current, ok := patches[key]; !ok || occurrence.AdvisoryFix.Compare(current, false) > 0 {
			patches[key] = *occurrence.AdvisoryFix
		}
	}
	return patches
}

// sameInstance reports whether two occurrences are one vulnerability in one package.
// Versions are not compared, since an upgrade moves the package to a new version.
// Vulnerabilities match when any of their identifiers (canonical id, source record ids, aliases) match.
func sameInstance(a, b patching.ToPatch) bool {
	if a.Vulnerability.AffectedDependency != b.Vulnerability.AffectedDependency {
		return false
	}
	for _, id := range a.Identifiers {
		for _, other := range b.Identifiers {
			if id == other {
				return true
			}
		}
	}
	return false
}

// generatePatchingResult splits the vulnerabilities left after an upgrade against those installed today:
// introduced are new, unpatchable remain, patchable are gone.
func generatePatchingResult(vulnerabilities []patching.ToPatch, toPatch []patching.ToPatch) ([]patching.ToPatch, []patching.ToPatch, []patching.ToPatch) {
	introduced := []patching.ToPatch{}
	unpatchable := []patching.ToPatch{}
	patchable := []patching.ToPatch{}
	for _, vulnerability := range vulnerabilities {
		present := false
		for _, oldVuln := range toPatch {
			if sameInstance(vulnerability, oldVuln) {
				present = true
			}
		}
		if !present {
			introduced = append(introduced, vulnerability)
		}
	}

	for _, oldVuln := range toPatch {
		present := false
		for _, vulnerability := range vulnerabilities {
			if sameInstance(vulnerability, oldVuln) {
				present = true
			}
		}
		if present {
			unpatchable = append(unpatchable, oldVuln)
		} else {
			patchable = append(patchable, oldVuln)
		}
	}
	return introduced, unpatchable, patchable
}

// getClosestNonVulnerable returns the fixed version of a range match, NVD first then OSV.
// Either match can be missing, and exact or universal matches name no fix.
func getClosestNonVulnerable(nvd *vulnerabilityFinder.NVDVulnerability, osv *vulnerabilityFinder.OSVVulnerability) (versions.Semver, bool) {
	if nvd != nil && nvd.VulnerableEvidenceType == vulnerabilityFinder.VULNERABLE_EVIDENCE_RANGE && !nvd.VulnerableEvidenceRange.OpenEnd {
		return nvd.VulnerableEvidenceRange.Vulnerable.FixedSemver, true
	}
	if osv != nil && osv.VulnerableEvidenceType == vulnerabilityFinder.VULNERABLE_EVIDENCE_RANGE && !osv.VulnerableEvidenceRange.OpenEnd {
		return osv.VulnerableEvidenceRange.Vulnerable.FixedSemver, true
	}
	return versions.Semver{}, false
}

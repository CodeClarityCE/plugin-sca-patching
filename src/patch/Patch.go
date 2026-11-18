package patch

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/CodeClarityCE/plugin-sca-patching/src/types/patching"
	vulnerabilityFinder "github.com/CodeClarityCE/plugin-sca-vuln-finder/src/types"
	semver "github.com/CodeClarityCE/utility-node-semver"
	"github.com/CodeClarityCE/utility-node-semver/versions"
	"github.com/sirupsen/logrus"
)

// ErrKnowledgeLookup marks a failed knowledge database lookup, which fails the patching step.
var ErrKnowledgeLookup = errors.New("knowledge lookup failed")

func knowledgeLookupError(err error) error {
	if errors.Is(err, ErrKnowledgeLookup) {
		return err
	}
	return fmt.Errorf("%w: %w", ErrKnowledgeLookup, err)
}

// candidate is one later version of a direct dependency and what upgrading to it leaves behind.
type candidate struct {
	version string
	tree    resolvedTree
	// remaining are the vulnerabilities still in the upgraded tree; empty for a full fix.
	remaining []vulnerabilityFinder.Vulnerability
	// compatible is true when npm's ^ range of the installed version allows the upgrade.
	compatible bool
	// fixes is true when the upgrade ends at least one vulnerability installed today.
	fixes bool
}

// dependencyPlan is the upgrade search for one direct dependency.
type dependencyPlan struct {
	key, name, version string
	toPatch            []patching.ToPatch
	compatible, later  []string
	checked            []candidate
}

// PatchDependencies chooses an upgrade for each direct dependency (key "name@version").
// Candidates are checked in at most two vuln-finder calls: first those npm's ^ range allows,
// then, for dependencies with no clean and fully checked one there, the later majors.
func (patcher Patcher) PatchDependencies(ctx context.Context, dependenciesToPatch map[string][]patching.ToPatch) (map[string]patching.PatchInfo, error) {
	patcher.patching_info = make(map[string]patching.PatchInfo)

	keys := make([]string, 0, len(dependenciesToPatch))
	for key := range dependenciesToPatch {
		keys = append(keys, key)
	}
	slices.Sort(keys)

	plans := []*dependencyPlan{}
	for _, key := range keys {
		plan, err := patcher.planDependency(key, dependenciesToPatch[key])
		if err != nil {
			return nil, err
		}
		if plan != nil {
			plans = append(plans, plan)
		}
	}

	if err := patcher.checkCandidates(ctx, plans, true); err != nil {
		return nil, err
	}
	undecided := []*dependencyPlan{}
	for _, plan := range plans {
		if best, ok := bestCandidate(plan.checked); !ok || !best.cleanAndChecked() {
			undecided = append(undecided, plan)
		}
	}
	if err := patcher.checkCandidates(ctx, undecided, false); err != nil {
		return nil, err
	}

	for _, plan := range plans {
		best, found := bestCandidate(plan.checked)
		patcher.patching_info[plan.key] = patcher.patchInfo(plan, best, found)
	}
	return patcher.patching_info, nil
}

// planDependency lists the later versions of one direct dependency. A direct dependency whose
// installed version is not semver cannot be compared with later versions, so it is marked NONE.
func (patcher Patcher) planDependency(key string, toPatch []patching.ToPatch) (*dependencyPlan, error) {
	name, version := splitNameVersion(key)
	installed, err := semver.ParseSemver(version)
	if err != nil {
		patcher.log.WithFields(logrus.Fields{"dependency": key}).Warn("Not checking upgrades of a dependency whose version is not semver")
		patcher.patching_info[key] = notPatchable(name, version, toPatch)
		return nil, nil
	}
	later, err := laterVersions(patcher.registry, name, version)
	if err != nil {
		return nil, knowledgeLookupError(fmt.Errorf("versions of %s: %w", name, err))
	}
	plan := &dependencyPlan{key: key, name: name, version: version, toPatch: toPatch}
	for _, candidateVersion := range later {
		parsed, err := semver.ParseSemver(candidateVersion)
		if err != nil {
			continue
		}
		if caretCompatible(installed, parsed) {
			plan.compatible = append(plan.compatible, candidateVersion)
		} else {
			plan.later = append(plan.later, candidateVersion)
		}
	}
	return plan, nil
}

// checkCandidates resolves the compatible or later candidates of each plan and checks them together.
func (patcher Patcher) checkCandidates(ctx context.Context, plans []*dependencyPlan, compatible bool) error {
	type pending struct {
		plan      *dependencyPlan
		candidate candidate
	}
	all := []pending{}
	trees := []resolvedTree{}
	for _, plan := range plans {
		group := plan.later
		if compatible {
			group = plan.compatible
		}
		for _, candidateVersion := range group {
			tree, err := resolveTree(patcher.registry, plan.name, candidateVersion)
			if err != nil {
				return knowledgeLookupError(fmt.Errorf("dependencies of %s@%s: %w", plan.name, candidateVersion, err))
			}
			all = append(all, pending{plan, candidate{version: candidateVersion, tree: tree, compatible: compatible}})
			trees = append(trees, tree)
		}
	}
	if len(all) == 0 {
		return nil
	}
	if err := patcher.checker.load(ctx, trees); err != nil {
		return err
	}
	unchecked := 0
	for _, p := range all {
		p.candidate.remaining = patcher.checker.vulnerabilities(p.candidate.tree)
		_, _, patchable := generatePatchingResult(occurrences(p.candidate.remaining), p.plan.toPatch)
		p.candidate.fixes = len(patchable) > 0
		p.plan.checked = append(p.plan.checked, p.candidate)
		if p.candidate.tree.unchecked > 0 {
			unchecked++
		}
	}
	patcher.log.WithFields(logrus.Fields{
		"dependencies":        len(plans),
		"candidates":          len(all),
		"partly_unchecked":    unchecked,
		"compatible_versions": compatible,
	}).Info("Checked upgrade candidates")
	return nil
}

// patchInfo describes the chosen upgrade of one direct dependency.
func (patcher Patcher) patchInfo(plan *dependencyPlan, best candidate, found bool) patching.PatchInfo {
	if !found {
		return notPatchable(plan.name, plan.version, plan.toPatch)
	}
	if best.tree.unchecked > 0 {
		patcher.log.WithFields(logrus.Fields{
			"dependency": plan.key,
			"upgrade":    best.version,
			"unchecked":  best.tree.unchecked,
		}).Info("Chosen upgrade has dependencies that could not be checked")
	}
	patch := emptyPatchInfo(plan.name, plan.version, plan.toPatch)
	if len(best.remaining) == 0 {
		patch.IsPatchable = "FULL"
		patch.Patchable = plan.toPatch
		patch.Patches = fixedVersions(plan.toPatch, nil, best.tree.highestVersions())
	} else {
		introduced, unpatchable, patchable := generatePatchingResult(occurrences(best.remaining), plan.toPatch)
		if len(patchable) == 0 {
			// The best upgrade fixes nothing that is installed today.
			return notPatchable(plan.name, plan.version, plan.toPatch)
		}
		patch.IsPatchable = "PARTIAL"
		patch.Introduced = introduced
		patch.Unpatchable = unpatchable
		patch.Patchable = patchable
		patch.Patches = fixedVersions(patchable, unpatchable, best.tree.highestVersions())
	}
	// best.version parsed when it was listed as a candidate.
	patch.Update, _ = semver.ParseSemver(best.version)
	patch.PotentiallyBreaking = !best.compatible
	return patch
}

func emptyPatchInfo(name, version string, toPatch []patching.ToPatch) patching.PatchInfo {
	patch := patching.PatchInfo{
		Unpatchable: []patching.ToPatch{},
		Patchable:   []patching.ToPatch{},
		Introduced:  []patching.ToPatch{},
		Patches:     map[string]versions.Semver{},
	}
	for _, occurrence := range toPatch {
		if occurrence.DependencyName == name && occurrence.DependencyVersion == version {
			patch.TopLevelVulnerable = true
		}
	}
	return patch
}

func notPatchable(name, version string, toPatch []patching.ToPatch) patching.PatchInfo {
	patch := emptyPatchInfo(name, version, toPatch)
	patch.IsPatchable = "NONE"
	patch.Unpatchable = toPatch
	patch.Patches = fixedVersions(nil, toPatch, nil)
	return patch
}

func (c candidate) cleanAndChecked() bool {
	return len(c.remaining) == 0 && c.tree.unchecked == 0
}

// bestCandidate ranks the candidates, which are in ascending version order within each group:
// no vulnerabilities left first, and among those a fully checked tree before one with unchecked
// dependencies; then ending at least one installed vulnerability, then inside npm's ^ range,
// then fewest vulnerabilities left, then fewest unchecked dependencies, then the lowest version.
func bestCandidate(candidates []candidate) (candidate, bool) {
	if len(candidates) == 0 {
		return candidate{}, false
	}
	best := candidates[0]
	for _, c := range candidates[1:] {
		if better(c, best) {
			best = c
		}
	}
	return best, true
}

func better(a, b candidate) bool {
	cleanA, cleanB := len(a.remaining) == 0, len(b.remaining) == 0
	if cleanA != cleanB {
		return cleanA
	}
	if cleanA && (a.tree.unchecked == 0) != (b.tree.unchecked == 0) {
		return a.tree.unchecked == 0
	}
	if a.fixes != b.fixes {
		return a.fixes
	}
	if a.compatible != b.compatible {
		return a.compatible
	}
	if countA, countB := countCanonical(a.remaining), countCanonical(b.remaining); countA != countB {
		return countA < countB
	}
	if a.tree.unchecked != b.tree.unchecked {
		return a.tree.unchecked < b.tree.unchecked
	}
	parsedA, errA := semver.ParseSemver(a.version)
	parsedB, errB := semver.ParseSemver(b.version)
	return errA == nil && errB == nil && parsedA.Compare(parsedB, false) < 0
}

// caretCompatible reports whether npm's ^installed range allows candidate: the same major,
// or for 0.x the same minor, or for 0.0.x the same patch.
func caretCompatible(installed, candidate versions.Semver) bool {
	switch {
	case installed.Major > 0:
		return candidate.Major == installed.Major
	case installed.Minor > 0:
		return candidate.Major == 0 && candidate.Minor == installed.Minor
	default:
		return candidate.Major == 0 && candidate.Minor == 0 && candidate.Patch == installed.Patch
	}
}

// splitNameVersion splits "name@version", keeping the @ of a scoped name.
func splitNameVersion(dependency string) (string, string) {
	at := strings.LastIndex(dependency, "@")
	if at <= 0 {
		return dependency, ""
	}
	return dependency[:at], dependency[at+1:]
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

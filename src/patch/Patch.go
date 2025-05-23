package patch

import (
	"fmt"
	"strings"
	"sync"

	"github.com/CodeClarityCE/plugin-sca-patching/src/types/patching"
	vulnerabilityFinder "github.com/CodeClarityCE/plugin-sca-vuln-finder/src/types"
	semver "github.com/CodeClarityCE/utility-node-semver"
	"github.com/CodeClarityCE/utility-node-semver/versions"
	knowledge "github.com/CodeClarityCE/utility-types/knowledge_db"
)

func (patcher Patcher) PatchDependencies(dependenciesToPatch map[string][]patching.ToPatch) map[string]patching.PatchInfo {
	patcher.patching_info = make(map[string]patching.PatchInfo)

	// We iterate over the direct dependencies that need to be patched
	// the vulnerability might be in the direct dependency itself or in one of its transitive dependencies
	for dependency, toPatch := range dependenciesToPatch {
		// We initialize the patching info for the dependency
		patcher.patching_info[dependency] = patching.PatchInfo{
			TopLevelVulnerable: false,
			IsPatchable:        "",
			Unpatchable:        []patching.ToPatch{},
			Patchable:          []patching.ToPatch{},
			Introduced:         []patching.ToPatch{},
			Patches:            make(map[string]versions.Semver),
		}

		// We if the dependency needs to be patched because it is vulnerable itself
		// In that case, we just need to find the closest non-vulnerable version
		if len(toPatch) == 1 && dependency == toPatch[0].DependencyName+"@"+toPatch[0].DependencyVersion {
			patch := patcher.patching_info[dependency]
			patch.TopLevelVulnerable = true
			patcher.patching_info[dependency] = patch
			patcher.patchDirectDependencyVulnerable(dependency, toPatch[0])
			continue
		} else {
			splited_dependency := strings.Split(dependency, "@")
			name := splited_dependency[0]
			version := splited_dependency[1]
			if len(splited_dependency) == 3 {
				name = splited_dependency[0] + "@" + splited_dependency[1]
				version = splited_dependency[2]
			}
			lessVulnerableVersion, vulnerabilities, err := patcher.findLessVulnerableDependency(name, version)
			if err != nil {
				if err.Error() == "already patched" {
					continue
				} else if err.Error() == "dependency not fully patchable" {
					patch := patcher.patching_info[dependency]
					introduced, unpatchable, patchable := generatePatchingResult(vulnerabilities, toPatch)
					patch.IsPatchable = "PARTIAL"
					patch.Introduced = introduced
					patch.Unpatchable = unpatchable
					patch.Patchable = patchable
					// patch.Patches[dependency] = versions.Semver{Version: lessVulnerableVersion}
					patch.Update, err = semver.ParseSemver(lessVulnerableVersion)
					if err != nil {
						panic(err)
					}
					patcher.patching_info[dependency] = patch
					continue
				} else if err.Error() == "not patchable" {
					patch := patcher.patching_info[dependency]
					patch.IsPatchable = "NONE"
					patch.Unpatchable = toPatch
					patcher.patching_info[dependency] = patch
					continue
				} else {
					panic(err)
				}
			}
			// If there is no error, it means that the dependency is fully patchable
			patch := patcher.patching_info[dependency]
			patch.IsPatchable = "FULL"
			patch.Patchable = toPatch
			// patch.Patches[dependency] = versions.Semver{Version: lessVulnerableVersion}
			patch.Update, err = semver.ParseSemver(lessVulnerableVersion)
			if err != nil {
				panic(err)
			}
			patcher.patching_info[dependency] = patch

		}
	}
	return patcher.patching_info
}

func generatePatchingResult(vulnerabilities []patching.ToPatch, toPatch []patching.ToPatch) ([]patching.ToPatch, []patching.ToPatch, []patching.ToPatch) {
	introduced := []patching.ToPatch{}
	unpatchable := []patching.ToPatch{}
	patchable := []patching.ToPatch{}
	for _, vulnerability := range vulnerabilities {
		present := false
		for _, oldVuln := range toPatch {
			if vulnerability.Vulnerability.VulnerabilityId == oldVuln.Vulnerability.VulnerabilityId &&
				vulnerability.Vulnerability.AffectedDependency == oldVuln.Vulnerability.AffectedDependency &&
				vulnerability.Vulnerability.AffectedVersion == oldVuln.Vulnerability.AffectedVersion {
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
			if vulnerability.Vulnerability.VulnerabilityId == oldVuln.Vulnerability.VulnerabilityId &&
				vulnerability.Vulnerability.AffectedDependency == oldVuln.Vulnerability.AffectedDependency &&
				vulnerability.Vulnerability.AffectedVersion == oldVuln.Vulnerability.AffectedVersion {
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

func (patcher Patcher) findLessVulnerableDependency(dependencyName string, dependencyVersion string) (string, []patching.ToPatch, error) {
	// Check that the dependency is not already patched
	if patcher.patching_info[dependencyName+"@"+dependencyVersion].IsPatchable != "" {
		return "", []patching.ToPatch{}, fmt.Errorf("already patched")
	}

	versions, err := patcher.getPossibleVersions(dependencyName, dependencyVersion)
	if err != nil {
		return "", []patching.ToPatch{}, err
	}
	if len(versions) == 0 {
		return "", []patching.ToPatch{}, fmt.Errorf("not patchable")
	}

	versionWithSmallestScore := ""
	smallestScore := 0
	smallestVulnerabilities := []patching.ToPatch{}
	for _, version := range versions {
		transitiveProdDependencies, transitiveDevDependencies, err := patcher.getTransitiveDependencies(dependencyName, version)
		if err != nil {
			return "", []patching.ToPatch{}, err
		}
		score, vulnerabilities, err := patcher.lookForVulnerabilities(transitiveProdDependencies, transitiveDevDependencies)
		if err != nil {
			return "", []patching.ToPatch{}, err
		}

		// If the dependency is not vulnerable, we return the version
		if score == 0 {
			return version, vulnerabilities, nil
		} else {
			// we keep track of the smallest score and continue
			if smallestScore == 0 || score < smallestScore {
				smallestScore = score
				smallestVulnerabilities = vulnerabilities
				versionWithSmallestScore = version
			}
		}

	}
	return versionWithSmallestScore, smallestVulnerabilities, fmt.Errorf("dependency not fully patchable")
}

func (patcher Patcher) lookForVulnerabilities(transitiveProdDependencies []string, transitiveDevDependencies []string) (int, []patching.ToPatch, error) {
	totalScore := 0
	vulnerabilities := []patching.ToPatch{}

	var wg sync.WaitGroup
	maxGoroutines := 50
	guard := make(chan struct{}, maxGoroutines)

	for _, dependency := range transitiveProdDependencies {
		wg.Add(1)
		guard <- struct{}{}
		go func(wg *sync.WaitGroup, dependency string) {
			defer wg.Done()
			splited_dependency := strings.Split(dependency, "@")
			name := splited_dependency[0]
			version := splited_dependency[1]
			if len(splited_dependency) == 3 {
				name = splited_dependency[0] + "@" + splited_dependency[1]
				version = splited_dependency[2]
			}
			nvdScore, foundVulnerabilities, _ := patcher.GetNVDVulnerabilities(name, version)
			totalScore += nvdScore
			vulnerabilitiesConverted := convertNVDItemsToPatchItems(foundVulnerabilities, name, version)
			vulnerabilities = append(vulnerabilities, vulnerabilitiesConverted...)
			<-guard
		}(&wg, dependency)
	}

	for _, dependency := range transitiveDevDependencies {
		wg.Add(1)
		guard <- struct{}{}
		go func(wg *sync.WaitGroup, dependency string) {
			defer wg.Done()
			splited_dependency := strings.Split(dependency, "@")
			name := splited_dependency[0]
			version := splited_dependency[1]
			if len(splited_dependency) == 3 {
				name = splited_dependency[0] + "@" + splited_dependency[1]
				version = splited_dependency[2]
			}
			nvdScore, foundVulnerabilities, _ := patcher.GetNVDVulnerabilities(name, version)
			totalScore += nvdScore
			vulnerabilitiesConverted := convertNVDItemsToPatchItems(foundVulnerabilities, name, version)
			vulnerabilities = append(vulnerabilities, vulnerabilitiesConverted...)
			<-guard
		}(&wg, dependency)
	}

	return totalScore, vulnerabilities, nil
}

func convertNVDItemsToPatchItems(nvdItems []knowledge.NVDItem, name string, version string) []patching.ToPatch {
	// TODO fill missing information
	toPatchItems := []patching.ToPatch{}
	for _, nvdItem := range nvdItems {
		toPatchItems = append(toPatchItems, patching.ToPatch{
			DependencyName:    name,
			DependencyVersion: version,
			Path:              []string{},
			Vulnerability: vulnerabilityFinder.Vulnerability{
				Sources:            []vulnerabilityFinder.VulnerabilitySource{},
				AffectedDependency: name,
				AffectedVersion:    version,
				VulnerabilityId:    nvdItem.NVDId,
				OSVMatch:           &vulnerabilityFinder.OSVVulnerability{},
				NVDMatch:           &vulnerabilityFinder.NVDVulnerability{},
				Severity:           vulnerabilityFinder.VulnerabilityMatchSeverity{},
				Weaknesses:         []vulnerabilityFinder.VulnerabilityMatchWeakness{},
			},
		})
	}
	return toPatchItems
}

func (patcher Patcher) patchDirectDependencyVulnerable(dependency string, vulnerableDependency patching.ToPatch) {
	patch := patcher.patching_info[dependency]
	if vulnerableDependency.Vulnerability.NVDMatch.VulnerableEvidenceType == vulnerabilityFinder.VULNERABLE_EVIDENCE_UNIVERSAL {
		patch.IsPatchable = "NONE"
		patch.Unpatchable = append(patch.Unpatchable, vulnerableDependency)

	} else {
		patched_version, err := getClosestNonVulnerable(*vulnerableDependency.Vulnerability.NVDMatch, *vulnerableDependency.Vulnerability.OSVMatch)
		if err != nil {
			panic(err)
		}
		patch.IsPatchable = "FULL"
		patch.Patchable = append(patch.Patchable, vulnerableDependency)
		patch.Patches[dependency] = patched_version
		patch.Update = patched_version
	}
	patcher.patching_info[dependency] = patch
}

func getClosestNonVulnerable(NVD vulnerabilityFinder.NVDVulnerability, OSV vulnerabilityFinder.OSVVulnerability) (versions.Semver, error) {
	if NVD.VulnerableEvidenceType == vulnerabilityFinder.VULNERABLE_EVIDENCE_RANGE {
		return NVD.VulnerableEvidenceRange.Vulnerable.FixedSemver, nil
	} else if NVD.VulnerableEvidenceType == vulnerabilityFinder.VULNERABLE_EVIDENCE_EXACT {
		return versions.Semver{}, fmt.Errorf("not implemented")
	}
	return versions.Semver{}, fmt.Errorf("vulnerable evidence unknown")
}
